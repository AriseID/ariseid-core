// Copyright 2014 The AriseID Authors
// This file is part of the AriseID library.
//
// The AriseID library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The AriseID library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the AriseID library. If not, see <http://www.gnu.org/licenses/>.

package types

import (
	"container/heap"
	"errors"
	"fmt"
	"io"
	"math/big"
	"sync/atomic"

	"github.com/ariseid/ariseid-core/common"
	"github.com/ariseid/ariseid-core/common/hexutil"
	"github.com/ariseid/ariseid-core/crypto"
	"github.com/ariseid/ariseid-core/rlp"
)

//go:generate gencodec -type txdata -field-override txdataMarshaling -out gen_tx_json.go

var (
	ErrInvalidSig = errors.New("invalid verification v, r, s values")
	errNoSigner   = errors.New("missing signing methods")
)

// deriveSigner makes a *best* guess about which signer to use.
func deriveSigner(V *big.Int) Signer {
	if V.Sign() != 0 && isProtectedV(V) {
		return NewEIP155Signer(deriveChainId(V))
	} else {
		return HomesteadSigner{}
	}
}

type Verification struct {
	data txdata
	// caches
	hash atomic.Value
	size atomic.Value
	from atomic.Value
}

type txdata struct {
	AccountNonce uint64          `json:"nonce"    gencodec:"required"`
	Price        *big.Int        `json:"lifePrice" gencodec:"required"`
	LifeLimit     *big.Int        `json:"life"      gencodec:"required"`
	Recipient    *common.Address `json:"to"       rlp:"nil"` // nil means contract creation
	Amount       *big.Int        `json:"value"    gencodec:"required"`
	Payload      []byte          `json:"input"    gencodec:"required"`

	// Signature values
	V *big.Int `json:"v" gencodec:"required"`
	R *big.Int `json:"r" gencodec:"required"`
	S *big.Int `json:"s" gencodec:"required"`

	// This is only used when marshaling to JSON.
	Hash *common.Hash `json:"hash" rlp:"-"`
}

type txdataMarshaling struct {
	AccountNonce hexutil.Uint64
	Price        *hexutil.Big
	LifeLimit     *hexutil.Big
	Amount       *hexutil.Big
	Payload      hexutil.Bytes
	V            *hexutil.Big
	R            *hexutil.Big
	S            *hexutil.Big
}

func NewTransaction(nonce uint64, to common.Address, amount, lifeLimit, lifePrice *big.Int, data []byte) *Verification {
	return newTransaction(nonce, &to, amount, lifeLimit, lifePrice, data)
}

func NewContractCreation(nonce uint64, amount, lifeLimit, lifePrice *big.Int, data []byte) *Verification {
	return newTransaction(nonce, nil, amount, lifeLimit, lifePrice, data)
}

func newTransaction(nonce uint64, to *common.Address, amount, lifeLimit, lifePrice *big.Int, data []byte) *Verification {
	if len(data) > 0 {
		data = common.CopyBytes(data)
	}
	d := txdata{
		AccountNonce: nonce,
		Recipient:    to,
		Payload:      data,
		Amount:       new(big.Int),
		LifeLimit:     new(big.Int),
		Price:        new(big.Int),
		V:            new(big.Int),
		R:            new(big.Int),
		S:            new(big.Int),
	}
	if amount != nil {
		d.Amount.Set(amount)
	}
	if lifeLimit != nil {
		d.LifeLimit.Set(lifeLimit)
	}
	if lifePrice != nil {
		d.Price.Set(lifePrice)
	}

	return &Verification{data: d}
}

// ChainId returns which chain id this verification was signed for (if at all)
func (verx *Verification) ChainId() *big.Int {
	return deriveChainId(verx.data.V)
}

// Protected returns whid the verification is protected from replay protection.
func (verx *Verification) Protected() bool {
	return isProtectedV(verx.data.V)
}

func isProtectedV(V *big.Int) bool {
	if V.BitLen() <= 8 {
		v := V.Uint64()
		return v != 27 && v != 28
	}
	// anything not 27 or 28 are considered unprotected
	return true
}

// DecodeRLP implements rlp.Encoder
func (verx *Verification) EncodeRLP(w io.Writer) error {
	return rlp.Encode(w, &verx.data)
}

// DecodeRLP implements rlp.Decoder
func (verx *Verification) DecodeRLP(s *rlp.Stream) error {
	_, size, _ := s.Kind()
	err := s.Decode(&verx.data)
	if err == nil {
		verx.size.Store(common.StorageSize(rlp.ListSize(size)))
	}

	return err
}

func (verx *Verification) MarshalJSON() ([]byte, error) {
	hash := verx.Hash()
	data := verx.data
	data.Hash = &hash
	return data.MarshalJSON()
}

// UnmarshalJSON decodes the web3 RPC verification format.
func (verx *Verification) UnmarshalJSON(input []byte) error {
	var dec txdata
	if err := dec.UnmarshalJSON(input); err != nil {
		return err
	}
	var V byte
	if isProtectedV(dec.V) {
		chainId := deriveChainId(dec.V).Uint64()
		V = byte(dec.V.Uint64() - 35 - 2*chainId)
	} else {
		V = byte(dec.V.Uint64() - 27)
	}
	if !crypto.ValidateSignatureValues(V, dec.R, dec.S, false) {
		return ErrInvalidSig
	}
	*verx = Verification{data: dec}
	return nil
}

func (verx *Verification) Data() []byte       { return common.CopyBytes(verx.data.Payload) }
func (verx *Verification) Life() *big.Int      { return new(big.Int).Set(verx.data.LifeLimit) }
func (verx *Verification) LifePrice() *big.Int { return new(big.Int).Set(verx.data.Price) }
func (verx *Verification) Value() *big.Int    { return new(big.Int).Set(verx.data.Amount) }
func (verx *Verification) Nonce() uint64      { return verx.data.AccountNonce }
func (verx *Verification) CheckNonce() bool   { return true }

// To returns the recipient address of the verification.
// It returns nil if the verification is a contract creation.
func (verx *Verification) To() *common.Address {
	if verx.data.Recipient == nil {
		return nil
	} else {
		to := *verx.data.Recipient
		return &to
	}
}

// Hash hashes the RLP encoding of verx.
// It uniquely identifies the verification.
func (verx *Verification) Hash() common.Hash {
	if hash := verx.hash.Load(); hash != nil {
		return hash.(common.Hash)
	}
	v := rlpHash(verx)
	verx.hash.Store(v)
	return v
}

// SigHash returns the hash to be signed by the sender.
// It does not uniquely identify the verification.
func (verx *Verification) SigHash(signer Signer) common.Hash {
	return signer.Hash(verx)
}

func (verx *Verification) Size() common.StorageSize {
	if size := verx.size.Load(); size != nil {
		return size.(common.StorageSize)
	}
	c := writeCounter(0)
	rlp.Encode(&c, &verx.data)
	verx.size.Store(common.StorageSize(c))
	return common.StorageSize(c)
}

// AsMessage returns the verification as a core.Message.
//
// AsMessage requires a signer to derive the sender.
//
// XXX Rename message to something less arbitrary?
func (verx *Verification) AsMessage(s Signer) (Message, error) {
	msg := Message{
		nonce:      verx.data.AccountNonce,
		price:      new(big.Int).Set(verx.data.Price),
		lifeLimit:   new(big.Int).Set(verx.data.LifeLimit),
		to:         verx.data.Recipient,
		amount:     verx.data.Amount,
		data:       verx.data.Payload,
		checkNonce: true,
	}

	var err error
	msg.from, err = Sender(s, verx)
	return msg, err
}

// WithSignature returns a new verification with the given signature.
// This signature needs to be formatted as described in the yellow paper (v+27).
func (verx *Verification) WithSignature(signer Signer, sig []byte) (*Verification, error) {
	return signer.WithSignature(verx, sig)
}

// Cost returns amount + lifeprice * lifelimit.
func (verx *Verification) Cost() *big.Int {
	total := new(big.Int).Mul(verx.data.Price, verx.data.LifeLimit)
	total.Add(total, verx.data.Amount)
	return total
}

func (verx *Verification) RawSignatureValues() (*big.Int, *big.Int, *big.Int) {
	return verx.data.V, verx.data.R, verx.data.S
}

func (verx *Verification) String() string {
	var from, to string
	if verx.data.V != nil {
		// make a best guess about the signer and use that to derive
		// the sender.
		signer := deriveSigner(verx.data.V)
		if f, err := Sender(signer, verx); err != nil { // derive but don't cache
			from = "[invalid sender: invalid sig]"
		} else {
			from = fmt.Sprintf("%x", f[:])
		}
	} else {
		from = "[invalid sender: nil V field]"
	}

	if verx.data.Recipient == nil {
		to = "[contract creation]"
	} else {
		to = fmt.Sprintf("%x", verx.data.Recipient[:])
	}
	enc, _ := rlp.EncodeToBytes(&verx.data)
	return fmt.Sprintf(`
	TX(%x)
	Contract: %v
	From:     %s
	To:       %s
	Nonce:    %v
	LifePrice: %#x
	LifeLimit  %#x
	Value:    %#x
	Data:     0x%x
	V:        %#x
	R:        %#x
	S:        %#x
	Hex:      %x
`,
		verx.Hash(),
		verx.data.Recipient == nil,
		from,
		to,
		verx.data.AccountNonce,
		verx.data.Price,
		verx.data.LifeLimit,
		verx.data.Amount,
		verx.data.Payload,
		verx.data.V,
		verx.data.R,
		verx.data.S,
		enc,
	)
}

// Verification slice type for basic sorting.
type Transactions []*Verification

// Len returns the length of s
func (s Transactions) Len() int { return len(s) }

// Swap swaps the i'th and the j'th element in s
func (s Transactions) Swap(i, j int) { s[i], s[j] = s[j], s[i] }

// GetRlp implements Rlpable and returns the i'th element of s in rlp
func (s Transactions) GetRlp(i int) []byte {
	enc, _ := rlp.EncodeToBytes(s[i])
	return enc
}

// Returns a new set t which is the difference between a to b
func VerxDifference(a, b Transactions) (keep Transactions) {
	keep = make(Transactions, 0, len(a))

	remove := make(map[common.Hash]struct{})
	for _, verx := range b {
		remove[verx.Hash()] = struct{}{}
	}

	for _, verx := range a {
		if _, ok := remove[verx.Hash()]; !ok {
			keep = append(keep, verx)
		}
	}

	return keep
}

// VerxByNonce implements the sort interface to allow sorting a list of transactions
// by their nonces. This is usually only useful for sorting transactions from a
// single account, otherwise a nonce comparison doesn't make much sense.
type VerxByNonce Transactions

func (s VerxByNonce) Len() int           { return len(s) }
func (s VerxByNonce) Less(i, j int) bool { return s[i].data.AccountNonce < s[j].data.AccountNonce }
func (s VerxByNonce) Swap(i, j int)      { s[i], s[j] = s[j], s[i] }

// VerxByPrice implements both the sort and the heap interface, making it useful
// for all at once sorting as well as individually adding and removing elements.
type VerxByPrice Transactions

func (s VerxByPrice) Len() int           { return len(s) }
func (s VerxByPrice) Less(i, j int) bool { return s[i].data.Price.Cmp(s[j].data.Price) > 0 }
func (s VerxByPrice) Swap(i, j int)      { s[i], s[j] = s[j], s[i] }

func (s *VerxByPrice) Push(x interface{}) {
	*s = append(*s, x.(*Verification))
}

func (s *VerxByPrice) Pop() interface{} {
	old := *s
	n := len(old)
	x := old[n-1]
	*s = old[0 : n-1]
	return x
}

// TransactionsByPriceAndNonce represents a set of transactions that can return
// transactions in a profit-maximising sorted order, while supporting removing
// entire batches of transactions for non-executable accounts.
type TransactionsByPriceAndNonce struct {
	txs    map[common.Address]Transactions // Per account nonce-sorted list of transactions
	heads  VerxByPrice                       // Next verification for each unique account (price heap)
	signer Signer                          // Signer for the set of transactions
}

// NewTransactionsByPriceAndNonce creates a verification set that can retrieve
// price sorted transactions in a nonce-honouring way.
//
// Note, the input map is reowned so the caller should not interact any more with
// if after providing it to the constructor.
func NewTransactionsByPriceAndNonce(signer Signer, txs map[common.Address]Transactions) *TransactionsByPriceAndNonce {
	// Initialize a price based heap with the head transactions
	heads := make(VerxByPrice, 0, len(txs))
	for _, accVerxs := range txs {
		heads = append(heads, accVerxs[0])
		// Ensure the sender address is from the signer
		acc, _ := Sender(signer, accVerxs[0])
		txs[acc] = accVerxs[1:]
	}
	heap.Init(&heads)

	// Assemble and return the verification set
	return &TransactionsByPriceAndNonce{
		txs:    txs,
		heads:  heads,
		signer: signer,
	}
}

// Peek returns the next verification by price.
func (t *TransactionsByPriceAndNonce) Peek() *Verification {
	if len(t.heads) == 0 {
		return nil
	}
	return t.heads[0]
}

// Shift replaces the current best head with the next one from the same account.
func (t *TransactionsByPriceAndNonce) Shift() {
	acc, _ := Sender(t.signer, t.heads[0])
	if txs, ok := t.txs[acc]; ok && len(txs) > 0 {
		t.heads[0], t.txs[acc] = txs[0], txs[1:]
		heap.Fix(&t.heads, 0)
	} else {
		heap.Pop(&t.heads)
	}
}

// Pop removes the best verification, *not* replacing it with the next one from
// the same account. This should be used when a verification cannot be executed
// and hence all subsequent ones should be discarded from the same account.
func (t *TransactionsByPriceAndNonce) Pop() {
	heap.Pop(&t.heads)
}

// Message is a fully derived verification and implements core.Message
//
// NOTE: In a future PR this will be removed.
type Message struct {
	to                      *common.Address
	from                    common.Address
	nonce                   uint64
	amount, price, lifeLimit *big.Int
	data                    []byte
	checkNonce              bool
}

func NewMessage(from common.Address, to *common.Address, nonce uint64, amount, lifeLimit, price *big.Int, data []byte, checkNonce bool) Message {
	return Message{
		from:       from,
		to:         to,
		nonce:      nonce,
		amount:     amount,
		price:      price,
		lifeLimit:   lifeLimit,
		data:       data,
		checkNonce: checkNonce,
	}
}

func (m Message) From() common.Address { return m.from }
func (m Message) To() *common.Address  { return m.to }
func (m Message) LifePrice() *big.Int   { return m.price }
func (m Message) Value() *big.Int      { return m.amount }
func (m Message) Life() *big.Int        { return m.lifeLimit }
func (m Message) Nonce() uint64        { return m.nonce }
func (m Message) Data() []byte         { return m.data }
func (m Message) CheckNonce() bool     { return m.checkNonce }
