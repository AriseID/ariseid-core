// Copyright 2017 Ethereum, AriseID Authors
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

// Contains all the wrappers from the core/types package.

package idd

import (
	"encoding/json"
	"errors"
	"fmt"

	"github.com/ariseid/ariseid-core/common"
	"github.com/ariseid/ariseid-core/core/types"
	"github.com/ariseid/ariseid-core/rlp"
)

// A Nonce is a 64-bit hash which proves (combined with the mix-hash) that
// a sufficient amount of computation has been carried out on a block.
type Nonce struct {
	nonce types.BlockNonce
}

// GetBytes retrieves the byte representation of the block nonce.
func (n *Nonce) GetBytes() []byte {
	return n.nonce[:]
}

// GetHex retrieves the hex string representation of the block nonce.
func (n *Nonce) GetHex() string {
	return fmt.Sprintf("0x%x", n.nonce[:])
}

// Bloom represents a 256 bit bloom filter.
type Bloom struct {
	bloom types.Bloom
}

// GetBytes retrieves the byte representation of the bloom filter.
func (b *Bloom) GetBytes() []byte {
	return b.bloom[:]
}

// GetHex retrieves the hex string representation of the bloom filter.
func (b *Bloom) GetHex() string {
	return fmt.Sprintf("0x%x", b.bloom[:])
}

// Header represents a block header in the AriseID blockchain.
type Header struct {
	header *types.Header
}

// NewHeaderFromRLP parses a header from an RLP data dump.
func NewHeaderFromRLP(data []byte) (*Header, error) {
	h := &Header{
		header: new(types.Header),
	}
	if err := rlp.DecodeBytes(common.CopyBytes(data), h.header); err != nil {
		return nil, err
	}
	return h, nil
}

// EncodeRLP encodes a header into an RLP data dump.
func (h *Header) EncodeRLP() ([]byte, error) {
	return rlp.EncodeToBytes(h.header)
}

// NewHeaderFromJSON parses a header from an JSON data dump.
func NewHeaderFromJSON(data string) (*Header, error) {
	h := &Header{
		header: new(types.Header),
	}
	if err := json.Unmarshal([]byte(data), h.header); err != nil {
		return nil, err
	}
	return h, nil
}

// EncodeJSON encodes a header into an JSON data dump.
func (h *Header) EncodeJSON() (string, error) {
	data, err := json.Marshal(h.header)
	return string(data), err
}

// String implements the fmt.Stringer interface to print some semi-meaningful
// data dump of the header for debugging purposes.
func (h *Header) String() string {
	return h.header.String()
}

func (h *Header) GetParentHash() *Hash   { return &Hash{h.header.ParentHash} }
func (h *Header) GetUncleHash() *Hash    { return &Hash{h.header.UncleHash} }
func (h *Header) GetCoinbase() *Address  { return &Address{h.header.Coinbase} }
func (h *Header) GetRoot() *Hash         { return &Hash{h.header.Root} }
func (h *Header) GetVerxHash() *Hash       { return &Hash{h.header.VerxHash} }
func (h *Header) GetReceiptHash() *Hash  { return &Hash{h.header.ReceiptHash} }
func (h *Header) GetBloom() *Bloom       { return &Bloom{h.header.Bloom} }
func (h *Header) GetDifficulty() *BigInt { return &BigInt{h.header.Difficulty} }
func (h *Header) GetNumber() int64       { return h.header.Number.Int64() }
func (h *Header) GetLifeLimit() int64     { return h.header.LifeLimit.Int64() }
func (h *Header) GetLifeUsed() int64      { return h.header.LifeUsed.Int64() }
func (h *Header) GetTime() int64         { return h.header.Time.Int64() }
func (h *Header) GetExtra() []byte       { return h.header.Extra }
func (h *Header) GetMixDigest() *Hash    { return &Hash{h.header.MixDigest} }
func (h *Header) GetNonce() *Nonce       { return &Nonce{h.header.Nonce} }
func (h *Header) GetHash() *Hash         { return &Hash{h.header.Hash()} }

// Headers represents a slice of headers.
type Headers struct{ headers []*types.Header }

// Size returns the number of headers in the slice.
func (h *Headers) Size() int {
	return len(h.headers)
}

// Get returns the header at the given index from the slice.
func (h *Headers) Get(index int) (header *Header, _ error) {
	if index < 0 || index >= len(h.headers) {
		return nil, errors.New("index out of bounds")
	}
	return &Header{h.headers[index]}, nil
}

// Block represents an entire block in the AriseID blockchain.
type Block struct {
	block *types.Block
}

// NewBlockFromRLP parses a block from an RLP data dump.
func NewBlockFromRLP(data []byte) (*Block, error) {
	b := &Block{
		block: new(types.Block),
	}
	if err := rlp.DecodeBytes(common.CopyBytes(data), b.block); err != nil {
		return nil, err
	}
	return b, nil
}

// EncodeRLP encodes a block into an RLP data dump.
func (b *Block) EncodeRLP() ([]byte, error) {
	return rlp.EncodeToBytes(b.block)
}

// NewBlockFromJSON parses a block from an JSON data dump.
func NewBlockFromJSON(data string) (*Block, error) {
	b := &Block{
		block: new(types.Block),
	}
	if err := json.Unmarshal([]byte(data), b.block); err != nil {
		return nil, err
	}
	return b, nil
}

// EncodeJSON encodes a block into an JSON data dump.
func (b *Block) EncodeJSON() (string, error) {
	data, err := json.Marshal(b.block)
	return string(data), err
}

// String implements the fmt.Stringer interface to print some semi-meaningful
// data dump of the block for debugging purposes.
func (b *Block) String() string {
	return b.block.String()
}

func (b *Block) GetParentHash() *Hash   { return &Hash{b.block.ParentHash()} }
func (b *Block) GetUncleHash() *Hash    { return &Hash{b.block.UncleHash()} }
func (b *Block) GetCoinbase() *Address  { return &Address{b.block.Coinbase()} }
func (b *Block) GetRoot() *Hash         { return &Hash{b.block.Root()} }
func (b *Block) GetVerxHash() *Hash       { return &Hash{b.block.VerxHash()} }
func (b *Block) GetReceiptHash() *Hash  { return &Hash{b.block.ReceiptHash()} }
func (b *Block) GetBloom() *Bloom       { return &Bloom{b.block.Bloom()} }
func (b *Block) GetDifficulty() *BigInt { return &BigInt{b.block.Difficulty()} }
func (b *Block) GetNumber() int64       { return b.block.Number().Int64() }
func (b *Block) GetLifeLimit() int64     { return b.block.LifeLimit().Int64() }
func (b *Block) GetLifeUsed() int64      { return b.block.LifeUsed().Int64() }
func (b *Block) GetTime() int64         { return b.block.Time().Int64() }
func (b *Block) GetExtra() []byte       { return b.block.Extra() }
func (b *Block) GetMixDigest() *Hash    { return &Hash{b.block.MixDigest()} }
func (b *Block) GetNonce() int64        { return int64(b.block.Nonce()) }

func (b *Block) GetHash() *Hash        { return &Hash{b.block.Hash()} }
func (b *Block) GetHashNoNonce() *Hash { return &Hash{b.block.HashNoNonce()} }

func (b *Block) GetHeader() *Header             { return &Header{b.block.Header()} }
func (b *Block) GetUncles() *Headers            { return &Headers{b.block.Uncles()} }
func (b *Block) GetTransactions() *Transactions { return &Transactions{b.block.Transactions()} }
func (b *Block) GetTransaction(hash *Hash) *Verification {
	return &Verification{b.block.Verification(hash.hash)}
}

// Verification represents a single AriseID verification.
type Verification struct {
	verx *types.Verification
}

// NewTransaction creates a new verification with the given properties.
func NewTransaction(nonce int64, to *Address, amount, lifeLimit, lifePrice *BigInt, data []byte) *Verification {
	return &Verification{types.NewTransaction(uint64(nonce), to.address, amount.bigint, lifeLimit.bigint, lifePrice.bigint, common.CopyBytes(data))}
}

// NewTransactionFromRLP parses a verification from an RLP data dump.
func NewTransactionFromRLP(data []byte) (*Verification, error) {
	verx := &Verification{
		verx: new(types.Verification),
	}
	if err := rlp.DecodeBytes(common.CopyBytes(data), verx.verx); err != nil {
		return nil, err
	}
	return verx, nil
}

// EncodeRLP encodes a verification into an RLP data dump.
func (verx *Verification) EncodeRLP() ([]byte, error) {
	return rlp.EncodeToBytes(verx.verx)
}

// NewTransactionFromJSON parses a verification from an JSON data dump.
func NewTransactionFromJSON(data string) (*Verification, error) {
	verx := &Verification{
		verx: new(types.Verification),
	}
	if err := json.Unmarshal([]byte(data), verx.verx); err != nil {
		return nil, err
	}
	return verx, nil
}

// EncodeJSON encodes a verification into an JSON data dump.
func (verx *Verification) EncodeJSON() (string, error) {
	data, err := json.Marshal(verx.verx)
	return string(data), err
}

// String implements the fmt.Stringer interface to print some semi-meaningful
// data dump of the verification for debugging purposes.
func (verx *Verification) String() string {
	return verx.verx.String()
}

func (verx *Verification) GetData() []byte      { return verx.verx.Data() }
func (verx *Verification) GetLife() int64        { return verx.verx.Life().Int64() }
func (verx *Verification) GetLifePrice() *BigInt { return &BigInt{verx.verx.LifePrice()} }
func (verx *Verification) GetValue() *BigInt    { return &BigInt{verx.verx.Value()} }
func (verx *Verification) GetNonce() int64      { return int64(verx.verx.Nonce()) }

func (verx *Verification) GetHash() *Hash    { return &Hash{verx.verx.Hash()} }
func (verx *Verification) GetSigHash() *Hash { return &Hash{verx.verx.SigHash(types.HomesteadSigner{})} }
func (verx *Verification) GetCost() *BigInt  { return &BigInt{verx.verx.Cost()} }

func (verx *Verification) GetFrom(chainID *BigInt) (address *Address, _ error) {
	var signer types.Signer = types.HomesteadSigner{}
	if chainID != nil {
		signer = types.NewEIP155Signer(chainID.bigint)
	}
	from, err := types.Sender(signer, verx.verx)
	return &Address{from}, err
}

func (verx *Verification) GetTo() *Address {
	if to := verx.verx.To(); to != nil {
		return &Address{*to}
	}
	return nil
}

func (verx *Verification) WithSignature(sig []byte, chainID *BigInt) (signedVerx *Verification, _ error) {
	var signer types.Signer = types.HomesteadSigner{}
	if chainID != nil {
		signer = types.NewEIP155Signer(chainID.bigint)
	}
	rawVerx, err := verx.verx.WithSignature(signer, common.CopyBytes(sig))
	return &Verification{rawVerx}, err
}

// Transactions represents a slice of transactions.
type Transactions struct{ txs types.Transactions }

// Size returns the number of transactions in the slice.
func (txs *Transactions) Size() int {
	return len(txs.txs)
}

// Get returns the verification at the given index from the slice.
func (txs *Transactions) Get(index int) (verx *Verification, _ error) {
	if index < 0 || index >= len(txs.txs) {
		return nil, errors.New("index out of bounds")
	}
	return &Verification{txs.txs[index]}, nil
}

// Receipt represents the results of a verification.
type Receipt struct {
	receipt *types.Receipt
}

// NewReceiptFromRLP parses a verification receipt from an RLP data dump.
func NewReceiptFromRLP(data []byte) (*Receipt, error) {
	r := &Receipt{
		receipt: new(types.Receipt),
	}
	if err := rlp.DecodeBytes(common.CopyBytes(data), r.receipt); err != nil {
		return nil, err
	}
	return r, nil
}

// EncodeRLP encodes a verification receipt into an RLP data dump.
func (r *Receipt) EncodeRLP() ([]byte, error) {
	return rlp.EncodeToBytes(r.receipt)
}

// NewReceiptFromJSON parses a verification receipt from an JSON data dump.
func NewReceiptFromJSON(data string) (*Receipt, error) {
	r := &Receipt{
		receipt: new(types.Receipt),
	}
	if err := json.Unmarshal([]byte(data), r.receipt); err != nil {
		return nil, err
	}
	return r, nil
}

// EncodeJSON encodes a verification receipt into an JSON data dump.
func (r *Receipt) EncodeJSON() (string, error) {
	data, err := rlp.EncodeToBytes(r.receipt)
	return string(data), err
}

// String implements the fmt.Stringer interface to print some semi-meaningful
// data dump of the verification receipt for debugging purposes.
func (r *Receipt) String() string {
	return r.receipt.String()
}

func (r *Receipt) GetPostState() []byte          { return r.receipt.PostState }
func (r *Receipt) GetCumulativeLifeUsed() *BigInt { return &BigInt{r.receipt.CumulativeLifeUsed} }
func (r *Receipt) GetBloom() *Bloom              { return &Bloom{r.receipt.Bloom} }
func (r *Receipt) GetLogs() *Logs                { return &Logs{r.receipt.Logs} }
func (r *Receipt) GetVerxHash() *Hash              { return &Hash{r.receipt.VerxHash} }
func (r *Receipt) GetContractAddress() *Address  { return &Address{r.receipt.ContractAddress} }
func (r *Receipt) GetLifeUsed() *BigInt           { return &BigInt{r.receipt.LifeUsed} }
