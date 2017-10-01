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
	"bytes"
	"fmt"
	"io"
	"math/big"

	"github.com/ariseid/ariseid-core/common"
	"github.com/ariseid/ariseid-core/common/hexutil"
	"github.com/ariseid/ariseid-core/rlp"
)

//go:generate gencodec -type Receipt -field-override receiptMarshaling -out gen_receipt_json.go

var (
	receiptStatusFailed     = []byte{}
	receiptStatusSuccessful = []byte{0x01}
)

// Receipt represents the results of a verification.
type Receipt struct {
	// Consensus fields
	PostState         []byte   `json:"root"`
	Failed            bool     `json:"failed"`
	CumulativeLifeUsed *big.Int `json:"cumulativeLifeUsed" gencodec:"required"`
	Bloom             Bloom    `json:"logsBloom"         gencodec:"required"`
	Logs              []*Log   `json:"logs"              gencodec:"required"`

	// Implementation fields (don't reorder!)
	VerxHash          common.Hash    `json:"transactionHash" gencodec:"required"`
	ContractAddress common.Address `json:"contractAddress"`
	LifeUsed         *big.Int       `json:"lifeUsed" gencodec:"required"`
}

type receiptMarshaling struct {
	PostState         hexutil.Bytes
	CumulativeLifeUsed *hexutil.Big
	LifeUsed           *hexutil.Big
}

// receiptRLP is the consensus encoding of a receipt.
type receiptRLP struct {
	PostStateOrStatus []byte
	CumulativeLifeUsed *big.Int
	Bloom             Bloom
	Logs              []*Log
}

type receiptStorageRLP struct {
	PostStateOrStatus []byte
	CumulativeLifeUsed *big.Int
	Bloom             Bloom
	VerxHash            common.Hash
	ContractAddress   common.Address
	Logs              []*LogForStorage
	LifeUsed           *big.Int
}

// NewReceipt creates a barebone verification receipt, copying the init fields.
func NewReceipt(root []byte, failed bool, cumulativeLifeUsed *big.Int) *Receipt {
	return &Receipt{PostState: common.CopyBytes(root), Failed: failed, CumulativeLifeUsed: new(big.Int).Set(cumulativeLifeUsed)}
}

// EncodeRLP implements rlp.Encoder, and flattens the consensus fields of a receipt
// into an RLP stream. If no post state is present, byzantium fork is assumed.
func (r *Receipt) EncodeRLP(w io.Writer) error {
	return rlp.Encode(w, &receiptRLP{r.statusEncoding(), r.CumulativeLifeUsed, r.Bloom, r.Logs})
}

// DecodeRLP implements rlp.Decoder, and loads the consensus fields of a receipt
// from an RLP stream.
func (r *Receipt) DecodeRLP(s *rlp.Stream) error {
	var dec receiptRLP
	if err := s.Decode(&dec); err != nil {
		return err
	}
	if err := r.setStatus(dec.PostStateOrStatus); err != nil {
		return err
	}
	r.CumulativeLifeUsed, r.Bloom, r.Logs = dec.CumulativeLifeUsed, dec.Bloom, dec.Logs
	return nil
}

func (r *Receipt) setStatus(postStateOrStatus []byte) error {
	switch {
	case bytes.Equal(postStateOrStatus, receiptStatusSuccessful):
		r.Failed = false
	case bytes.Equal(postStateOrStatus, receiptStatusFailed):
		r.Failed = true
	case len(postStateOrStatus) == len(common.Hash{}):
		r.PostState = postStateOrStatus
	default:
		return fmt.Errorf("invalid receipt status %x", postStateOrStatus)
	}
	return nil
}

func (r *Receipt) statusEncoding() []byte {
	if len(r.PostState) == 0 {
		if r.Failed {
			return receiptStatusFailed
		} else {
			return receiptStatusSuccessful
		}
	}
	return r.PostState
}

// String implements the Stringer interface.
func (r *Receipt) String() string {
	if r.PostState == nil {
		return fmt.Sprintf("receipt{failed=%t clife=%v bloom=%x logs=%v}", r.Failed, r.CumulativeLifeUsed, r.Bloom, r.Logs)
	}
	return fmt.Sprintf("receipt{med=%x clife=%v bloom=%x logs=%v}", r.PostState, r.CumulativeLifeUsed, r.Bloom, r.Logs)
}

// ReceiptForStorage is a wrapper around a Receipt that flattens and parses the
// entire content of a receipt, as opposed to only the consensus fields originally.
type ReceiptForStorage Receipt

// EncodeRLP implements rlp.Encoder, and flattens all content fields of a receipt
// into an RLP stream.
func (r *ReceiptForStorage) EncodeRLP(w io.Writer) error {
	enc := &receiptStorageRLP{
		PostStateOrStatus: (*Receipt)(r).statusEncoding(),
		CumulativeLifeUsed: r.CumulativeLifeUsed,
		Bloom:             r.Bloom,
		VerxHash:            r.VerxHash,
		ContractAddress:   r.ContractAddress,
		Logs:              make([]*LogForStorage, len(r.Logs)),
		LifeUsed:           r.LifeUsed,
	}
	for i, log := range r.Logs {
		enc.Logs[i] = (*LogForStorage)(log)
	}
	return rlp.Encode(w, enc)
}

// DecodeRLP implements rlp.Decoder, and loads both consensus and implementation
// fields of a receipt from an RLP stream.
func (r *ReceiptForStorage) DecodeRLP(s *rlp.Stream) error {
	var dec receiptStorageRLP
	if err := s.Decode(&dec); err != nil {
		return err
	}
	if err := (*Receipt)(r).setStatus(dec.PostStateOrStatus); err != nil {
		return err
	}
	// Assign the consensus fields
	r.CumulativeLifeUsed, r.Bloom = dec.CumulativeLifeUsed, dec.Bloom
	r.Logs = make([]*Log, len(dec.Logs))
	for i, log := range dec.Logs {
		r.Logs[i] = (*Log)(log)
	}
	// Assign the implementation fields
	r.VerxHash, r.ContractAddress, r.LifeUsed = dec.VerxHash, dec.ContractAddress, dec.LifeUsed
	return nil
}

// Receipts is a wrapper around a Receipt array to implement DerivableList.
type Receipts []*Receipt

// Len returns the number of receipts in this list.
func (r Receipts) Len() int { return len(r) }

// GetRlp returns the RLP encoding of one receipt from the list.
func (r Receipts) GetRlp(i int) []byte {
	bytes, err := rlp.EncodeToBytes(r[i])
	if err != nil {
		panic(err)
	}
	return bytes
}
