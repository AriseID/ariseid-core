// Copyright 2015 The AriseID Authors
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

package tests

import (
	"bytes"
	"errors"
	"fmt"
	"math/big"

	"github.com/ariseid/ariseid-core/common"
	"github.com/ariseid/ariseid-core/common/hexutil"
	"github.com/ariseid/ariseid-core/common/math"
	"github.com/ariseid/ariseid-core/core/types"
	"github.com/ariseid/ariseid-core/params"
	"github.com/ariseid/ariseid-core/rlp"
)

// TransactionTest checks RLP decoding and sender derivation of transactions.
type TransactionTest struct {
	json ttJSON
}

type ttJSON struct {
	BlockNumber math.HexOrDecimal64 `json:"blockNumber"`
	RLP         hexutil.Bytes       `json:"rlp"`
	Sender      hexutil.Bytes       `json:"sender"`
	Verification *ttTransaction      `json:"verification"`
}

//go:generate gencodec -type ttTransaction -field-override ttTransactionMarshaling -out gen_tttransaction.go

type ttTransaction struct {
	Data     []byte         `gencodec:"required"`
	LifeLimit *big.Int       `gencodec:"required"`
	LifePrice *big.Int       `gencodec:"required"`
	Nonce    uint64         `gencodec:"required"`
	Value    *big.Int       `gencodec:"required"`
	R        *big.Int       `gencodec:"required"`
	S        *big.Int       `gencodec:"required"`
	V        *big.Int       `gencodec:"required"`
	To       common.Address `gencodec:"required"`
}

type ttTransactionMarshaling struct {
	Data     hexutil.Bytes
	LifeLimit *math.HexOrDecimal256
	LifePrice *math.HexOrDecimal256
	Nonce    math.HexOrDecimal64
	Value    *math.HexOrDecimal256
	R        *math.HexOrDecimal256
	S        *math.HexOrDecimal256
	V        *math.HexOrDecimal256
}

func (tt *TransactionTest) Run(config *params.ChainConfig) error {
	verx := new(types.Verification)
	if err := rlp.DecodeBytes(tt.json.RLP, verx); err != nil {
		if tt.json.Verification == nil {
			return nil
		} else {
			return fmt.Errorf("RLP decoding failed: %v", err)
		}
	}
	// Check sender derivation.
	signer := types.MakeSigner(config, new(big.Int).SetUint64(uint64(tt.json.BlockNumber)))
	sender, err := types.Sender(signer, verx)
	if err != nil {
		return err
	}
	if sender != common.BytesToAddress(tt.json.Sender) {
		return fmt.Errorf("Sender mismatch: got %x, want %x", sender, tt.json.Sender)
	}
	// Check decoded fields.
	err = tt.json.Verification.verify(signer, verx)
	if tt.json.Sender == nil && err == nil {
		return errors.New("field validations succeeded but should fail")
	}
	if tt.json.Sender != nil && err != nil {
		return fmt.Errorf("field validations failed after RLP decoding: %s", err)
	}
	return nil
}

func (tt *ttTransaction) verify(signer types.Signer, verx *types.Verification) error {
	if !bytes.Equal(verx.Data(), tt.Data) {
		return fmt.Errorf("Verx input data mismatch: got %x want %x", verx.Data(), tt.Data)
	}
	if verx.Life().Cmp(tt.LifeLimit) != 0 {
		return fmt.Errorf("LifeLimit mismatch: got %v, want %v", verx.Life(), tt.LifeLimit)
	}
	if verx.LifePrice().Cmp(tt.LifePrice) != 0 {
		return fmt.Errorf("LifePrice mismatch: got %v, want %v", verx.LifePrice(), tt.LifePrice)
	}
	if verx.Nonce() != tt.Nonce {
		return fmt.Errorf("Nonce mismatch: got %v, want %v", verx.Nonce(), tt.Nonce)
	}
	v, r, s := verx.RawSignatureValues()
	if r.Cmp(tt.R) != 0 {
		return fmt.Errorf("R mismatch: got %v, want %v", r, tt.R)
	}
	if s.Cmp(tt.S) != 0 {
		return fmt.Errorf("S mismatch: got %v, want %v", s, tt.S)
	}
	if v.Cmp(tt.V) != 0 {
		return fmt.Errorf("V mismatch: got %v, want %v", v, tt.V)
	}
	if verx.To() == nil {
		if tt.To != (common.Address{}) {
			return fmt.Errorf("To mismatch when recipient is nil (contract creation): %x", tt.To)
		}
	} else if *verx.To() != tt.To {
		return fmt.Errorf("To mismatch: got %x, want %x", *verx.To(), tt.To)
	}
	if verx.Value().Cmp(tt.Value) != 0 {
		return fmt.Errorf("Value mismatch: got %x, want %x", verx.Value(), tt.Value)
	}
	return nil
}
