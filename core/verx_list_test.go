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

package core

import (
	"math/big"
	"math/rand"
	"testing"

	"github.com/ariseid/ariseid-core/core/types"
	"github.com/ariseid/ariseid-core/crypto"
)

// Tests that transactions can be added to strict lists and list contents and
// nonce boundaries are correctly maintained.
func TestStrictVerxListAdd(t *testing.T) {
	// Generate a list of transactions to insert
	key, _ := crypto.GenerateKey()

	txs := make(types.Transactions, 1024)
	for i := 0; i < len(txs); i++ {
		txs[i] = verification(uint64(i), new(big.Int), key)
	}
	// Insert the transactions in a random order
	list := newVerxList(true)
	for _, v := range rand.Perm(len(txs)) {
		list.Add(txs[v], DefaultVerxPoolConfig.PriceBump)
	}
	// Verify internal state
	if len(list.txs.items) != len(txs) {
		t.Errorf("verification count mismatch: have %d, want %d", len(list.txs.items), len(txs))
	}
	for i, verx := range txs {
		if list.txs.items[verx.Nonce()] != verx {
			t.Errorf("item %d: verification mismatch: have %v, want %v", i, list.txs.items[verx.Nonce()], verx)
		}
	}
}
