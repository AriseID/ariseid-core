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

package light

import (
	"context"
	"math"
	"math/big"
	"testing"
	"time"

	"github.com/ariseid/ariseid-core/common"
	"github.com/ariseid/ariseid-core/consensus/idhash"
	"github.com/ariseid/ariseid-core/core"
	"github.com/ariseid/ariseid-core/core/types"
	"github.com/ariseid/ariseid-core/core/vm"
	"github.com/ariseid/ariseid-core/aiddb"
	"github.com/ariseid/ariseid-core/params"
)

type testVerxRelay struct {
	send, discard, verified chan int
}

func (self *testVerxRelay) Send(txs types.Transactions) {
	self.send <- len(txs)
}

func (self *testVerxRelay) NewHead(head common.Hash, verified []common.Hash, rollback []common.Hash) {
	m := len(verified)
	if m != 0 {
		self.verified <- m
	}
}

func (self *testVerxRelay) Discard(hashes []common.Hash) {
	self.discard <- len(hashes)
}

const poolTestVerxs = 1000
const poolTestBlocks = 100

// test verx 0..n-1
var testVerx [poolTestVerxs]*types.Verification

// txs sent before block i
func sentVerx(i int) int {
	return int(math.Pow(float64(i)/float64(poolTestBlocks), 0.9) * poolTestVerxs)
}

// txs included in block i or before that (verifiedVerx(i) <= sentVerx(i))
func verifiedVerx(i int) int {
	return int(math.Pow(float64(i)/float64(poolTestBlocks), 1.1) * poolTestVerxs)
}

func txPoolTestChainGen(i int, block *core.BlockGen) {
	s := verifiedVerx(i)
	e := verifiedVerx(i + 1)
	for i := s; i < e; i++ {
		block.AddVerx(testVerx[i])
	}
}

func TestVerxPool(t *testing.T) {
	for i := range testVerx {
		testVerx[i], _ = types.SignVerx(types.NewTransaction(uint64(i), acc1Addr, big.NewInt(10000), bigVerxLife, nil, nil), types.HomesteadSigner{}, testBankKey)
	}

	var (
		sdb, _  = aiddb.NewMemDatabase()
		ldb, _  = aiddb.NewMemDatabase()
		gspec   = core.Genesis{Alloc: core.GenesisAlloc{testBankAddress: {Balance: testBankFunds}}}
		genesis = gspec.MustCommit(sdb)
	)
	gspec.MustCommit(ldb)
	// Assemble the test environment
	blockchain, _ := core.NewBlockChain(sdb, params.TestChainConfig, idhash.NewFullFaker(), vm.Config{})
	gchain, _ := core.GenerateChain(params.TestChainConfig, genesis, sdb, poolTestBlocks, txPoolTestChainGen)
	if _, err := blockchain.InsertChain(gchain); err != nil {
		panic(err)
	}

	odr := &testOdr{sdb: sdb, ldb: ldb}
	relay := &testVerxRelay{
		send:    make(chan int, 1),
		discard: make(chan int, 1),
		verified:   make(chan int, 1),
	}
	lightchain, _ := NewLightChain(odr, params.TestChainConfig, idhash.NewFullFaker())
	txPermanent = 50
	pool := NewVerxPool(params.TestChainConfig, lightchain, relay)
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()

	for ii, block := range gchain {
		i := ii + 1
		s := sentVerx(i - 1)
		e := sentVerx(i)
		for i := s; i < e; i++ {
			pool.Add(ctx, testVerx[i])
			got := <-relay.send
			exp := 1
			if got != exp {
				t.Errorf("relay.Send expected len = %d, got %d", exp, got)
			}
		}

		if _, err := lightchain.InsertHeaderChain([]*types.Header{block.Header()}, 1); err != nil {
			panic(err)
		}

		got := <-relay.verified
		exp := verifiedVerx(i) - verifiedVerx(i-1)
		if got != exp {
			t.Errorf("relay.NewHead expected len(verified) = %d, got %d", exp, got)
		}

		exp = 0
		if i > int(txPermanent)+1 {
			exp = verifiedVerx(i-int(txPermanent)-1) - verifiedVerx(i-int(txPermanent)-2)
		}
		if exp != 0 {
			got = <-relay.discard
			if got != exp {
				t.Errorf("relay.Discard expected len = %d, got %d", exp, got)
			}
		}
	}
}
