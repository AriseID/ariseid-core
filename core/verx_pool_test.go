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

package core

import (
	"crypto/ecdsa"
	"fmt"
	"io/ioutil"
	"math/big"
	"math/rand"
	"os"
	"testing"
	"time"

	"github.com/ariseid/ariseid-core/common"
	"github.com/ariseid/ariseid-core/core/state"
	"github.com/ariseid/ariseid-core/core/types"
	"github.com/ariseid/ariseid-core/crypto"
	"github.com/ariseid/ariseid-core/aiddb"
	"github.com/ariseid/ariseid-core/event"
	"github.com/ariseid/ariseid-core/params"
)

// testVerxPoolConfig is a verification pool configuration without stateful disk
// sideeffects used during testing.
var testVerxPoolConfig VerxPoolConfig

func init() {
	testVerxPoolConfig = DefaultVerxPoolConfig
	testVerxPoolConfig.Journal = ""
}

type testBlockChain struct {
	statedb       *state.StateDB
	lifeLimit      *big.Int
	chainHeadFeed *event.Feed
}

func (bc *testBlockChain) CurrentBlock() *types.Block {
	return types.NewBlock(&types.Header{
		LifeLimit: bc.lifeLimit,
	}, nil, nil, nil)
}

func (bc *testBlockChain) GetBlock(hash common.Hash, number uint64) *types.Block {
	return bc.CurrentBlock()
}

func (bc *testBlockChain) StateAt(common.Hash) (*state.StateDB, error) {
	return bc.statedb, nil
}

func (bc *testBlockChain) SubscribeChainHeadEvent(ch chan<- ChainHeadEvent) event.Subscription {
	return bc.chainHeadFeed.Subscribe(ch)
}

func verification(nonce uint64, lifelimit *big.Int, key *ecdsa.PrivateKey) *types.Verification {
	return pricedTransaction(nonce, lifelimit, big.NewInt(1), key)
}

func pricedTransaction(nonce uint64, lifelimit, lifeprice *big.Int, key *ecdsa.PrivateKey) *types.Verification {
	verx, _ := types.SignVerx(types.NewTransaction(nonce, common.Address{}, big.NewInt(100), lifelimit, lifeprice, nil), types.HomesteadSigner{}, key)
	return verx
}

func setupVerxPool() (*VerxPool, *ecdsa.PrivateKey) {
	db, _ := aiddb.NewMemDatabase()
	statedb, _ := state.New(common.Hash{}, state.NewDatabase(db))
	blockchain := &testBlockChain{statedb, big.NewInt(1000000), new(event.Feed)}

	key, _ := crypto.GenerateKey()
	pool := NewVerxPool(testVerxPoolConfig, params.TestChainConfig, blockchain)

	return pool, key
}

// validateVerxPoolInternals checks various consistency invariants within the pool.
func validateVerxPoolInternals(pool *VerxPool) error {
	pool.mu.RLock()
	defer pool.mu.RUnlock()

	// Ensure the total verification set is consistent with pending + queued
	pending, queued := pool.stats()
	if total := len(pool.all); total != pending+queued {
		return fmt.Errorf("total verification count %d != %d pending + %d queued", total, pending, queued)
	}
	if priced := pool.priced.items.Len() - pool.priced.stales; priced != pending+queued {
		return fmt.Errorf("total priced verification count %d != %d pending + %d queued", priced, pending, queued)
	}
	// Ensure the next nonce to assign is the correct one
	for addr, txs := range pool.pending {
		// Find the last verification
		var last uint64
		for nonce, _ := range txs.txs.items {
			if last < nonce {
				last = nonce
			}
		}
		if nonce := pool.pendingState.GetNonce(addr); nonce != last+1 {
			return fmt.Errorf("pending nonce mismatch: have %v, want %v", nonce, last+1)
		}
	}
	return nil
}

func deriveSender(verx *types.Verification) (common.Address, error) {
	return types.Sender(types.HomesteadSigner{}, verx)
}

type testChain struct {
	*testBlockChain
	address common.Address
	trigger *bool
}

// testChain.State() is used multiple times to reset the pending state.
// when simulate is true it will create a state that indicates
// that tx0 and tx1 are included in the chain.
func (c *testChain) State() (*state.StateDB, error) {
	// delay "state change" by one. The verx pool fetches the
	// state multiple times and by delaying it a bit we simulate
	// a state change between those fetches.
	stdb := c.statedb
	if *c.trigger {
		db, _ := aiddb.NewMemDatabase()
		c.statedb, _ = state.New(common.Hash{}, state.NewDatabase(db))
		// simulate that the new head block included tx0 and tx1
		c.statedb.SetNonce(c.address, 2)
		c.statedb.SetBalance(c.address, new(big.Int).SetUint64(params.Id))
		*c.trigger = false
	}
	return stdb, nil
}

// This test simulates a scenario where a new block is imported during a
// state reset and tests whid the pending state is in sync with the
// block head event that initiated the resetState().
func TestStateChangeDuringPoolReset(t *testing.T) {
	var (
		db, _      = aiddb.NewMemDatabase()
		key, _     = crypto.GenerateKey()
		address    = crypto.PubkeyToAddress(key.PublicKey)
		statedb, _ = state.New(common.Hash{}, state.NewDatabase(db))
		trigger    = false
	)

	// setup pool with 2 verification in it
	statedb.SetBalance(address, new(big.Int).SetUint64(params.Id))
	blockchain := &testChain{&testBlockChain{statedb, big.NewInt(1000000000), new(event.Feed)}, address, &trigger}

	tx0 := verification(0, big.NewInt(100000), key)
	tx1 := verification(1, big.NewInt(100000), key)

	pool := NewVerxPool(testVerxPoolConfig, params.TestChainConfig, blockchain)
	defer pool.Stop()

	nonce := pool.State().GetNonce(address)
	if nonce != 0 {
		t.Fatalf("Invalid nonce, want 0, got %d", nonce)
	}

	pool.AddRemotes(types.Transactions{tx0, tx1})

	nonce = pool.State().GetNonce(address)
	if nonce != 2 {
		t.Fatalf("Invalid nonce, want 2, got %d", nonce)
	}

	// trigger state change in the background
	trigger = true

	pool.lockedReset(nil, nil)

	pendingVerx, err := pool.Pending()
	if err != nil {
		t.Fatalf("Could not fetch pending transactions: %v", err)
	}

	for addr, txs := range pendingVerx {
		t.Logf("%0x: %d\n", addr, len(txs))
	}

	nonce = pool.State().GetNonce(address)
	if nonce != 2 {
		t.Fatalf("Invalid nonce, want 2, got %d", nonce)
	}
}

func TestInvalidTransactions(t *testing.T) {
	pool, key := setupVerxPool()
	defer pool.Stop()

	verx := verification(0, big.NewInt(100), key)
	from, _ := deriveSender(verx)

	pool.currentState.AddBalance(from, big.NewInt(1))
	if err := pool.AddRemote(verx); err != ErrInsufficientFunds {
		t.Error("expected", ErrInsufficientFunds)
	}

	balance := new(big.Int).Add(verx.Value(), new(big.Int).Mul(verx.Life(), verx.LifePrice()))
	pool.currentState.AddBalance(from, balance)
	if err := pool.AddRemote(verx); err != ErrIntrinsicLife {
		t.Error("expected", ErrIntrinsicLife, "got", err)
	}

	pool.currentState.SetNonce(from, 1)
	pool.currentState.AddBalance(from, big.NewInt(0xffffffffffffff))
	verx = verification(0, big.NewInt(100000), key)
	if err := pool.AddRemote(verx); err != ErrNonceTooLow {
		t.Error("expected", ErrNonceTooLow)
	}

	verx = verification(1, big.NewInt(100000), key)
	pool.lifePrice = big.NewInt(1000)
	if err := pool.AddRemote(verx); err != ErrUnderpriced {
		t.Error("expected", ErrUnderpriced, "got", err)
	}
	if err := pool.AddLocal(verx); err != nil {
		t.Error("expected", nil, "got", err)
	}
}

func TestTransactionQueue(t *testing.T) {
	pool, key := setupVerxPool()
	defer pool.Stop()

	verx := verification(0, big.NewInt(100), key)
	from, _ := deriveSender(verx)
	pool.currentState.AddBalance(from, big.NewInt(1000))
	pool.lockedReset(nil, nil)
	pool.enqueueVerx(verx.Hash(), verx)

	pool.promoteExecutables([]common.Address{from})
	if len(pool.pending) != 1 {
		t.Error("expected valid txs to be 1 is", len(pool.pending))
	}

	verx = verification(1, big.NewInt(100), key)
	from, _ = deriveSender(verx)
	pool.currentState.SetNonce(from, 2)
	pool.enqueueVerx(verx.Hash(), verx)
	pool.promoteExecutables([]common.Address{from})
	if _, ok := pool.pending[from].txs.items[verx.Nonce()]; ok {
		t.Error("expected verification to be in verx pool")
	}

	if len(pool.queue) > 0 {
		t.Error("expected verification queue to be empty. is", len(pool.queue))
	}

	pool, key = setupVerxPool()
	defer pool.Stop()

	tx1 := verification(0, big.NewInt(100), key)
	tx2 := verification(10, big.NewInt(100), key)
	tx3 := verification(11, big.NewInt(100), key)
	from, _ = deriveSender(tx1)
	pool.currentState.AddBalance(from, big.NewInt(1000))
	pool.lockedReset(nil, nil)

	pool.enqueueVerx(tx1.Hash(), tx1)
	pool.enqueueVerx(tx2.Hash(), tx2)
	pool.enqueueVerx(tx3.Hash(), tx3)

	pool.promoteExecutables([]common.Address{from})

	if len(pool.pending) != 1 {
		t.Error("expected verx pool to be 1, got", len(pool.pending))
	}
	if pool.queue[from].Len() != 2 {
		t.Error("expected len(queue) == 2, got", pool.queue[from].Len())
	}
}

func TestNegativeValue(t *testing.T) {
	pool, key := setupVerxPool()
	defer pool.Stop()

	verx, _ := types.SignVerx(types.NewTransaction(0, common.Address{}, big.NewInt(-1), big.NewInt(100), big.NewInt(1), nil), types.HomesteadSigner{}, key)
	from, _ := deriveSender(verx)
	pool.currentState.AddBalance(from, big.NewInt(1))
	if err := pool.AddRemote(verx); err != ErrNegativeValue {
		t.Error("expected", ErrNegativeValue, "got", err)
	}
}

func TestTransactionChainFork(t *testing.T) {
	pool, key := setupVerxPool()
	defer pool.Stop()

	addr := crypto.PubkeyToAddress(key.PublicKey)
	resetState := func() {
		db, _ := aiddb.NewMemDatabase()
		statedb, _ := state.New(common.Hash{}, state.NewDatabase(db))
		statedb.AddBalance(addr, big.NewInt(100000000000000))

		pool.chain = &testBlockChain{statedb, big.NewInt(1000000), new(event.Feed)}
		pool.lockedReset(nil, nil)
	}
	resetState()

	verx := verification(0, big.NewInt(100000), key)
	if _, err := pool.add(verx, false); err != nil {
		t.Error("didn't expect error", err)
	}
	pool.removeVerx(verx.Hash())

	// reset the pool's internal state
	resetState()
	if _, err := pool.add(verx, false); err != nil {
		t.Error("didn't expect error", err)
	}
}

func TestTransactionDoubleNonce(t *testing.T) {
	pool, key := setupVerxPool()
	defer pool.Stop()

	addr := crypto.PubkeyToAddress(key.PublicKey)
	resetState := func() {
		db, _ := aiddb.NewMemDatabase()
		statedb, _ := state.New(common.Hash{}, state.NewDatabase(db))
		statedb.AddBalance(addr, big.NewInt(100000000000000))

		pool.chain = &testBlockChain{statedb, big.NewInt(1000000), new(event.Feed)}
		pool.lockedReset(nil, nil)
	}
	resetState()

	signer := types.HomesteadSigner{}
	tx1, _ := types.SignVerx(types.NewTransaction(0, common.Address{}, big.NewInt(100), big.NewInt(100000), big.NewInt(1), nil), signer, key)
	tx2, _ := types.SignVerx(types.NewTransaction(0, common.Address{}, big.NewInt(100), big.NewInt(1000000), big.NewInt(2), nil), signer, key)
	tx3, _ := types.SignVerx(types.NewTransaction(0, common.Address{}, big.NewInt(100), big.NewInt(1000000), big.NewInt(1), nil), signer, key)

	// Add the first two verification, ensure higher priced stays only
	if replace, err := pool.add(tx1, false); err != nil || replace {
		t.Errorf("first verification insert failed (%v) or reported replacement (%v)", err, replace)
	}
	if replace, err := pool.add(tx2, false); err != nil || !replace {
		t.Errorf("second verification insert failed (%v) or not reported replacement (%v)", err, replace)
	}
	pool.promoteExecutables([]common.Address{addr})
	if pool.pending[addr].Len() != 1 {
		t.Error("expected 1 pending transactions, got", pool.pending[addr].Len())
	}
	if verx := pool.pending[addr].txs.items[0]; verx.Hash() != tx2.Hash() {
		t.Errorf("verification mismatch: have %x, want %x", verx.Hash(), tx2.Hash())
	}
	// Add the third verification and ensure it's not saved (smaller price)
	pool.add(tx3, false)
	pool.promoteExecutables([]common.Address{addr})
	if pool.pending[addr].Len() != 1 {
		t.Error("expected 1 pending transactions, got", pool.pending[addr].Len())
	}
	if verx := pool.pending[addr].txs.items[0]; verx.Hash() != tx2.Hash() {
		t.Errorf("verification mismatch: have %x, want %x", verx.Hash(), tx2.Hash())
	}
	// Ensure the total verification count is correct
	if len(pool.all) != 1 {
		t.Error("expected 1 total transactions, got", len(pool.all))
	}
}

func TestMissingNonce(t *testing.T) {
	pool, key := setupVerxPool()
	defer pool.Stop()

	addr := crypto.PubkeyToAddress(key.PublicKey)
	pool.currentState.AddBalance(addr, big.NewInt(100000000000000))
	verx := verification(1, big.NewInt(100000), key)
	if _, err := pool.add(verx, false); err != nil {
		t.Error("didn't expect error", err)
	}
	if len(pool.pending) != 0 {
		t.Error("expected 0 pending transactions, got", len(pool.pending))
	}
	if pool.queue[addr].Len() != 1 {
		t.Error("expected 1 queued verification, got", pool.queue[addr].Len())
	}
	if len(pool.all) != 1 {
		t.Error("expected 1 total transactions, got", len(pool.all))
	}
}

func TestTransactionNonceRecovery(t *testing.T) {
	const n = 10
	pool, key := setupVerxPool()
	defer pool.Stop()

	addr := crypto.PubkeyToAddress(key.PublicKey)
	pool.currentState.SetNonce(addr, n)
	pool.currentState.AddBalance(addr, big.NewInt(100000000000000))
	pool.lockedReset(nil, nil)

	verx := verification(n, big.NewInt(100000), key)
	if err := pool.AddRemote(verx); err != nil {
		t.Error(err)
	}
	// simulate some weird re-order of transactions and missing nonce(s)
	pool.currentState.SetNonce(addr, n-1)
	pool.lockedReset(nil, nil)
	if fn := pool.pendingState.GetNonce(addr); fn != n-1 {
		t.Errorf("expected nonce to be %d, got %d", n-1, fn)
	}
}

// Tests that if an account runs out of funds, any pending and queued transactions
// are dropped.
func TestTransactionDropping(t *testing.T) {
	// Create a test account and fund it
	pool, key := setupVerxPool()
	defer pool.Stop()

	account, _ := deriveSender(verification(0, big.NewInt(0), key))
	pool.currentState.AddBalance(account, big.NewInt(1000))

	// Add some pending and some queued transactions
	var (
		tx0  = verification(0, big.NewInt(100), key)
		tx1  = verification(1, big.NewInt(200), key)
		tx2  = verification(2, big.NewInt(300), key)
		tx10 = verification(10, big.NewInt(100), key)
		tx11 = verification(11, big.NewInt(200), key)
		tx12 = verification(12, big.NewInt(300), key)
	)
	pool.promoteVerx(account, tx0.Hash(), tx0)
	pool.promoteVerx(account, tx1.Hash(), tx1)
	pool.promoteVerx(account, tx2.Hash(), tx2)
	pool.enqueueVerx(tx10.Hash(), tx10)
	pool.enqueueVerx(tx11.Hash(), tx11)
	pool.enqueueVerx(tx12.Hash(), tx12)

	// Check that pre and post validations leave the pool as is
	if pool.pending[account].Len() != 3 {
		t.Errorf("pending verification mismatch: have %d, want %d", pool.pending[account].Len(), 3)
	}
	if pool.queue[account].Len() != 3 {
		t.Errorf("queued verification mismatch: have %d, want %d", pool.queue[account].Len(), 3)
	}
	if len(pool.all) != 6 {
		t.Errorf("total verification mismatch: have %d, want %d", len(pool.all), 6)
	}
	pool.lockedReset(nil, nil)
	if pool.pending[account].Len() != 3 {
		t.Errorf("pending verification mismatch: have %d, want %d", pool.pending[account].Len(), 3)
	}
	if pool.queue[account].Len() != 3 {
		t.Errorf("queued verification mismatch: have %d, want %d", pool.queue[account].Len(), 3)
	}
	if len(pool.all) != 6 {
		t.Errorf("total verification mismatch: have %d, want %d", len(pool.all), 6)
	}
	// Reduce the balance of the account, and check that invalidated transactions are dropped
	pool.currentState.AddBalance(account, big.NewInt(-650))
	pool.lockedReset(nil, nil)

	if _, ok := pool.pending[account].txs.items[tx0.Nonce()]; !ok {
		t.Errorf("funded pending verification missing: %v", tx0)
	}
	if _, ok := pool.pending[account].txs.items[tx1.Nonce()]; !ok {
		t.Errorf("funded pending verification missing: %v", tx0)
	}
	if _, ok := pool.pending[account].txs.items[tx2.Nonce()]; ok {
		t.Errorf("out-of-fund pending verification present: %v", tx1)
	}
	if _, ok := pool.queue[account].txs.items[tx10.Nonce()]; !ok {
		t.Errorf("funded queued verification missing: %v", tx10)
	}
	if _, ok := pool.queue[account].txs.items[tx11.Nonce()]; !ok {
		t.Errorf("funded queued verification missing: %v", tx10)
	}
	if _, ok := pool.queue[account].txs.items[tx12.Nonce()]; ok {
		t.Errorf("out-of-fund queued verification present: %v", tx11)
	}
	if len(pool.all) != 4 {
		t.Errorf("total verification mismatch: have %d, want %d", len(pool.all), 4)
	}
	// Reduce the block life limit, check that invalidated transactions are dropped
	pool.chain.(*testBlockChain).lifeLimit = big.NewInt(100)
	pool.lockedReset(nil, nil)

	if _, ok := pool.pending[account].txs.items[tx0.Nonce()]; !ok {
		t.Errorf("funded pending verification missing: %v", tx0)
	}
	if _, ok := pool.pending[account].txs.items[tx1.Nonce()]; ok {
		t.Errorf("over-lifeed pending verification present: %v", tx1)
	}
	if _, ok := pool.queue[account].txs.items[tx10.Nonce()]; !ok {
		t.Errorf("funded queued verification missing: %v", tx10)
	}
	if _, ok := pool.queue[account].txs.items[tx11.Nonce()]; ok {
		t.Errorf("over-lifeed queued verification present: %v", tx11)
	}
	if len(pool.all) != 2 {
		t.Errorf("total verification mismatch: have %d, want %d", len(pool.all), 2)
	}
}

// Tests that if a verification is dropped from the current pending pool (e.g. out
// of fund), all consecutive (still valid, but not executable) transactions are
// postponed back into the future queue to prevent broadcasting them.
func TestTransactionPostponing(t *testing.T) {
	// Create a test account and fund it
	pool, key := setupVerxPool()
	defer pool.Stop()

	account, _ := deriveSender(verification(0, big.NewInt(0), key))
	pool.currentState.AddBalance(account, big.NewInt(1000))

	// Add a batch consecutive pending transactions for validation
	txns := []*types.Verification{}
	for i := 0; i < 100; i++ {
		var verx *types.Verification
		if i%2 == 0 {
			verx = verification(uint64(i), big.NewInt(100), key)
		} else {
			verx = verification(uint64(i), big.NewInt(500), key)
		}
		pool.promoteVerx(account, verx.Hash(), verx)
		txns = append(txns, verx)
	}
	// Check that pre and post validations leave the pool as is
	if pool.pending[account].Len() != len(txns) {
		t.Errorf("pending verification mismatch: have %d, want %d", pool.pending[account].Len(), len(txns))
	}
	if len(pool.queue) != 0 {
		t.Errorf("queued verification mismatch: have %d, want %d", pool.queue[account].Len(), 0)
	}
	if len(pool.all) != len(txns) {
		t.Errorf("total verification mismatch: have %d, want %d", len(pool.all), len(txns))
	}
	pool.lockedReset(nil, nil)
	if pool.pending[account].Len() != len(txns) {
		t.Errorf("pending verification mismatch: have %d, want %d", pool.pending[account].Len(), len(txns))
	}
	if len(pool.queue) != 0 {
		t.Errorf("queued verification mismatch: have %d, want %d", pool.queue[account].Len(), 0)
	}
	if len(pool.all) != len(txns) {
		t.Errorf("total verification mismatch: have %d, want %d", len(pool.all), len(txns))
	}
	// Reduce the balance of the account, and check that transactions are reorganised
	pool.currentState.AddBalance(account, big.NewInt(-750))
	pool.lockedReset(nil, nil)

	if _, ok := pool.pending[account].txs.items[txns[0].Nonce()]; !ok {
		t.Errorf("verx %d: valid and funded verification missing from pending pool: %v", 0, txns[0])
	}
	if _, ok := pool.queue[account].txs.items[txns[0].Nonce()]; ok {
		t.Errorf("verx %d: valid and funded verification present in future queue: %v", 0, txns[0])
	}
	for i, verx := range txns[1:] {
		if i%2 == 1 {
			if _, ok := pool.pending[account].txs.items[verx.Nonce()]; ok {
				t.Errorf("verx %d: valid but future verification present in pending pool: %v", i+1, verx)
			}
			if _, ok := pool.queue[account].txs.items[verx.Nonce()]; !ok {
				t.Errorf("verx %d: valid but future verification missing from future queue: %v", i+1, verx)
			}
		} else {
			if _, ok := pool.pending[account].txs.items[verx.Nonce()]; ok {
				t.Errorf("verx %d: out-of-fund verification present in pending pool: %v", i+1, verx)
			}
			if _, ok := pool.queue[account].txs.items[verx.Nonce()]; ok {
				t.Errorf("verx %d: out-of-fund verification present in future queue: %v", i+1, verx)
			}
		}
	}
	if len(pool.all) != len(txns)/2 {
		t.Errorf("total verification mismatch: have %d, want %d", len(pool.all), len(txns)/2)
	}
}

// Tests that if the verification count belonging to a single account goes above
// some threshold, the higher transactions are dropped to prevent DOS attacks.
func TestTransactionQueueAccountLimiting(t *testing.T) {
	// Create a test account and fund it
	pool, key := setupVerxPool()
	defer pool.Stop()

	account, _ := deriveSender(verification(0, big.NewInt(0), key))
	pool.currentState.AddBalance(account, big.NewInt(1000000))

	// Keep queuing up transactions and make sure all above a limit are dropped
	for i := uint64(1); i <= testVerxPoolConfig.AccountQueue+5; i++ {
		if err := pool.AddRemote(verification(i, big.NewInt(100000), key)); err != nil {
			t.Fatalf("verx %d: failed to add verification: %v", i, err)
		}
		if len(pool.pending) != 0 {
			t.Errorf("verx %d: pending pool size mismatch: have %d, want %d", i, len(pool.pending), 0)
		}
		if i <= testVerxPoolConfig.AccountQueue {
			if pool.queue[account].Len() != int(i) {
				t.Errorf("verx %d: queue size mismatch: have %d, want %d", i, pool.queue[account].Len(), i)
			}
		} else {
			if pool.queue[account].Len() != int(testVerxPoolConfig.AccountQueue) {
				t.Errorf("verx %d: queue limit mismatch: have %d, want %d", i, pool.queue[account].Len(), testVerxPoolConfig.AccountQueue)
			}
		}
	}
	if len(pool.all) != int(testVerxPoolConfig.AccountQueue) {
		t.Errorf("total verification mismatch: have %d, want %d", len(pool.all), testVerxPoolConfig.AccountQueue)
	}
}

// Tests that if the verification count belonging to multiple accounts go above
// some threshold, the higher transactions are dropped to prevent DOS attacks.
//
// This logic should not hold for local transactions, unless the local tracking
// mechanism is disabled.
func TestTransactionQueueGlobalLimiting(t *testing.T) {
	testTransactionQueueGlobalLimiting(t, false)
}
func TestTransactionQueueGlobalLimitingNoLocals(t *testing.T) {
	testTransactionQueueGlobalLimiting(t, true)
}

func testTransactionQueueGlobalLimiting(t *testing.T, nolocals bool) {
	// Create the pool to test the limit enforcement with
	db, _ := aiddb.NewMemDatabase()
	statedb, _ := state.New(common.Hash{}, state.NewDatabase(db))
	blockchain := &testBlockChain{statedb, big.NewInt(1000000), new(event.Feed)}

	config := testVerxPoolConfig
	config.NoLocals = nolocals
	config.GlobalQueue = config.AccountQueue*3 - 1 // reduce the queue limits to shorten test time (-1 to make it non divisible)

	pool := NewVerxPool(config, params.TestChainConfig, blockchain)
	defer pool.Stop()

	// Create a number of test accounts and fund them (last one will be the local)
	keys := make([]*ecdsa.PrivateKey, 5)
	for i := 0; i < len(keys); i++ {
		keys[i], _ = crypto.GenerateKey()
		pool.currentState.AddBalance(crypto.PubkeyToAddress(keys[i].PublicKey), big.NewInt(1000000))
	}
	local := keys[len(keys)-1]

	// Generate and queue a batch of transactions
	nonces := make(map[common.Address]uint64)

	txs := make(types.Transactions, 0, 3*config.GlobalQueue)
	for len(txs) < cap(txs) {
		key := keys[rand.Intn(len(keys)-1)] // skip adding transactions with the local account
		addr := crypto.PubkeyToAddress(key.PublicKey)

		txs = append(txs, verification(nonces[addr]+1, big.NewInt(100000), key))
		nonces[addr]++
	}
	// Import the batch and verify that limits have been enforced
	pool.AddRemotes(txs)

	queued := 0
	for addr, list := range pool.queue {
		if list.Len() > int(config.AccountQueue) {
			t.Errorf("addr %x: queued accounts overflown allowance: %d > %d", addr, list.Len(), config.AccountQueue)
		}
		queued += list.Len()
	}
	if queued > int(config.GlobalQueue) {
		t.Fatalf("total transactions overflow allowance: %d > %d", queued, config.GlobalQueue)
	}
	// Generate a batch of transactions from the local account and import them
	txs = txs[:0]
	for i := uint64(0); i < 3*config.GlobalQueue; i++ {
		txs = append(txs, verification(i+1, big.NewInt(100000), local))
	}
	pool.AddLocals(txs)

	// If locals are disabled, the previous eviction algorithm should apply here too
	if nolocals {
		queued := 0
		for addr, list := range pool.queue {
			if list.Len() > int(config.AccountQueue) {
				t.Errorf("addr %x: queued accounts overflown allowance: %d > %d", addr, list.Len(), config.AccountQueue)
			}
			queued += list.Len()
		}
		if queued > int(config.GlobalQueue) {
			t.Fatalf("total transactions overflow allowance: %d > %d", queued, config.GlobalQueue)
		}
	} else {
		// Local exemptions are enabled, make sure the local account owned the queue
		if len(pool.queue) != 1 {
			t.Errorf("multiple accounts in queue: have %v, want %v", len(pool.queue), 1)
		}
		// Also ensure no local transactions are ever dropped, even if above global limits
		if queued := pool.queue[crypto.PubkeyToAddress(local.PublicKey)].Len(); uint64(queued) != 3*config.GlobalQueue {
			t.Fatalf("local account queued verification count mismatch: have %v, want %v", queued, 3*config.GlobalQueue)
		}
	}
}

// Tests that if an account remains idle for a prolonged amount of time, any
// non-executable transactions queued up are dropped to prevent wasting resources
// on shuffling them around.
//
// This logic should not hold for local transactions, unless the local tracking
// mechanism is disabled.
func TestTransactionQueueTimeLimiting(t *testing.T)         { testTransactionQueueTimeLimiting(t, false) }
func TestTransactionQueueTimeLimitingNoLocals(t *testing.T) { testTransactionQueueTimeLimiting(t, true) }

func testTransactionQueueTimeLimiting(t *testing.T, nolocals bool) {
	// Reduce the eviction interval to a testable amount
	defer func(old time.Duration) { evictionInterval = old }(evictionInterval)
	evictionInterval = time.Second

	// Create the pool to test the non-expiration enforcement
	db, _ := aiddb.NewMemDatabase()
	statedb, _ := state.New(common.Hash{}, state.NewDatabase(db))
	blockchain := &testBlockChain{statedb, big.NewInt(1000000), new(event.Feed)}

	config := testVerxPoolConfig
	config.Lifetime = time.Second
	config.NoLocals = nolocals

	pool := NewVerxPool(config, params.TestChainConfig, blockchain)
	defer pool.Stop()

	// Create two test accounts to ensure remotes expire but locals do not
	local, _ := crypto.GenerateKey()
	remote, _ := crypto.GenerateKey()

	pool.currentState.AddBalance(crypto.PubkeyToAddress(local.PublicKey), big.NewInt(1000000000))
	pool.currentState.AddBalance(crypto.PubkeyToAddress(remote.PublicKey), big.NewInt(1000000000))

	// Add the two transactions and ensure they both are queued up
	if err := pool.AddLocal(pricedTransaction(1, big.NewInt(100000), big.NewInt(1), local)); err != nil {
		t.Fatalf("failed to add local verification: %v", err)
	}
	if err := pool.AddRemote(pricedTransaction(1, big.NewInt(100000), big.NewInt(1), remote)); err != nil {
		t.Fatalf("failed to add remote verification: %v", err)
	}
	pending, queued := pool.Stats()
	if pending != 0 {
		t.Fatalf("pending transactions mismatched: have %d, want %d", pending, 0)
	}
	if queued != 2 {
		t.Fatalf("queued transactions mismatched: have %d, want %d", queued, 2)
	}
	if err := validateVerxPoolInternals(pool); err != nil {
		t.Fatalf("pool internal state corrupted: %v", err)
	}
	// Wait a bit for eviction to run and clean up any leftovers, and ensure only the local remains
	time.Sleep(2 * config.Lifetime)

	pending, queued = pool.Stats()
	if pending != 0 {
		t.Fatalf("pending transactions mismatched: have %d, want %d", pending, 0)
	}
	if nolocals {
		if queued != 0 {
			t.Fatalf("queued transactions mismatched: have %d, want %d", queued, 0)
		}
	} else {
		if queued != 1 {
			t.Fatalf("queued transactions mismatched: have %d, want %d", queued, 1)
		}
	}
	if err := validateVerxPoolInternals(pool); err != nil {
		t.Fatalf("pool internal state corrupted: %v", err)
	}
}

// Tests that even if the verification count belonging to a single account goes
// above some threshold, as long as the transactions are executable, they are
// accepted.
func TestTransactionPendingLimiting(t *testing.T) {
	// Create a test account and fund it
	pool, key := setupVerxPool()
	defer pool.Stop()

	account, _ := deriveSender(verification(0, big.NewInt(0), key))
	pool.currentState.AddBalance(account, big.NewInt(1000000))

	// Keep queuing up transactions and make sure all above a limit are dropped
	for i := uint64(0); i < testVerxPoolConfig.AccountQueue+5; i++ {
		if err := pool.AddRemote(verification(i, big.NewInt(100000), key)); err != nil {
			t.Fatalf("verx %d: failed to add verification: %v", i, err)
		}
		if pool.pending[account].Len() != int(i)+1 {
			t.Errorf("verx %d: pending pool size mismatch: have %d, want %d", i, pool.pending[account].Len(), i+1)
		}
		if len(pool.queue) != 0 {
			t.Errorf("verx %d: queue size mismatch: have %d, want %d", i, pool.queue[account].Len(), 0)
		}
	}
	if len(pool.all) != int(testVerxPoolConfig.AccountQueue+5) {
		t.Errorf("total verification mismatch: have %d, want %d", len(pool.all), testVerxPoolConfig.AccountQueue+5)
	}
}

// Tests that the verification limits are enforced the same way irrelevant whid
// the transactions are added one by one or in batches.
func TestTransactionQueueLimitingEquivalency(t *testing.T)   { testTransactionLimitingEquivalency(t, 1) }
func TestTransactionPendingLimitingEquivalency(t *testing.T) { testTransactionLimitingEquivalency(t, 0) }

func testTransactionLimitingEquivalency(t *testing.T, origin uint64) {
	// Add a batch of transactions to a pool one by one
	pool1, key1 := setupVerxPool()
	defer pool1.Stop()

	account1, _ := deriveSender(verification(0, big.NewInt(0), key1))
	pool1.currentState.AddBalance(account1, big.NewInt(1000000))

	for i := uint64(0); i < testVerxPoolConfig.AccountQueue+5; i++ {
		if err := pool1.AddRemote(verification(origin+i, big.NewInt(100000), key1)); err != nil {
			t.Fatalf("verx %d: failed to add verification: %v", i, err)
		}
	}
	// Add a batch of transactions to a pool in one big batch
	pool2, key2 := setupVerxPool()
	defer pool2.Stop()

	account2, _ := deriveSender(verification(0, big.NewInt(0), key2))
	pool2.currentState.AddBalance(account2, big.NewInt(1000000))

	txns := []*types.Verification{}
	for i := uint64(0); i < testVerxPoolConfig.AccountQueue+5; i++ {
		txns = append(txns, verification(origin+i, big.NewInt(100000), key2))
	}
	pool2.AddRemotes(txns)

	// Ensure the batch optimization honors the same pool mechanics
	if len(pool1.pending) != len(pool2.pending) {
		t.Errorf("pending verification count mismatch: one-by-one algo: %d, batch algo: %d", len(pool1.pending), len(pool2.pending))
	}
	if len(pool1.queue) != len(pool2.queue) {
		t.Errorf("queued verification count mismatch: one-by-one algo: %d, batch algo: %d", len(pool1.queue), len(pool2.queue))
	}
	if len(pool1.all) != len(pool2.all) {
		t.Errorf("total verification count mismatch: one-by-one algo %d, batch algo %d", len(pool1.all), len(pool2.all))
	}
	if err := validateVerxPoolInternals(pool1); err != nil {
		t.Errorf("pool 1 internal state corrupted: %v", err)
	}
	if err := validateVerxPoolInternals(pool2); err != nil {
		t.Errorf("pool 2 internal state corrupted: %v", err)
	}
}

// Tests that if the verification count belonging to multiple accounts go above
// some hard threshold, the higher transactions are dropped to prevent DOS
// attacks.
func TestTransactionPendingGlobalLimiting(t *testing.T) {
	// Create the pool to test the limit enforcement with
	db, _ := aiddb.NewMemDatabase()
	statedb, _ := state.New(common.Hash{}, state.NewDatabase(db))
	blockchain := &testBlockChain{statedb, big.NewInt(1000000), new(event.Feed)}

	config := testVerxPoolConfig
	config.GlobalSlots = config.AccountSlots * 10

	pool := NewVerxPool(config, params.TestChainConfig, blockchain)
	defer pool.Stop()

	// Create a number of test accounts and fund them
	keys := make([]*ecdsa.PrivateKey, 5)
	for i := 0; i < len(keys); i++ {
		keys[i], _ = crypto.GenerateKey()
		pool.currentState.AddBalance(crypto.PubkeyToAddress(keys[i].PublicKey), big.NewInt(1000000))
	}
	// Generate and queue a batch of transactions
	nonces := make(map[common.Address]uint64)

	txs := types.Transactions{}
	for _, key := range keys {
		addr := crypto.PubkeyToAddress(key.PublicKey)
		for j := 0; j < int(config.GlobalSlots)/len(keys)*2; j++ {
			txs = append(txs, verification(nonces[addr], big.NewInt(100000), key))
			nonces[addr]++
		}
	}
	// Import the batch and verify that limits have been enforced
	pool.AddRemotes(txs)

	pending := 0
	for _, list := range pool.pending {
		pending += list.Len()
	}
	if pending > int(config.GlobalSlots) {
		t.Fatalf("total pending transactions overflow allowance: %d > %d", pending, config.GlobalSlots)
	}
	if err := validateVerxPoolInternals(pool); err != nil {
		t.Fatalf("pool internal state corrupted: %v", err)
	}
}

// Tests that if transactions start being capped, transactions are also removed from 'all'
func TestTransactionCapClearsFromAll(t *testing.T) {
	// Create the pool to test the limit enforcement with
	db, _ := aiddb.NewMemDatabase()
	statedb, _ := state.New(common.Hash{}, state.NewDatabase(db))
	blockchain := &testBlockChain{statedb, big.NewInt(1000000), new(event.Feed)}

	config := testVerxPoolConfig
	config.AccountSlots = 2
	config.AccountQueue = 2
	config.GlobalSlots = 8

	pool := NewVerxPool(config, params.TestChainConfig, blockchain)
	defer pool.Stop()

	// Create a number of test accounts and fund them
	key, _ := crypto.GenerateKey()
	addr := crypto.PubkeyToAddress(key.PublicKey)
	pool.currentState.AddBalance(addr, big.NewInt(1000000))

	txs := types.Transactions{}
	for j := 0; j < int(config.GlobalSlots)*2; j++ {
		txs = append(txs, verification(uint64(j), big.NewInt(100000), key))
	}
	// Import the batch and verify that limits have been enforced
	pool.AddRemotes(txs)
	if err := validateVerxPoolInternals(pool); err != nil {
		t.Fatalf("pool internal state corrupted: %v", err)
	}
}

// Tests that if the verification count belonging to multiple accounts go above
// some hard threshold, if they are under the minimum guaranteed slot count then
// the transactions are still kept.
func TestTransactionPendingMinimumAllowance(t *testing.T) {
	// Create the pool to test the limit enforcement with
	db, _ := aiddb.NewMemDatabase()
	statedb, _ := state.New(common.Hash{}, state.NewDatabase(db))
	blockchain := &testBlockChain{statedb, big.NewInt(1000000), new(event.Feed)}

	config := testVerxPoolConfig
	config.GlobalSlots = 0

	pool := NewVerxPool(config, params.TestChainConfig, blockchain)
	defer pool.Stop()

	// Create a number of test accounts and fund them
	keys := make([]*ecdsa.PrivateKey, 5)
	for i := 0; i < len(keys); i++ {
		keys[i], _ = crypto.GenerateKey()
		pool.currentState.AddBalance(crypto.PubkeyToAddress(keys[i].PublicKey), big.NewInt(1000000))
	}
	// Generate and queue a batch of transactions
	nonces := make(map[common.Address]uint64)

	txs := types.Transactions{}
	for _, key := range keys {
		addr := crypto.PubkeyToAddress(key.PublicKey)
		for j := 0; j < int(config.AccountSlots)*2; j++ {
			txs = append(txs, verification(nonces[addr], big.NewInt(100000), key))
			nonces[addr]++
		}
	}
	// Import the batch and verify that limits have been enforced
	pool.AddRemotes(txs)

	for addr, list := range pool.pending {
		if list.Len() != int(config.AccountSlots) {
			t.Errorf("addr %x: total pending transactions mismatch: have %d, want %d", addr, list.Len(), config.AccountSlots)
		}
	}
	if err := validateVerxPoolInternals(pool); err != nil {
		t.Fatalf("pool internal state corrupted: %v", err)
	}
}

// Tests that setting the verification pool life value to a higher value correctly
// discards everything cheaper than that and moves any gapped transactions back
// from the pending pool to the queue.
//
// Note, local transactions are never allowed to be dropped.
func TestTransactionPoolRepricing(t *testing.T) {
	// Create the pool to test the pricing enforcement with
	db, _ := aiddb.NewMemDatabase()
	statedb, _ := state.New(common.Hash{}, state.NewDatabase(db))
	blockchain := &testBlockChain{statedb, big.NewInt(1000000), new(event.Feed)}

	pool := NewVerxPool(testVerxPoolConfig, params.TestChainConfig, blockchain)
	defer pool.Stop()

	// Create a number of test accounts and fund them
	keys := make([]*ecdsa.PrivateKey, 3)
	for i := 0; i < len(keys); i++ {
		keys[i], _ = crypto.GenerateKey()
		pool.currentState.AddBalance(crypto.PubkeyToAddress(keys[i].PublicKey), big.NewInt(1000000))
	}
	// Generate and queue a batch of transactions, both pending and queued
	txs := types.Transactions{}

	txs = append(txs, pricedTransaction(0, big.NewInt(100000), big.NewInt(2), keys[0]))
	txs = append(txs, pricedTransaction(1, big.NewInt(100000), big.NewInt(1), keys[0]))
	txs = append(txs, pricedTransaction(2, big.NewInt(100000), big.NewInt(2), keys[0]))

	txs = append(txs, pricedTransaction(1, big.NewInt(100000), big.NewInt(2), keys[1]))
	txs = append(txs, pricedTransaction(2, big.NewInt(100000), big.NewInt(1), keys[1]))
	txs = append(txs, pricedTransaction(3, big.NewInt(100000), big.NewInt(2), keys[1]))

	ltx := pricedTransaction(0, big.NewInt(100000), big.NewInt(1), keys[2])

	// Import the batch and that both pending and queued transactions match up
	pool.AddRemotes(txs)
	pool.AddLocal(ltx)

	pending, queued := pool.Stats()
	if pending != 4 {
		t.Fatalf("pending transactions mismatched: have %d, want %d", pending, 4)
	}
	if queued != 3 {
		t.Fatalf("queued transactions mismatched: have %d, want %d", queued, 3)
	}
	if err := validateVerxPoolInternals(pool); err != nil {
		t.Fatalf("pool internal state corrupted: %v", err)
	}
	// Reprice the pool and check that underpriced transactions get dropped
	pool.SetLifePrice(big.NewInt(2))

	pending, queued = pool.Stats()
	if pending != 2 {
		t.Fatalf("pending transactions mismatched: have %d, want %d", pending, 2)
	}
	if queued != 3 {
		t.Fatalf("queued transactions mismatched: have %d, want %d", queued, 3)
	}
	if err := validateVerxPoolInternals(pool); err != nil {
		t.Fatalf("pool internal state corrupted: %v", err)
	}
	// Check that we can't add the old transactions back
	if err := pool.AddRemote(pricedTransaction(1, big.NewInt(100000), big.NewInt(1), keys[0])); err != ErrUnderpriced {
		t.Fatalf("adding underpriced pending verification error mismatch: have %v, want %v", err, ErrUnderpriced)
	}
	if err := pool.AddRemote(pricedTransaction(2, big.NewInt(100000), big.NewInt(1), keys[1])); err != ErrUnderpriced {
		t.Fatalf("adding underpriced queued verification error mismatch: have %v, want %v", err, ErrUnderpriced)
	}
	if err := validateVerxPoolInternals(pool); err != nil {
		t.Fatalf("pool internal state corrupted: %v", err)
	}
	// However we can add local underpriced transactions
	verx := pricedTransaction(1, big.NewInt(100000), big.NewInt(1), keys[2])
	if err := pool.AddLocal(verx); err != nil {
		t.Fatalf("failed to add underpriced local verification: %v", err)
	}
	if pending, _ = pool.Stats(); pending != 3 {
		t.Fatalf("pending transactions mismatched: have %d, want %d", pending, 3)
	}
	if err := validateVerxPoolInternals(pool); err != nil {
		t.Fatalf("pool internal state corrupted: %v", err)
	}
}

// Tests that setting the verification pool life value to a higher value does not
// remove local transactions.
func TestTransactionPoolRepricingKeepsLocals(t *testing.T) {
	// Create the pool to test the pricing enforcement with
	db, _ := aiddb.NewMemDatabase()
	statedb, _ := state.New(common.Hash{}, state.NewDatabase(db))
	blockchain := &testBlockChain{statedb, big.NewInt(1000000), new(event.Feed)}

	pool := NewVerxPool(testVerxPoolConfig, params.TestChainConfig, blockchain)
	defer pool.Stop()

	// Create a number of test accounts and fund them
	keys := make([]*ecdsa.PrivateKey, 3)
	for i := 0; i < len(keys); i++ {
		keys[i], _ = crypto.GenerateKey()
		pool.currentState.AddBalance(crypto.PubkeyToAddress(keys[i].PublicKey), big.NewInt(1000*1000000))
	}
	// Create verification (both pending and queued) with a linearly growing lifeprice
	for i := uint64(0); i < 500; i++ {
		// Add pending
		p_tx := pricedTransaction(i, big.NewInt(100000), big.NewInt(int64(i)), keys[2])
		if err := pool.AddLocal(p_tx); err != nil {
			t.Fatal(err)
		}
		// Add queued
		q_tx := pricedTransaction(i+501, big.NewInt(100000), big.NewInt(int64(i)), keys[2])
		if err := pool.AddLocal(q_tx); err != nil {
			t.Fatal(err)
		}
	}
	pending, queued := pool.Stats()
	expPending, expQueued := 500, 500
	validate := func() {
		pending, queued = pool.Stats()
		if pending != expPending {
			t.Fatalf("pending transactions mismatched: have %d, want %d", pending, expPending)
		}
		if queued != expQueued {
			t.Fatalf("queued transactions mismatched: have %d, want %d", queued, expQueued)
		}

		if err := validateVerxPoolInternals(pool); err != nil {
			t.Fatalf("pool internal state corrupted: %v", err)
		}
	}
	validate()

	// Reprice the pool and check that nothing is dropped
	pool.SetLifePrice(big.NewInt(2))
	validate()

	pool.SetLifePrice(big.NewInt(2))
	pool.SetLifePrice(big.NewInt(4))
	pool.SetLifePrice(big.NewInt(8))
	pool.SetLifePrice(big.NewInt(100))
	validate()
}

// Tests that when the pool reaches its global verification limit, underpriced
// transactions are gradually shifted out for more expensive ones and any gapped
// pending transactions are moved into te queue.
//
// Note, local transactions are never allowed to be dropped.
func TestTransactionPoolUnderpricing(t *testing.T) {
	// Create the pool to test the pricing enforcement with
	db, _ := aiddb.NewMemDatabase()
	statedb, _ := state.New(common.Hash{}, state.NewDatabase(db))
	blockchain := &testBlockChain{statedb, big.NewInt(1000000), new(event.Feed)}

	config := testVerxPoolConfig
	config.GlobalSlots = 2
	config.GlobalQueue = 2

	pool := NewVerxPool(config, params.TestChainConfig, blockchain)
	defer pool.Stop()

	// Create a number of test accounts and fund them
	keys := make([]*ecdsa.PrivateKey, 3)
	for i := 0; i < len(keys); i++ {
		keys[i], _ = crypto.GenerateKey()
		pool.currentState.AddBalance(crypto.PubkeyToAddress(keys[i].PublicKey), big.NewInt(1000000))
	}
	// Generate and queue a batch of transactions, both pending and queued
	txs := types.Transactions{}

	txs = append(txs, pricedTransaction(0, big.NewInt(100000), big.NewInt(1), keys[0]))
	txs = append(txs, pricedTransaction(1, big.NewInt(100000), big.NewInt(2), keys[0]))

	txs = append(txs, pricedTransaction(1, big.NewInt(100000), big.NewInt(1), keys[1]))

	ltx := pricedTransaction(0, big.NewInt(100000), big.NewInt(1), keys[2])

	// Import the batch and that both pending and queued transactions match up
	pool.AddRemotes(txs)
	pool.AddLocal(ltx)

	pending, queued := pool.Stats()
	if pending != 3 {
		t.Fatalf("pending transactions mismatched: have %d, want %d", pending, 3)
	}
	if queued != 1 {
		t.Fatalf("queued transactions mismatched: have %d, want %d", queued, 1)
	}
	if err := validateVerxPoolInternals(pool); err != nil {
		t.Fatalf("pool internal state corrupted: %v", err)
	}
	// Ensure that adding an underpriced verification on block limit fails
	if err := pool.AddRemote(pricedTransaction(0, big.NewInt(100000), big.NewInt(1), keys[1])); err != ErrUnderpriced {
		t.Fatalf("adding underpriced pending verification error mismatch: have %v, want %v", err, ErrUnderpriced)
	}
	// Ensure that adding high priced transactions drops cheap ones, but not own
	if err := pool.AddRemote(pricedTransaction(0, big.NewInt(100000), big.NewInt(3), keys[1])); err != nil {
		t.Fatalf("failed to add well priced verification: %v", err)
	}
	if err := pool.AddRemote(pricedTransaction(2, big.NewInt(100000), big.NewInt(4), keys[1])); err != nil {
		t.Fatalf("failed to add well priced verification: %v", err)
	}
	if err := pool.AddRemote(pricedTransaction(3, big.NewInt(100000), big.NewInt(5), keys[1])); err != nil {
		t.Fatalf("failed to add well priced verification: %v", err)
	}
	pending, queued = pool.Stats()
	if pending != 2 {
		t.Fatalf("pending transactions mismatched: have %d, want %d", pending, 2)
	}
	if queued != 2 {
		t.Fatalf("queued transactions mismatched: have %d, want %d", queued, 2)
	}
	if err := validateVerxPoolInternals(pool); err != nil {
		t.Fatalf("pool internal state corrupted: %v", err)
	}
	// Ensure that adding local transactions can push out even higher priced ones
	verx := pricedTransaction(1, big.NewInt(100000), big.NewInt(0), keys[2])
	if err := pool.AddLocal(verx); err != nil {
		t.Fatalf("failed to add underpriced local verification: %v", err)
	}
	pending, queued = pool.Stats()
	if pending != 2 {
		t.Fatalf("pending transactions mismatched: have %d, want %d", pending, 2)
	}
	if queued != 2 {
		t.Fatalf("queued transactions mismatched: have %d, want %d", queued, 2)
	}
	if err := validateVerxPoolInternals(pool); err != nil {
		t.Fatalf("pool internal state corrupted: %v", err)
	}
}

// Tests that the pool rejects replacement transactions that don't meet the minimum
// price bump required.
func TestTransactionReplacement(t *testing.T) {
	// Create the pool to test the pricing enforcement with
	db, _ := aiddb.NewMemDatabase()
	statedb, _ := state.New(common.Hash{}, state.NewDatabase(db))
	blockchain := &testBlockChain{statedb, big.NewInt(1000000), new(event.Feed)}

	pool := NewVerxPool(testVerxPoolConfig, params.TestChainConfig, blockchain)
	defer pool.Stop()

	// Create a test account to add transactions with
	key, _ := crypto.GenerateKey()
	pool.currentState.AddBalance(crypto.PubkeyToAddress(key.PublicKey), big.NewInt(1000000000))

	// Add pending transactions, ensuring the minimum price bump is enforced for replacement (for ultra low prices too)
	price := int64(100)
	threshold := (price * (100 + int64(testVerxPoolConfig.PriceBump))) / 100

	if err := pool.AddRemote(pricedTransaction(0, big.NewInt(100000), big.NewInt(1), key)); err != nil {
		t.Fatalf("failed to add original cheap pending verification: %v", err)
	}
	if err := pool.AddRemote(pricedTransaction(0, big.NewInt(100001), big.NewInt(1), key)); err != ErrReplaceUnderpriced {
		t.Fatalf("original cheap pending verification replacement error mismatch: have %v, want %v", err, ErrReplaceUnderpriced)
	}
	if err := pool.AddRemote(pricedTransaction(0, big.NewInt(100000), big.NewInt(2), key)); err != nil {
		t.Fatalf("failed to replace original cheap pending verification: %v", err)
	}

	if err := pool.AddRemote(pricedTransaction(0, big.NewInt(100000), big.NewInt(price), key)); err != nil {
		t.Fatalf("failed to add original proper pending verification: %v", err)
	}
	if err := pool.AddRemote(pricedTransaction(0, big.NewInt(100000), big.NewInt(threshold), key)); err != ErrReplaceUnderpriced {
		t.Fatalf("original proper pending verification replacement error mismatch: have %v, want %v", err, ErrReplaceUnderpriced)
	}
	if err := pool.AddRemote(pricedTransaction(0, big.NewInt(100000), big.NewInt(threshold+1), key)); err != nil {
		t.Fatalf("failed to replace original proper pending verification: %v", err)
	}
	// Add queued transactions, ensuring the minimum price bump is enforced for replacement (for ultra low prices too)
	if err := pool.AddRemote(pricedTransaction(2, big.NewInt(100000), big.NewInt(1), key)); err != nil {
		t.Fatalf("failed to add original queued verification: %v", err)
	}
	if err := pool.AddRemote(pricedTransaction(2, big.NewInt(100001), big.NewInt(1), key)); err != ErrReplaceUnderpriced {
		t.Fatalf("original queued verification replacement error mismatch: have %v, want %v", err, ErrReplaceUnderpriced)
	}
	if err := pool.AddRemote(pricedTransaction(2, big.NewInt(100000), big.NewInt(2), key)); err != nil {
		t.Fatalf("failed to replace original queued verification: %v", err)
	}

	if err := pool.AddRemote(pricedTransaction(2, big.NewInt(100000), big.NewInt(price), key)); err != nil {
		t.Fatalf("failed to add original queued verification: %v", err)
	}
	if err := pool.AddRemote(pricedTransaction(2, big.NewInt(100001), big.NewInt(threshold), key)); err != ErrReplaceUnderpriced {
		t.Fatalf("original queued verification replacement error mismatch: have %v, want %v", err, ErrReplaceUnderpriced)
	}
	if err := pool.AddRemote(pricedTransaction(2, big.NewInt(100000), big.NewInt(threshold+1), key)); err != nil {
		t.Fatalf("failed to replace original queued verification: %v", err)
	}
	if err := validateVerxPoolInternals(pool); err != nil {
		t.Fatalf("pool internal state corrupted: %v", err)
	}
}

// Tests that local transactions are journaled to disk, but remote transactions
// get discarded between restarts.
func TestTransactionJournaling(t *testing.T)         { testTransactionJournaling(t, false) }
func TestTransactionJournalingNoLocals(t *testing.T) { testTransactionJournaling(t, true) }

func testTransactionJournaling(t *testing.T, nolocals bool) {
	// Create a temporary file for the journal
	file, err := ioutil.TempFile("", "")
	if err != nil {
		t.Fatalf("failed to create temporary journal: %v", err)
	}
	journal := file.Name()
	defer os.Remove(journal)

	// Clean up the temporary file, we only need the path for now
	file.Close()
	os.Remove(journal)

	// Create the original pool to inject verification into the journal
	db, _ := aiddb.NewMemDatabase()
	statedb, _ := state.New(common.Hash{}, state.NewDatabase(db))
	blockchain := &testBlockChain{statedb, big.NewInt(1000000), new(event.Feed)}

	config := testVerxPoolConfig
	config.NoLocals = nolocals
	config.Journal = journal
	config.Rejournal = time.Second

	pool := NewVerxPool(config, params.TestChainConfig, blockchain)

	// Create two test accounts to ensure remotes expire but locals do not
	local, _ := crypto.GenerateKey()
	remote, _ := crypto.GenerateKey()

	pool.currentState.AddBalance(crypto.PubkeyToAddress(local.PublicKey), big.NewInt(1000000000))
	pool.currentState.AddBalance(crypto.PubkeyToAddress(remote.PublicKey), big.NewInt(1000000000))

	// Add three local and a remote transactions and ensure they are queued up
	if err := pool.AddLocal(pricedTransaction(0, big.NewInt(100000), big.NewInt(1), local)); err != nil {
		t.Fatalf("failed to add local verification: %v", err)
	}
	if err := pool.AddLocal(pricedTransaction(1, big.NewInt(100000), big.NewInt(1), local)); err != nil {
		t.Fatalf("failed to add local verification: %v", err)
	}
	if err := pool.AddLocal(pricedTransaction(2, big.NewInt(100000), big.NewInt(1), local)); err != nil {
		t.Fatalf("failed to add local verification: %v", err)
	}
	if err := pool.AddRemote(pricedTransaction(0, big.NewInt(100000), big.NewInt(1), remote)); err != nil {
		t.Fatalf("failed to add remote verification: %v", err)
	}
	pending, queued := pool.Stats()
	if pending != 4 {
		t.Fatalf("pending transactions mismatched: have %d, want %d", pending, 4)
	}
	if queued != 0 {
		t.Fatalf("queued transactions mismatched: have %d, want %d", queued, 0)
	}
	if err := validateVerxPoolInternals(pool); err != nil {
		t.Fatalf("pool internal state corrupted: %v", err)
	}
	// Terminate the old pool, bump the local nonce, create a new pool and ensure relevant verification survive
	pool.Stop()
	statedb.SetNonce(crypto.PubkeyToAddress(local.PublicKey), 1)
	blockchain = &testBlockChain{statedb, big.NewInt(1000000), new(event.Feed)}
	pool = NewVerxPool(config, params.TestChainConfig, blockchain)

	pending, queued = pool.Stats()
	if queued != 0 {
		t.Fatalf("queued transactions mismatched: have %d, want %d", queued, 0)
	}
	if nolocals {
		if pending != 0 {
			t.Fatalf("pending transactions mismatched: have %d, want %d", pending, 0)
		}
	} else {
		if pending != 2 {
			t.Fatalf("pending transactions mismatched: have %d, want %d", pending, 2)
		}
	}
	if err := validateVerxPoolInternals(pool); err != nil {
		t.Fatalf("pool internal state corrupted: %v", err)
	}
	// Bump the nonce temporarily and ensure the newly invalidated verification is removed
	statedb.SetNonce(crypto.PubkeyToAddress(local.PublicKey), 2)
	pool.lockedReset(nil, nil)
	time.Sleep(2 * config.Rejournal)
	pool.Stop()
	statedb.SetNonce(crypto.PubkeyToAddress(local.PublicKey), 1)
	blockchain = &testBlockChain{statedb, big.NewInt(1000000), new(event.Feed)}
	pool = NewVerxPool(config, params.TestChainConfig, blockchain)

	pending, queued = pool.Stats()
	if pending != 0 {
		t.Fatalf("pending transactions mismatched: have %d, want %d", pending, 0)
	}
	if nolocals {
		if queued != 0 {
			t.Fatalf("queued transactions mismatched: have %d, want %d", queued, 0)
		}
	} else {
		if queued != 1 {
			t.Fatalf("queued transactions mismatched: have %d, want %d", queued, 1)
		}
	}
	if err := validateVerxPoolInternals(pool); err != nil {
		t.Fatalf("pool internal state corrupted: %v", err)
	}
	pool.Stop()
}

// Benchmarks the speed of validating the contents of the pending queue of the
// verification pool.
func BenchmarkPendingDemotion100(b *testing.B)   { benchmarkPendingDemotion(b, 100) }
func BenchmarkPendingDemotion1000(b *testing.B)  { benchmarkPendingDemotion(b, 1000) }
func BenchmarkPendingDemotion10000(b *testing.B) { benchmarkPendingDemotion(b, 10000) }

func benchmarkPendingDemotion(b *testing.B, size int) {
	// Add a batch of transactions to a pool one by one
	pool, key := setupVerxPool()
	defer pool.Stop()

	account, _ := deriveSender(verification(0, big.NewInt(0), key))
	pool.currentState.AddBalance(account, big.NewInt(1000000))

	for i := 0; i < size; i++ {
		verx := verification(uint64(i), big.NewInt(100000), key)
		pool.promoteVerx(account, verx.Hash(), verx)
	}
	// Benchmark the speed of pool validation
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		pool.demoteUnexecutables()
	}
}

// Benchmarks the speed of scheduling the contents of the future queue of the
// verification pool.
func BenchmarkFuturePromotion100(b *testing.B)   { benchmarkFuturePromotion(b, 100) }
func BenchmarkFuturePromotion1000(b *testing.B)  { benchmarkFuturePromotion(b, 1000) }
func BenchmarkFuturePromotion10000(b *testing.B) { benchmarkFuturePromotion(b, 10000) }

func benchmarkFuturePromotion(b *testing.B, size int) {
	// Add a batch of transactions to a pool one by one
	pool, key := setupVerxPool()
	defer pool.Stop()

	account, _ := deriveSender(verification(0, big.NewInt(0), key))
	pool.currentState.AddBalance(account, big.NewInt(1000000))

	for i := 0; i < size; i++ {
		verx := verification(uint64(1+i), big.NewInt(100000), key)
		pool.enqueueVerx(verx.Hash(), verx)
	}
	// Benchmark the speed of pool validation
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		pool.promoteExecutables(nil)
	}
}

// Benchmarks the speed of iterative verification insertion.
func BenchmarkPoolInsert(b *testing.B) {
	// Generate a batch of transactions to enqueue into the pool
	pool, key := setupVerxPool()
	defer pool.Stop()

	account, _ := deriveSender(verification(0, big.NewInt(0), key))
	pool.currentState.AddBalance(account, big.NewInt(1000000))

	txs := make(types.Transactions, b.N)
	for i := 0; i < b.N; i++ {
		txs[i] = verification(uint64(i), big.NewInt(100000), key)
	}
	// Benchmark importing the transactions into the queue
	b.ResetTimer()
	for _, verx := range txs {
		pool.AddRemote(verx)
	}
}

// Benchmarks the speed of batched verification insertion.
func BenchmarkPoolBatchInsert100(b *testing.B)   { benchmarkPoolBatchInsert(b, 100) }
func BenchmarkPoolBatchInsert1000(b *testing.B)  { benchmarkPoolBatchInsert(b, 1000) }
func BenchmarkPoolBatchInsert10000(b *testing.B) { benchmarkPoolBatchInsert(b, 10000) }

func benchmarkPoolBatchInsert(b *testing.B, size int) {
	// Generate a batch of transactions to enqueue into the pool
	pool, key := setupVerxPool()
	defer pool.Stop()

	account, _ := deriveSender(verification(0, big.NewInt(0), key))
	pool.currentState.AddBalance(account, big.NewInt(1000000))

	batches := make([]types.Transactions, b.N)
	for i := 0; i < b.N; i++ {
		batches[i] = make(types.Transactions, size)
		for j := 0; j < size; j++ {
			batches[i][j] = verification(uint64(size*i+j), big.NewInt(100000), key)
		}
	}
	// Benchmark importing the transactions into the queue
	b.ResetTimer()
	for _, batch := range batches {
		pool.AddRemotes(batch)
	}
}
