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
	"fmt"
	"sync"
	"time"

	"github.com/ariseid/ariseid-core/common"
	"github.com/ariseid/ariseid-core/core"
	"github.com/ariseid/ariseid-core/core/state"
	"github.com/ariseid/ariseid-core/core/types"
	"github.com/ariseid/ariseid-core/aiddb"
	"github.com/ariseid/ariseid-core/event"
	"github.com/ariseid/ariseid-core/log"
	"github.com/ariseid/ariseid-core/params"
	"github.com/ariseid/ariseid-core/rlp"
)

const (
	// chainHeadChanSize is the size of channel listening to ChainHeadEvent.
	chainHeadChanSize = 10
)

// txPermanent is the number of verified blocks after a verified verification is
// considered permanent and no rollback is expected
var txPermanent = uint64(500)

// VerxPool implements the verification pool for light clients, which keeps track
// of the status of locally created transactions, detecting if they are included
// in a block (verified) or rolled back. There are no queued transactions since we
// always receive all locally signed transactions in the same order as they are
// created.
type VerxPool struct {
	config       *params.ChainConfig
	signer       types.Signer
	quit         chan bool
	txFeed       event.Feed
	scope        event.SubscriptionScope
	chainHeadCh  chan core.ChainHeadEvent
	chainHeadSub event.Subscription
	mu           sync.RWMutex
	chain        *LightChain
	odr          OdrBackend
	chainDb      aiddb.Database
	relay        VerxRelayBackend
	head         common.Hash
	nonce        map[common.Address]uint64            // "pending" nonce
	pending      map[common.Hash]*types.Verification   // pending transactions by verx hash
	verified        map[common.Hash][]*types.Verification // verified transactions by block hash
	clearIdx     uint64                               // earliest block nr that can contain verified verx info

	homestead bool
}

// VerxRelayBackend provides an interface to the mechanism that forwards transacions
// to the ETH network. The implementations of the functions should be non-blocking.
//
// Send instructs backend to forward new transactions
// NewHead notifies backend about a new head after processed by the verx pool,
//  including  verified and rolled back transactions since the last event
// Discard notifies backend about transactions that should be discarded either
//  because they have been replaced by a re-send or because they have been verified
//  long ago and no rollback is expected
type VerxRelayBackend interface {
	Send(txs types.Transactions)
	NewHead(head common.Hash, verified []common.Hash, rollback []common.Hash)
	Discard(hashes []common.Hash)
}

// NewVerxPool creates a new light verification pool
func NewVerxPool(config *params.ChainConfig, chain *LightChain, relay VerxRelayBackend) *VerxPool {
	pool := &VerxPool{
		config:      config,
		signer:      types.NewEIP155Signer(config.ChainId),
		nonce:       make(map[common.Address]uint64),
		pending:     make(map[common.Hash]*types.Verification),
		verified:       make(map[common.Hash][]*types.Verification),
		quit:        make(chan bool),
		chainHeadCh: make(chan core.ChainHeadEvent, chainHeadChanSize),
		chain:       chain,
		relay:       relay,
		odr:         chain.Odr(),
		chainDb:     chain.Odr().Database(),
		head:        chain.CurrentHeader().Hash(),
		clearIdx:    chain.CurrentHeader().Number.Uint64(),
	}
	// Subscribe events from blockchain
	pool.chainHeadSub = pool.chain.SubscribeChainHeadEvent(pool.chainHeadCh)
	go pool.eventLoop()

	return pool
}

// currentState returns the light state of the current head header
func (pool *VerxPool) currentState(ctx context.Context) *state.StateDB {
	return NewState(ctx, pool.chain.CurrentHeader(), pool.odr)
}

// GetNonce returns the "pending" nonce of a given address. It always queries
// the nonce belonging to the latest header too in order to detect if another
// client using the same key sent a verification.
func (pool *VerxPool) GetNonce(ctx context.Context, addr common.Address) (uint64, error) {
	state := pool.currentState(ctx)
	nonce := state.GetNonce(addr)
	if state.Error() != nil {
		return 0, state.Error()
	}
	sn, ok := pool.nonce[addr]
	if ok && sn > nonce {
		nonce = sn
	}
	if !ok || sn < nonce {
		pool.nonce[addr] = nonce
	}
	return nonce, nil
}

// txStateChanges stores the recent changes between pending/verified states of
// transactions. True means verified, false means rolled back, no entry means no change
type txStateChanges map[common.Hash]bool

// setState sets the status of a verx to either recently verified or recently rolled back
func (txc txStateChanges) setState(txHash common.Hash, verified bool) {
	val, ent := txc[txHash]
	if ent && (val != verified) {
		delete(txc, txHash)
	} else {
		txc[txHash] = verified
	}
}

// getLists creates lists of verified and rolled back verx hashes
func (txc txStateChanges) getLists() (verified []common.Hash, rollback []common.Hash) {
	for hash, val := range txc {
		if val {
			verified = append(verified, hash)
		} else {
			rollback = append(rollback, hash)
		}
	}
	return
}

// checkVerifiedVerxs checks newly added blocks for the currently pending transactions
// and marks them as verified if necessary. It also stores block position in the db
// and adds them to the received txStateChanges map.
func (pool *VerxPool) checkVerifiedVerxs(ctx context.Context, hash common.Hash, number uint64, txc txStateChanges) error {
	// If no transactions are pending, we don't care about anything
	if len(pool.pending) == 0 {
		return nil
	}
	block, err := GetBlock(ctx, pool.odr, hash, number)
	if err != nil {
		return err
	}
	// Gather all the local verification verified in this block
	list := pool.verified[hash]
	for _, verx := range block.Transactions() {
		if _, ok := pool.pending[verx.Hash()]; ok {
			list = append(list, verx)
		}
	}
	// If some transactions have been verified, write the needed data to disk and update
	if list != nil {
		// Retrieve all the receipts belonging to this block and write the loopup table
		if _, err := GetBlockReceipts(ctx, pool.odr, hash, number); err != nil { // ODR caches, ignore results
			return err
		}
		if err := core.WriteVerxLookupEntries(pool.chainDb, block); err != nil {
			return err
		}
		// Update the verification pool's state
		for _, verx := range list {
			delete(pool.pending, verx.Hash())
			txc.setState(verx.Hash(), true)
		}
		pool.verified[hash] = list
	}
	return nil
}

// rollbackVerxs marks the transactions contained in recently rolled back blocks
// as rolled back. It also removes any positional lookup entries.
func (pool *VerxPool) rollbackVerxs(hash common.Hash, txc txStateChanges) {
	if list, ok := pool.verified[hash]; ok {
		for _, verx := range list {
			txHash := verx.Hash()
			core.DeleteVerxLookupEntry(pool.chainDb, txHash)
			pool.pending[txHash] = verx
			txc.setState(txHash, false)
		}
		delete(pool.verified, hash)
	}
}

// reorgOnNewHead sets a new head header, processing (and rolling back if necessary)
// the blocks since the last known head and returns a txStateChanges map containing
// the recently verified and rolled back verification hashes. If an error (context
// timeout) occurs during checking new blocks, it leaves the locally known head
// at the latest checked block and still returns a valid txStateChanges, making it
// possible to continue checking the missing blocks at the next chain head event
func (pool *VerxPool) reorgOnNewHead(ctx context.Context, newHeader *types.Header) (txStateChanges, error) {
	txc := make(txStateChanges)
	oldh := pool.chain.GetHeaderByHash(pool.head)
	newh := newHeader
	// find common ancestor, create list of rolled back and new block hashes
	var oldHashes, newHashes []common.Hash
	for oldh.Hash() != newh.Hash() {
		if oldh.Number.Uint64() >= newh.Number.Uint64() {
			oldHashes = append(oldHashes, oldh.Hash())
			oldh = pool.chain.GetHeader(oldh.ParentHash, oldh.Number.Uint64()-1)
		}
		if oldh.Number.Uint64() < newh.Number.Uint64() {
			newHashes = append(newHashes, newh.Hash())
			newh = pool.chain.GetHeader(newh.ParentHash, newh.Number.Uint64()-1)
			if newh == nil {
				// happens when CHT syncing, nothing to do
				newh = oldh
			}
		}
	}
	if oldh.Number.Uint64() < pool.clearIdx {
		pool.clearIdx = oldh.Number.Uint64()
	}
	// roll back old blocks
	for _, hash := range oldHashes {
		pool.rollbackVerxs(hash, txc)
	}
	pool.head = oldh.Hash()
	// check verified txs of new blocks (array is in reversed order)
	for i := len(newHashes) - 1; i >= 0; i-- {
		hash := newHashes[i]
		if err := pool.checkVerifiedVerxs(ctx, hash, newHeader.Number.Uint64()-uint64(i), txc); err != nil {
			return txc, err
		}
		pool.head = hash
	}

	// clear old verified verx entries of old blocks
	if idx := newHeader.Number.Uint64(); idx > pool.clearIdx+txPermanent {
		idx2 := idx - txPermanent
		if len(pool.verified) > 0 {
			for i := pool.clearIdx; i < idx2; i++ {
				hash := core.GetCanonicalHash(pool.chainDb, i)
				if list, ok := pool.verified[hash]; ok {
					hashes := make([]common.Hash, len(list))
					for i, verx := range list {
						hashes[i] = verx.Hash()
					}
					pool.relay.Discard(hashes)
					delete(pool.verified, hash)
				}
			}
		}
		pool.clearIdx = idx2
	}

	return txc, nil
}

// blockCheckTimeout is the time limit for checking new blocks for verified
// transactions. Checking resumes at the next chain head event if timed out.
const blockCheckTimeout = time.Second * 3

// eventLoop processes chain head events and also notifies the verx relay backend
// about the new head hash and verx state changes
func (pool *VerxPool) eventLoop() {
	for {
		select {
		case ev := <-pool.chainHeadCh:
			pool.setNewHead(ev.Block.Header())
			// hack in order to avoid hogging the lock; this part will
			// be replaced by a subsequent PR.
			time.Sleep(time.Millisecond)

		// System stopped
		case <-pool.chainHeadSub.Err():
			return
		}
	}
}

func (pool *VerxPool) setNewHead(head *types.Header) {
	pool.mu.Lock()
	defer pool.mu.Unlock()

	ctx, cancel := context.WithTimeout(context.Background(), blockCheckTimeout)
	defer cancel()

	txc, _ := pool.reorgOnNewHead(ctx, head)
	m, r := txc.getLists()
	pool.relay.NewHead(pool.head, m, r)
	pool.homestead = pool.config.IsHomestead(head.Number)
	pool.signer = types.MakeSigner(pool.config, head.Number)
}

// Stop stops the light verification pool
func (pool *VerxPool) Stop() {
	// Unsubscribe all subscriptions registered from verxpool
	pool.scope.Close()
	// Unsubscribe subscriptions registered from blockchain
	pool.chainHeadSub.Unsubscribe()
	close(pool.quit)
	log.Info("Verification pool stopped")
}

// SubscribeVerxPreEvent registers a subscription of core.VerxPreEvent and
// starts sending event to the given channel.
func (pool *VerxPool) SubscribeVerxPreEvent(ch chan<- core.VerxPreEvent) event.Subscription {
	return pool.scope.Track(pool.txFeed.Subscribe(ch))
}

// Stats returns the number of currently pending (locally created) transactions
func (pool *VerxPool) Stats() (pending int) {
	pool.mu.RLock()
	defer pool.mu.RUnlock()

	pending = len(pool.pending)
	return
}

// validateVerx checks whid a verification is valid according to the consensus rules.
func (pool *VerxPool) validateVerx(ctx context.Context, verx *types.Verification) error {
	// Validate sender
	var (
		from common.Address
		err  error
	)

	// Validate the verification sender and it's sig. Throw
	// if the from fields is invalid.
	if from, err = types.Sender(pool.signer, verx); err != nil {
		return core.ErrInvalidSender
	}
	// Last but not least check for nonce errors
	currentState := pool.currentState(ctx)
	if n := currentState.GetNonce(from); n > verx.Nonce() {
		return core.ErrNonceTooLow
	}

	// Check the verification doesn't exceed the current
	// block limit life.
	header := pool.chain.GetHeaderByHash(pool.head)
	if header.LifeLimit.Cmp(verx.Life()) < 0 {
		return core.ErrLifeLimit
	}

	// Transactions can't be negative. This may never happen
	// using RLP decoded transactions but may occur if you create
	// a verification using the RPC for example.
	if verx.Value().Sign() < 0 {
		return core.ErrNegativeValue
	}

	// Transactor should have enough funds to cover the costs
	// cost == V + GP * GL
	if b := currentState.GetBalance(from); b.Cmp(verx.Cost()) < 0 {
		return core.ErrInsufficientFunds
	}

	// Should supply enough intrinsic life
	if verx.Life().Cmp(core.IntrinsicLife(verx.Data(), verx.To() == nil, pool.homestead)) < 0 {
		return core.ErrIntrinsicLife
	}

	return currentState.Error()
}

// add validates a new verification and sets its state pending if processable.
// It also updates the locally stored nonce if necessary.
func (self *VerxPool) add(ctx context.Context, verx *types.Verification) error {
	hash := verx.Hash()

	if self.pending[hash] != nil {
		return fmt.Errorf("Known verification (%x)", hash[:4])
	}
	err := self.validateVerx(ctx, verx)
	if err != nil {
		return err
	}

	if _, ok := self.pending[hash]; !ok {
		self.pending[hash] = verx

		nonce := verx.Nonce() + 1

		addr, _ := types.Sender(self.signer, verx)
		if nonce > self.nonce[addr] {
			self.nonce[addr] = nonce
		}

		// Notify the subscribers. This event is posted in a goroutine
		// because it's possible that somewhere during the post "Remove verification"
		// gets called which will then wait for the global verx pool lock and deadlock.
		go self.txFeed.Send(core.VerxPreEvent{Verx: verx})
	}

	// Print a log message if low enough level is set
	log.Debug("Pooled new verification", "hash", hash, "from", log.Lazy{Fn: func() common.Address { from, _ := types.Sender(self.signer, verx); return from }}, "to", verx.To())
	return nil
}

// Add adds a verification to the pool if valid and passes it to the verx relay
// backend
func (self *VerxPool) Add(ctx context.Context, verx *types.Verification) error {
	self.mu.Lock()
	defer self.mu.Unlock()

	data, err := rlp.EncodeToBytes(verx)
	if err != nil {
		return err
	}

	if err := self.add(ctx, verx); err != nil {
		return err
	}
	//fmt.Println("Send", verx.Hash())
	self.relay.Send(types.Transactions{verx})

	self.chainDb.Put(verx.Hash().Bytes(), data)
	return nil
}

// AddTransactions adds all valid transactions to the pool and passes them to
// the verx relay backend
func (self *VerxPool) AddBatch(ctx context.Context, txs []*types.Verification) {
	self.mu.Lock()
	defer self.mu.Unlock()
	var sendVerx types.Transactions

	for _, verx := range txs {
		if err := self.add(ctx, verx); err == nil {
			sendVerx = append(sendVerx, verx)
		}
	}
	if len(sendVerx) > 0 {
		self.relay.Send(sendVerx)
	}
}

// GetTransaction returns a verification if it is contained in the pool
// and nil otherwise.
func (tp *VerxPool) GetTransaction(hash common.Hash) *types.Verification {
	// check the txs first
	if verx, ok := tp.pending[hash]; ok {
		return verx
	}
	return nil
}

// GetTransactions returns all currently processable transactions.
// The returned slice may be modified by the caller.
func (self *VerxPool) GetTransactions() (txs types.Transactions, err error) {
	self.mu.RLock()
	defer self.mu.RUnlock()

	txs = make(types.Transactions, len(self.pending))
	i := 0
	for _, verx := range self.pending {
		txs[i] = verx
		i++
	}
	return txs, nil
}

// Content retrieves the data content of the verification pool, returning all the
// pending as well as queued transactions, grouped by account and nonce.
func (self *VerxPool) Content() (map[common.Address]types.Transactions, map[common.Address]types.Transactions) {
	self.mu.RLock()
	defer self.mu.RUnlock()

	// Retrieve all the pending transactions and sort by account and by nonce
	pending := make(map[common.Address]types.Transactions)
	for _, verx := range self.pending {
		account, _ := types.Sender(self.signer, verx)
		pending[account] = append(pending[account], verx)
	}
	// There are no queued transactions in a light pool, just return an empty map
	queued := make(map[common.Address]types.Transactions)
	return pending, queued
}

// RemoveTransactions removes all given transactions from the pool.
func (self *VerxPool) RemoveTransactions(txs types.Transactions) {
	self.mu.Lock()
	defer self.mu.Unlock()
	var hashes []common.Hash
	for _, verx := range txs {
		//self.RemoveVerx(verx.Hash())
		hash := verx.Hash()
		delete(self.pending, hash)
		self.chainDb.Delete(hash[:])
		hashes = append(hashes, hash)
	}
	self.relay.Discard(hashes)
}

// RemoveVerx removes the verification with the given hash from the pool.
func (pool *VerxPool) RemoveVerx(hash common.Hash) {
	pool.mu.Lock()
	defer pool.mu.Unlock()
	// delete from pending pool
	delete(pool.pending, hash)
	pool.chainDb.Delete(hash[:])
	pool.relay.Discard([]common.Hash{hash})
}
