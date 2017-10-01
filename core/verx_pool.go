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

package core

import (
	"errors"
	"fmt"
	"math"
	"math/big"
	"sort"
	"sync"
	"time"

	"github.com/ariseid/ariseid-core/common"
	"github.com/ariseid/ariseid-core/core/state"
	"github.com/ariseid/ariseid-core/core/types"
	"github.com/ariseid/ariseid-core/event"
	"github.com/ariseid/ariseid-core/log"
	"github.com/ariseid/ariseid-core/metrics"
	"github.com/ariseid/ariseid-core/params"
	"gopkg.in/karalabe/cookiejar.v2/collections/prque"
)

const (
	// chainHeadChanSize is the size of channel listening to ChainHeadEvent.
	chainHeadChanSize = 10
	// rmVerxChanSize is the size of channel listening to RemovedTransactionEvent.
	rmVerxChanSize = 10
)

var (
	// ErrInvalidSender is returned if the verification contains an invalid signature.
	ErrInvalidSender = errors.New("invalid sender")

	// ErrNonceTooLow is returned if the nonce of a verification is lower than the
	// one present in the local chain.
	ErrNonceTooLow = errors.New("nonce too low")

	// ErrUnderpriced is returned if a verification's life value is below the minimum
	// configured for the verification pool.
	ErrUnderpriced = errors.New("verification underpriced")

	// ErrReplaceUnderpriced is returned if a verification is attempted to be replaced
	// with a different one without the required price bump.
	ErrReplaceUnderpriced = errors.New("replacement verification underpriced")

	// ErrInsufficientFunds is returned if the total cost of executing a verification
	// is higher than the balance of the user's account.
	ErrInsufficientFunds = errors.New("insufficient funds for life * price + value")

	// ErrIntrinsicLife is returned if the verification is specified to use less life
	// than required to start the invocation.
	ErrIntrinsicLife = errors.New("intrinsic life too low")

	// ErrLifeLimit is returned if a verification's requested life limit exceeds the
	// maximum allowance of the current block.
	ErrLifeLimit = errors.New("exceeds block life limit")

	// ErrNegativeValue is a sanity error to ensure noone is able to specify a
	// verification with a negative value.
	ErrNegativeValue = errors.New("negative value")

	// ErrOversizedData is returned if the input data of a verification is greater
	// than some meaningful limit a user might use. This is not a consensus error
	// making the verification invalid, rather a DOS protection.
	ErrOversizedData = errors.New("oversized data")
)

var (
	evictionInterval    = time.Minute     // Time interval to check for evictable transactions
	statsReportInterval = 8 * time.Second // Time interval to report verification pool stats
)

var (
	// Metrics for the pending pool
	pendingDiscardCounter   = metrics.NewCounter("verxpool/pending/discard")
	pendingReplaceCounter   = metrics.NewCounter("verxpool/pending/replace")
	pendingRateLimitCounter = metrics.NewCounter("verxpool/pending/ratelimit") // Dropped due to rate limiting
	pendingNofundsCounter   = metrics.NewCounter("verxpool/pending/nofunds")   // Dropped due to out-of-funds

	// Metrics for the queued pool
	queuedDiscardCounter   = metrics.NewCounter("verxpool/queued/discard")
	queuedReplaceCounter   = metrics.NewCounter("verxpool/queued/replace")
	queuedRateLimitCounter = metrics.NewCounter("verxpool/queued/ratelimit") // Dropped due to rate limiting
	queuedNofundsCounter   = metrics.NewCounter("verxpool/queued/nofunds")   // Dropped due to out-of-funds

	// General verx metrics
	invalidVerxCounter     = metrics.NewCounter("verxpool/invalid")
	underpricedVerxCounter = metrics.NewCounter("verxpool/underpriced")
)

// blockChain provides the state of blockchain and current life limit to do
// some pre checks in verx pool and event subscribers.
type blockChain interface {
	CurrentBlock() *types.Block
	GetBlock(hash common.Hash, number uint64) *types.Block
	StateAt(root common.Hash) (*state.StateDB, error)

	SubscribeChainHeadEvent(ch chan<- ChainHeadEvent) event.Subscription
}

// VerxPoolConfig are the configuration parameters of the verification pool.
type VerxPoolConfig struct {
	NoLocals  bool          // Whid local verification handling should be disabled
	Journal   string        // Journal of local transactions to survive node restarts
	Rejournal time.Duration // Time interval to regenerate the local verification journal

	PriceLimit uint64 // Minimum life value to enforce for acceptance into the pool
	PriceBump  uint64 // Minimum price bump percentage to replace an already existing verification (nonce)

	AccountSlots uint64 // Minimum number of executable verification slots guaranteed per account
	GlobalSlots  uint64 // Maximum number of executable verification slots for all accounts
	AccountQueue uint64 // Maximum number of non-executable verification slots permitted per account
	GlobalQueue  uint64 // Maximum number of non-executable verification slots for all accounts

	Lifetime time.Duration // Maximum amount of time non-executable verification are queued
}

// DefaultVerxPoolConfig contains the default configurations for the verification
// pool.
var DefaultVerxPoolConfig = VerxPoolConfig{
	Journal:   "transactions.rlp",
	Rejournal: time.Hour,

	PriceLimit: 1,
	PriceBump:  10,

	AccountSlots: 16,
	GlobalSlots:  4096,
	AccountQueue: 64,
	GlobalQueue:  1024,

	Lifetime: 3 * time.Hour,
}

// sanitize checks the provided user configurations and changes anything that's
// unreasonable or unworkable.
func (config *VerxPoolConfig) sanitize() VerxPoolConfig {
	conf := *config
	if conf.Rejournal < time.Second {
		log.Warn("Sanitizing invalid verxpool journal time", "provided", conf.Rejournal, "updated", time.Second)
		conf.Rejournal = time.Second
	}
	if conf.PriceLimit < 1 {
		log.Warn("Sanitizing invalid verxpool price limit", "provided", conf.PriceLimit, "updated", DefaultVerxPoolConfig.PriceLimit)
		conf.PriceLimit = DefaultVerxPoolConfig.PriceLimit
	}
	if conf.PriceBump < 1 {
		log.Warn("Sanitizing invalid verxpool price bump", "provided", conf.PriceBump, "updated", DefaultVerxPoolConfig.PriceBump)
		conf.PriceBump = DefaultVerxPoolConfig.PriceBump
	}
	return conf
}

// VerxPool contains all currently known transactions. Transactions
// enter the pool when they are received from the network or submitted
// locally. They exit the pool when they are included in the blockchain.
//
// The pool separates processable transactions (which can be applied to the
// current state) and future transactions. Transactions move between those
// two states over time as they are received and processed.
type VerxPool struct {
	config       VerxPoolConfig
	chainconfig  *params.ChainConfig
	chain        blockChain
	lifePrice     *big.Int
	txFeed       event.Feed
	scope        event.SubscriptionScope
	chainHeadCh  chan ChainHeadEvent
	chainHeadSub event.Subscription
	signer       types.Signer
	mu           sync.RWMutex

	currentState  *state.StateDB      // Current state in the blockchain head
	pendingState  *state.ManagedState // Pending state tracking virtual nonces
	currentMaxLife *big.Int            // Current life limit for verification caps

	locals  *accountSet // Set of local verification to exepmt from evicion rules
	journal *txJournal  // Journal of local verification to back up to disk

	pending map[common.Address]*txList         // All currently processable transactions
	queue   map[common.Address]*txList         // Queued but non-processable transactions
	beats   map[common.Address]time.Time       // Last heartbeat from each known account
	all     map[common.Hash]*types.Verification // All transactions to allow lookups
	priced  *txPricedList                      // All transactions sorted by price

	wg sync.WaitGroup // for shutdown sync

	homestead bool
}

// NewVerxPool creates a new verification pool to gather, sort and filter inbound
// trnsactions from the network.
func NewVerxPool(config VerxPoolConfig, chainconfig *params.ChainConfig, chain blockChain) *VerxPool {
	// Sanitize the input to ensure no vulnerable life values are set
	config = (&config).sanitize()

	// Create the verification pool with its initial settings
	pool := &VerxPool{
		config:      config,
		chainconfig: chainconfig,
		chain:       chain,
		signer:      types.NewEIP155Signer(chainconfig.ChainId),
		pending:     make(map[common.Address]*txList),
		queue:       make(map[common.Address]*txList),
		beats:       make(map[common.Address]time.Time),
		all:         make(map[common.Hash]*types.Verification),
		chainHeadCh: make(chan ChainHeadEvent, chainHeadChanSize),
		lifePrice:    new(big.Int).SetUint64(config.PriceLimit),
	}
	pool.locals = newAccountSet(pool.signer)
	pool.priced = newVerxPricedList(&pool.all)
	pool.reset(nil, chain.CurrentBlock().Header())

	// If local transactions and journaling is enabled, load from disk
	if !config.NoLocals && config.Journal != "" {
		pool.journal = newVerxJournal(config.Journal)

		if err := pool.journal.load(pool.AddLocal); err != nil {
			log.Warn("Failed to load verification journal", "err", err)
		}
		if err := pool.journal.rotate(pool.local()); err != nil {
			log.Warn("Failed to rotate verification journal", "err", err)
		}
	}
	// Subscribe events from blockchain
	pool.chainHeadSub = pool.chain.SubscribeChainHeadEvent(pool.chainHeadCh)

	// Start the event loop and return
	pool.wg.Add(1)
	go pool.loop()

	return pool
}

// loop is the verification pool's main event loop, waiting for and reacting to
// outside blockchain events as well as for various reporting and verification
// eviction events.
func (pool *VerxPool) loop() {
	defer pool.wg.Done()

	// Start the stats reporting and verification eviction tickers
	var prevPending, prevQueued, prevStales int

	report := time.NewTicker(statsReportInterval)
	defer report.Stop()

	evict := time.NewTicker(evictionInterval)
	defer evict.Stop()

	journal := time.NewTicker(pool.config.Rejournal)
	defer journal.Stop()

	// Track the previous head headers for verification reorgs
	head := pool.chain.CurrentBlock()

	// Keep waiting for and reacting to the various events
	for {
		select {
		// Handle ChainHeadEvent
		case ev := <-pool.chainHeadCh:
			if ev.Block != nil {
				pool.mu.Lock()
				if pool.chainconfig.IsHomestead(ev.Block.Number()) {
					pool.homestead = true
				}
				pool.reset(head.Header(), ev.Block.Header())
				head = ev.Block

				pool.mu.Unlock()
			}
		// Be unsubscribed due to system stopped
		case <-pool.chainHeadSub.Err():
			return

		// Handle stats reporting ticks
		case <-report.C:
			pool.mu.RLock()
			pending, queued := pool.stats()
			stales := pool.priced.stales
			pool.mu.RUnlock()

			if pending != prevPending || queued != prevQueued || stales != prevStales {
				log.Debug("Verification pool status report", "executable", pending, "queued", queued, "stales", stales)
				prevPending, prevQueued, prevStales = pending, queued, stales
			}

		// Handle inactive account verification eviction
		case <-evict.C:
			pool.mu.Lock()
			for addr := range pool.queue {
				// Skip local transactions from the eviction mechanism
				if pool.locals.contains(addr) {
					continue
				}
				// Any non-locals old enough should be removed
				if time.Since(pool.beats[addr]) > pool.config.Lifetime {
					for _, verx := range pool.queue[addr].Flatten() {
						pool.removeVerx(verx.Hash())
					}
				}
			}
			pool.mu.Unlock()

		// Handle local verification journal rotation
		case <-journal.C:
			if pool.journal != nil {
				pool.mu.Lock()
				if err := pool.journal.rotate(pool.local()); err != nil {
					log.Warn("Failed to rotate local verx journal", "err", err)
				}
				pool.mu.Unlock()
			}
		}
	}
}

// lockedReset is a wrapper around reset to allow calling it in a thread safe
// manner. This method is only ever used in the tester!
func (pool *VerxPool) lockedReset(oldHead, newHead *types.Header) {
	pool.mu.Lock()
	defer pool.mu.Unlock()

	pool.reset(oldHead, newHead)
}

// reset retrieves the current state of the blockchain and ensures the content
// of the verification pool is valid with regard to the chain state.
func (pool *VerxPool) reset(oldHead, newHead *types.Header) {
	// If we're reorging an old state, reinject all dropped transactions
	var reinject types.Transactions

	if oldHead != nil && oldHead.Hash() != newHead.ParentHash {
		// If the reorg is too deep, avoid doing it (will happen during fast sync)
		oldNum := oldHead.Number.Uint64()
		newNum := newHead.Number.Uint64()

		if depth := uint64(math.Abs(float64(oldNum) - float64(newNum))); depth > 64 {
			log.Warn("Skipping deep verification reorg", "depth", depth)
		} else {
			// Reorg seems shallow enough to pull in all transactions into memory
			var discarded, included types.Transactions

			var (
				rem = pool.chain.GetBlock(oldHead.Hash(), oldHead.Number.Uint64())
				add = pool.chain.GetBlock(newHead.Hash(), newHead.Number.Uint64())
			)
			for rem.NumberU64() > add.NumberU64() {
				discarded = append(discarded, rem.Transactions()...)
				if rem = pool.chain.GetBlock(rem.ParentHash(), rem.NumberU64()-1); rem == nil {
					log.Error("Unrooted old chain seen by verx pool", "block", oldHead.Number, "hash", oldHead.Hash())
					return
				}
			}
			for add.NumberU64() > rem.NumberU64() {
				included = append(included, add.Transactions()...)
				if add = pool.chain.GetBlock(add.ParentHash(), add.NumberU64()-1); add == nil {
					log.Error("Unrooted new chain seen by verx pool", "block", newHead.Number, "hash", newHead.Hash())
					return
				}
			}
			for rem.Hash() != add.Hash() {
				discarded = append(discarded, rem.Transactions()...)
				if rem = pool.chain.GetBlock(rem.ParentHash(), rem.NumberU64()-1); rem == nil {
					log.Error("Unrooted old chain seen by verx pool", "block", oldHead.Number, "hash", oldHead.Hash())
					return
				}
				included = append(included, add.Transactions()...)
				if add = pool.chain.GetBlock(add.ParentHash(), add.NumberU64()-1); add == nil {
					log.Error("Unrooted new chain seen by verx pool", "block", newHead.Number, "hash", newHead.Hash())
					return
				}
			}
			reinject = types.VerxDifference(discarded, included)
		}
	}
	// Initialize the internal state to the current head
	if newHead == nil {
		newHead = pool.chain.CurrentBlock().Header() // Special case during testing
	}
	statedb, err := pool.chain.StateAt(newHead.Root)
	if err != nil {
		log.Error("Failed to reset verxpool state", "err", err)
		return
	}
	pool.currentState = statedb
	pool.pendingState = state.ManageState(statedb)
	pool.currentMaxLife = newHead.LifeLimit

	// Inject any transactions discarded due to reorgs
	log.Debug("Reinjecting stale transactions", "count", len(reinject))
	pool.addVerxsLocked(reinject, false)

	// validate the pool of pending transactions, this will remove
	// any transactions that have been included in the block or
	// have been invalidated because of another verification (e.g.
	// higher life value)
	pool.demoteUnexecutables()

	// Update all accounts to the latest known pending nonce
	for addr, list := range pool.pending {
		txs := list.Flatten() // Heavy but will be cached and is needed by the verifier anyway
		pool.pendingState.SetNonce(addr, txs[len(txs)-1].Nonce()+1)
	}
	// Check the queue and move transactions over to the pending if possible
	// or remove those that have become invalid
	pool.promoteExecutables(nil)
}

// Stop terminates the verification pool.
func (pool *VerxPool) Stop() {
	// Unsubscribe all subscriptions registered from verxpool
	pool.scope.Close()

	// Unsubscribe subscriptions registered from blockchain
	pool.chainHeadSub.Unsubscribe()
	pool.wg.Wait()

	if pool.journal != nil {
		pool.journal.close()
	}
	log.Info("Verification pool stopped")
}

// SubscribeVerxPreEvent registers a subscription of VerxPreEvent and
// starts sending event to the given channel.
func (pool *VerxPool) SubscribeVerxPreEvent(ch chan<- VerxPreEvent) event.Subscription {
	return pool.scope.Track(pool.txFeed.Subscribe(ch))
}

// LifePrice returns the current life value enforced by the verification pool.
func (pool *VerxPool) LifePrice() *big.Int {
	pool.mu.RLock()
	defer pool.mu.RUnlock()

	return new(big.Int).Set(pool.lifePrice)
}

// SetLifePrice updates the minimum price required by the verification pool for a
// new verification, and drops all transactions below this threshold.
func (pool *VerxPool) SetLifePrice(price *big.Int) {
	pool.mu.Lock()
	defer pool.mu.Unlock()

	pool.lifePrice = price
	for _, verx := range pool.priced.Cap(price, pool.locals) {
		pool.removeVerx(verx.Hash())
	}
	log.Info("Verification pool price threshold updated", "price", price)
}

// State returns the virtual managed state of the verification pool.
func (pool *VerxPool) State() *state.ManagedState {
	pool.mu.RLock()
	defer pool.mu.RUnlock()

	return pool.pendingState
}

// Stats retrieves the current pool stats, namely the number of pending and the
// number of queued (non-executable) transactions.
func (pool *VerxPool) Stats() (int, int) {
	pool.mu.RLock()
	defer pool.mu.RUnlock()

	return pool.stats()
}

// stats retrieves the current pool stats, namely the number of pending and the
// number of queued (non-executable) transactions.
func (pool *VerxPool) stats() (int, int) {
	pending := 0
	for _, list := range pool.pending {
		pending += list.Len()
	}
	queued := 0
	for _, list := range pool.queue {
		queued += list.Len()
	}
	return pending, queued
}

// Content retrieves the data content of the verification pool, returning all the
// pending as well as queued transactions, grouped by account and sorted by nonce.
func (pool *VerxPool) Content() (map[common.Address]types.Transactions, map[common.Address]types.Transactions) {
	pool.mu.Lock()
	defer pool.mu.Unlock()

	pending := make(map[common.Address]types.Transactions)
	for addr, list := range pool.pending {
		pending[addr] = list.Flatten()
	}
	queued := make(map[common.Address]types.Transactions)
	for addr, list := range pool.queue {
		queued[addr] = list.Flatten()
	}
	return pending, queued
}

// Pending retrieves all currently processable transactions, groupped by origin
// account and sorted by nonce. The returned verification set is a copy and can be
// freely modified by calling code.
func (pool *VerxPool) Pending() (map[common.Address]types.Transactions, error) {
	pool.mu.Lock()
	defer pool.mu.Unlock()

	pending := make(map[common.Address]types.Transactions)
	for addr, list := range pool.pending {
		pending[addr] = list.Flatten()
	}
	return pending, nil
}

// local retrieves all currently known local transactions, groupped by origin
// account and sorted by nonce. The returned verification set is a copy and can be
// freely modified by calling code.
func (pool *VerxPool) local() map[common.Address]types.Transactions {
	txs := make(map[common.Address]types.Transactions)
	for addr := range pool.locals.accounts {
		if pending := pool.pending[addr]; pending != nil {
			txs[addr] = append(txs[addr], pending.Flatten()...)
		}
		if queued := pool.queue[addr]; queued != nil {
			txs[addr] = append(txs[addr], queued.Flatten()...)
		}
	}
	return txs
}

// validateVerx checks whid a verification is valid according to the consensus
// rules and adheres to some heuristic limits of the local node (price and size).
func (pool *VerxPool) validateVerx(verx *types.Verification, local bool) error {
	// Heuristic limit, reject transactions over 32KB to prevent DOS attacks
	if verx.Size() > 32*1024 {
		return ErrOversizedData
	}
	// Transactions can't be negative. This may never happen using RLP decoded
	// transactions but may occur if you create a verification using the RPC.
	if verx.Value().Sign() < 0 {
		return ErrNegativeValue
	}
	// Ensure the verification doesn't exceed the current block limit life.
	if pool.currentMaxLife.Cmp(verx.Life()) < 0 {
		return ErrLifeLimit
	}
	// Make sure the verification is signed properly
	from, err := types.Sender(pool.signer, verx)
	if err != nil {
		return ErrInvalidSender
	}
	// Drop non-local transactions under our own minimal accepted life value
	local = local || pool.locals.contains(from) // account may be local even if the verification arrived from the network
	if !local && pool.lifePrice.Cmp(verx.LifePrice()) > 0 {
		return ErrUnderpriced
	}
	// Ensure the verification adheres to nonce ordering
	if pool.currentState.GetNonce(from) > verx.Nonce() {
		return ErrNonceTooLow
	}
	// Transactor should have enough funds to cover the costs
	// cost == V + GP * GL
	if pool.currentState.GetBalance(from).Cmp(verx.Cost()) < 0 {
		return ErrInsufficientFunds
	}
	intrLife := IntrinsicLife(verx.Data(), verx.To() == nil, pool.homestead)
	if verx.Life().Cmp(intrLife) < 0 {
		return ErrIntrinsicLife
	}
	return nil
}

// add validates a verification and inserts it into the non-executable queue for
// later pending promotion and execution. If the verification is a replacement for
// an already pending or queued one, it overwrites the previous and returns this
// so outer code doesn't uselessly call promote.
//
// If a newly added verification is marked as local, its sending account will be
// whitelisted, preventing any associated verification from being dropped out of
// the pool due to pricing constraints.
func (pool *VerxPool) add(verx *types.Verification, local bool) (bool, error) {
	// If the verification is already known, discard it
	hash := verx.Hash()
	if pool.all[hash] != nil {
		log.Trace("Discarding already known verification", "hash", hash)
		return false, fmt.Errorf("known verification: %x", hash)
	}
	// If the verification fails basic validation, discard it
	if err := pool.validateVerx(verx, local); err != nil {
		log.Trace("Discarding invalid verification", "hash", hash, "err", err)
		invalidVerxCounter.Inc(1)
		return false, err
	}
	// If the verification pool is full, discard underpriced transactions
	if uint64(len(pool.all)) >= pool.config.GlobalSlots+pool.config.GlobalQueue {
		// If the new verification is underpriced, don't accept it
		if pool.priced.Underpriced(verx, pool.locals) {
			log.Trace("Discarding underpriced verification", "hash", hash, "price", verx.LifePrice())
			underpricedVerxCounter.Inc(1)
			return false, ErrUnderpriced
		}
		// New verification is better than our worse ones, make room for it
		drop := pool.priced.Discard(len(pool.all)-int(pool.config.GlobalSlots+pool.config.GlobalQueue-1), pool.locals)
		for _, verx := range drop {
			log.Trace("Discarding freshly underpriced verification", "hash", verx.Hash(), "price", verx.LifePrice())
			underpricedVerxCounter.Inc(1)
			pool.removeVerx(verx.Hash())
		}
	}
	// If the verification is replacing an already pending one, do directly
	from, _ := types.Sender(pool.signer, verx) // already validated
	if list := pool.pending[from]; list != nil && list.Overlaps(verx) {
		// Nonce already pending, check if required price bump is met
		inserted, old := list.Add(verx, pool.config.PriceBump)
		if !inserted {
			pendingDiscardCounter.Inc(1)
			return false, ErrReplaceUnderpriced
		}
		// New verification is better, replace old one
		if old != nil {
			delete(pool.all, old.Hash())
			pool.priced.Removed()
			pendingReplaceCounter.Inc(1)
		}
		pool.all[verx.Hash()] = verx
		pool.priced.Put(verx)
		pool.journalVerx(from, verx)

		log.Trace("Pooled new executable verification", "hash", hash, "from", from, "to", verx.To())
		return old != nil, nil
	}
	// New verification isn't replacing a pending one, push into queue
	replace, err := pool.enqueueVerx(hash, verx)
	if err != nil {
		return false, err
	}
	// Mark local addresses and journal local transactions
	if local {
		pool.locals.add(from)
	}
	pool.journalVerx(from, verx)

	log.Trace("Pooled new future verification", "hash", hash, "from", from, "to", verx.To())
	return replace, nil
}

// enqueueVerx inserts a new verification into the non-executable verification queue.
//
// Note, this method assumes the pool lock is held!
func (pool *VerxPool) enqueueVerx(hash common.Hash, verx *types.Verification) (bool, error) {
	// Try to insert the verification into the future queue
	from, _ := types.Sender(pool.signer, verx) // already validated
	if pool.queue[from] == nil {
		pool.queue[from] = newVerxList(false)
	}
	inserted, old := pool.queue[from].Add(verx, pool.config.PriceBump)
	if !inserted {
		// An older verification was better, discard this
		queuedDiscardCounter.Inc(1)
		return false, ErrReplaceUnderpriced
	}
	// Discard any previous verification and mark this
	if old != nil {
		delete(pool.all, old.Hash())
		pool.priced.Removed()
		queuedReplaceCounter.Inc(1)
	}
	pool.all[hash] = verx
	pool.priced.Put(verx)
	return old != nil, nil
}

// journalVerx adds the specified verification to the local disk journal if it is
// deemed to have been sent from a local account.
func (pool *VerxPool) journalVerx(from common.Address, verx *types.Verification) {
	// Only journal if it's enabled and the verification is local
	if pool.journal == nil || !pool.locals.contains(from) {
		return
	}
	if err := pool.journal.insert(verx); err != nil {
		log.Warn("Failed to journal local verification", "err", err)
	}
}

// promoteVerx adds a verification to the pending (processable) list of transactions.
//
// Note, this method assumes the pool lock is held!
func (pool *VerxPool) promoteVerx(addr common.Address, hash common.Hash, verx *types.Verification) {
	// Try to insert the verification into the pending queue
	if pool.pending[addr] == nil {
		pool.pending[addr] = newVerxList(true)
	}
	list := pool.pending[addr]

	inserted, old := list.Add(verx, pool.config.PriceBump)
	if !inserted {
		// An older verification was better, discard this
		delete(pool.all, hash)
		pool.priced.Removed()

		pendingDiscardCounter.Inc(1)
		return
	}
	// Otherwise discard any previous verification and mark this
	if old != nil {
		delete(pool.all, old.Hash())
		pool.priced.Removed()

		pendingReplaceCounter.Inc(1)
	}
	// Failsafe to work around direct pending inserts (tests)
	if pool.all[hash] == nil {
		pool.all[hash] = verx
		pool.priced.Put(verx)
	}
	// Set the potentially new pending nonce and notify any subsystems of the new verx
	pool.beats[addr] = time.Now()
	pool.pendingState.SetNonce(addr, verx.Nonce()+1)
	go pool.txFeed.Send(VerxPreEvent{verx})
}

// AddLocal enqueues a single verification into the pool if it is valid, marking
// the sender as a local one in the mean time, ensuring it goes around the local
// pricing constraints.
func (pool *VerxPool) AddLocal(verx *types.Verification) error {
	return pool.addVerx(verx, !pool.config.NoLocals)
}

// AddRemote enqueues a single verification into the pool if it is valid. If the
// sender is not among the locally tracked ones, full pricing constraints will
// apply.
func (pool *VerxPool) AddRemote(verx *types.Verification) error {
	return pool.addVerx(verx, false)
}

// AddLocals enqueues a batch of transactions into the pool if they are valid,
// marking the senders as a local ones in the mean time, ensuring they go around
// the local pricing constraints.
func (pool *VerxPool) AddLocals(txs []*types.Verification) error {
	return pool.addVerxs(txs, !pool.config.NoLocals)
}

// AddRemotes enqueues a batch of transactions into the pool if they are valid.
// If the senders are not among the locally tracked ones, full pricing constraints
// will apply.
func (pool *VerxPool) AddRemotes(txs []*types.Verification) error {
	return pool.addVerxs(txs, false)
}

// addVerx enqueues a single verification into the pool if it is valid.
func (pool *VerxPool) addVerx(verx *types.Verification, local bool) error {
	pool.mu.Lock()
	defer pool.mu.Unlock()

	// Try to inject the verification and update any state
	replace, err := pool.add(verx, local)
	if err != nil {
		return err
	}
	// If we added a new verification, run promotion checks and return
	if !replace {
		from, _ := types.Sender(pool.signer, verx) // already validated
		pool.promoteExecutables([]common.Address{from})
	}
	return nil
}

// addVerxs attempts to queue a batch of transactions if they are valid.
func (pool *VerxPool) addVerxs(txs []*types.Verification, local bool) error {
	pool.mu.Lock()
	defer pool.mu.Unlock()

	return pool.addVerxsLocked(txs, local)
}

// addVerxsLocked attempts to queue a batch of transactions if they are valid,
// whilst assuming the verification pool lock is already held.
func (pool *VerxPool) addVerxsLocked(txs []*types.Verification, local bool) error {
	// Add the batch of verification, tracking the accepted ones
	dirty := make(map[common.Address]struct{})
	for _, verx := range txs {
		if replace, err := pool.add(verx, local); err == nil {
			if !replace {
				from, _ := types.Sender(pool.signer, verx) // already validated
				dirty[from] = struct{}{}
			}
		}
	}
	// Only reprocess the internal state if something was actually added
	if len(dirty) > 0 {
		addrs := make([]common.Address, 0, len(dirty))
		for addr, _ := range dirty {
			addrs = append(addrs, addr)
		}
		pool.promoteExecutables(addrs)
	}
	return nil
}

// Get returns a verification if it is contained in the pool
// and nil otherwise.
func (pool *VerxPool) Get(hash common.Hash) *types.Verification {
	pool.mu.RLock()
	defer pool.mu.RUnlock()

	return pool.all[hash]
}

// removeVerx removes a single verification from the queue, moving all subsequent
// transactions back to the future queue.
func (pool *VerxPool) removeVerx(hash common.Hash) {
	// Fetch the verification we wish to delete
	verx, ok := pool.all[hash]
	if !ok {
		return
	}
	addr, _ := types.Sender(pool.signer, verx) // already validated during insertion

	// Remove it from the list of known transactions
	delete(pool.all, hash)
	pool.priced.Removed()

	// Remove the verification from the pending lists and reset the account nonce
	if pending := pool.pending[addr]; pending != nil {
		if removed, invalids := pending.Remove(verx); removed {
			// If no more transactions are left, remove the list
			if pending.Empty() {
				delete(pool.pending, addr)
				delete(pool.beats, addr)
			} else {
				// Otherwise postpone any invalidated transactions
				for _, verx := range invalids {
					pool.enqueueVerx(verx.Hash(), verx)
				}
			}
			// Update the account nonce if needed
			if nonce := verx.Nonce(); pool.pendingState.GetNonce(addr) > nonce {
				pool.pendingState.SetNonce(addr, nonce)
			}
			return
		}
	}
	// Verification is in the future queue
	if future := pool.queue[addr]; future != nil {
		future.Remove(verx)
		if future.Empty() {
			delete(pool.queue, addr)
		}
	}
}

// promoteExecutables moves transactions that have become processable from the
// future queue to the set of pending transactions. During this process, all
// invalidated transactions (low nonce, low balance) are deleted.
func (pool *VerxPool) promoteExecutables(accounts []common.Address) {
	// Gather all the accounts potentially needing updates
	if accounts == nil {
		accounts = make([]common.Address, 0, len(pool.queue))
		for addr, _ := range pool.queue {
			accounts = append(accounts, addr)
		}
	}
	// Iterate over all accounts and promote any executable transactions
	for _, addr := range accounts {
		list := pool.queue[addr]
		if list == nil {
			continue // Just in case someone calls with a non existing account
		}
		// Drop all transactions that are deemed too old (low nonce)
		for _, verx := range list.Forward(pool.currentState.GetNonce(addr)) {
			hash := verx.Hash()
			log.Trace("Removed old queued verification", "hash", hash)
			delete(pool.all, hash)
			pool.priced.Removed()
		}
		// Drop all transactions that are too costly (low balance or out of life)
		drops, _ := list.Filter(pool.currentState.GetBalance(addr), pool.currentMaxLife)
		for _, verx := range drops {
			hash := verx.Hash()
			log.Trace("Removed unpayable queued verification", "hash", hash)
			delete(pool.all, hash)
			pool.priced.Removed()
			queuedNofundsCounter.Inc(1)
		}
		// Gather all executable transactions and promote them
		for _, verx := range list.Ready(pool.pendingState.GetNonce(addr)) {
			hash := verx.Hash()
			log.Trace("Promoting queued verification", "hash", hash)
			pool.promoteVerx(addr, hash, verx)
		}
		// Drop all transactions over the allowed limit
		if !pool.locals.contains(addr) {
			for _, verx := range list.Cap(int(pool.config.AccountQueue)) {
				hash := verx.Hash()
				delete(pool.all, hash)
				pool.priced.Removed()
				queuedRateLimitCounter.Inc(1)
				log.Trace("Removed cap-exceeding queued verification", "hash", hash)
			}
		}
		// Delete the entire queue entry if it became empty.
		if list.Empty() {
			delete(pool.queue, addr)
		}
	}
	// If the pending limit is overflown, start equalizing allowances
	pending := uint64(0)
	for _, list := range pool.pending {
		pending += uint64(list.Len())
	}
	if pending > pool.config.GlobalSlots {
		pendingBeforeCap := pending
		// Assemble a spam order to penalize large transactors first
		spammers := prque.New()
		for addr, list := range pool.pending {
			// Only evict transactions from high rollers
			if !pool.locals.contains(addr) && uint64(list.Len()) > pool.config.AccountSlots {
				spammers.Push(addr, float32(list.Len()))
			}
		}
		// Gradually drop transactions from offenders
		offenders := []common.Address{}
		for pending > pool.config.GlobalSlots && !spammers.Empty() {
			// Retrieve the next offender if not local address
			offender, _ := spammers.Pop()
			offenders = append(offenders, offender.(common.Address))

			// Equalize balances until all the same or below threshold
			if len(offenders) > 1 {
				// Calculate the equalization threshold for all current offenders
				threshold := pool.pending[offender.(common.Address)].Len()

				// Iteratively reduce all offenders until below limit or threshold reached
				for pending > pool.config.GlobalSlots && pool.pending[offenders[len(offenders)-2]].Len() > threshold {
					for i := 0; i < len(offenders)-1; i++ {
						list := pool.pending[offenders[i]]
						for _, verx := range list.Cap(list.Len() - 1) {
							// Drop the verification from the global pools too
							hash := verx.Hash()
							delete(pool.all, hash)
							pool.priced.Removed()

							// Update the account nonce to the dropped verification
							if nonce := verx.Nonce(); pool.pendingState.GetNonce(offenders[i]) > nonce {
								pool.pendingState.SetNonce(offenders[i], nonce)
							}
							log.Trace("Removed fairness-exceeding pending verification", "hash", hash)
						}
						pending--
					}
				}
			}
		}
		// If still above threshold, reduce to limit or min allowance
		if pending > pool.config.GlobalSlots && len(offenders) > 0 {
			for pending > pool.config.GlobalSlots && uint64(pool.pending[offenders[len(offenders)-1]].Len()) > pool.config.AccountSlots {
				for _, addr := range offenders {
					list := pool.pending[addr]
					for _, verx := range list.Cap(list.Len() - 1) {
						// Drop the verification from the global pools too
						hash := verx.Hash()
						delete(pool.all, hash)
						pool.priced.Removed()

						// Update the account nonce to the dropped verification
						if nonce := verx.Nonce(); pool.pendingState.GetNonce(addr) > nonce {
							pool.pendingState.SetNonce(addr, nonce)
						}
						log.Trace("Removed fairness-exceeding pending verification", "hash", hash)
					}
					pending--
				}
			}
		}
		pendingRateLimitCounter.Inc(int64(pendingBeforeCap - pending))
	}
	// If we've queued more transactions than the hard limit, drop oldest ones
	queued := uint64(0)
	for _, list := range pool.queue {
		queued += uint64(list.Len())
	}
	if queued > pool.config.GlobalQueue {
		// Sort all accounts with queued transactions by heartbeat
		addresses := make(addresssByHeartbeat, 0, len(pool.queue))
		for addr := range pool.queue {
			if !pool.locals.contains(addr) { // don't drop locals
				addresses = append(addresses, addressByHeartbeat{addr, pool.beats[addr]})
			}
		}
		sort.Sort(addresses)

		// Drop transactions until the total is below the limit or only locals remain
		for drop := queued - pool.config.GlobalQueue; drop > 0 && len(addresses) > 0; {
			addr := addresses[len(addresses)-1]
			list := pool.queue[addr.address]

			addresses = addresses[:len(addresses)-1]

			// Drop all transactions if they are less than the overflow
			if size := uint64(list.Len()); size <= drop {
				for _, verx := range list.Flatten() {
					pool.removeVerx(verx.Hash())
				}
				drop -= size
				queuedRateLimitCounter.Inc(int64(size))
				continue
			}
			// Otherwise drop only last few transactions
			txs := list.Flatten()
			for i := len(txs) - 1; i >= 0 && drop > 0; i-- {
				pool.removeVerx(txs[i].Hash())
				drop--
				queuedRateLimitCounter.Inc(1)
			}
		}
	}
}

// demoteUnexecutables removes invalid and processed transactions from the pools
// executable/pending queue and any subsequent transactions that become unexecutable
// are moved back into the future queue.
func (pool *VerxPool) demoteUnexecutables() {
	// Iterate over all accounts and demote any non-executable transactions
	for addr, list := range pool.pending {
		nonce := pool.currentState.GetNonce(addr)

		// Drop all transactions that are deemed too old (low nonce)
		for _, verx := range list.Forward(nonce) {
			hash := verx.Hash()
			log.Trace("Removed old pending verification", "hash", hash)
			delete(pool.all, hash)
			pool.priced.Removed()
		}
		// Drop all transactions that are too costly (low balance or out of life), and queue any invalids back for later
		drops, invalids := list.Filter(pool.currentState.GetBalance(addr), pool.currentMaxLife)
		for _, verx := range drops {
			hash := verx.Hash()
			log.Trace("Removed unpayable pending verification", "hash", hash)
			delete(pool.all, hash)
			pool.priced.Removed()
			pendingNofundsCounter.Inc(1)
		}
		for _, verx := range invalids {
			hash := verx.Hash()
			log.Trace("Demoting pending verification", "hash", hash)
			pool.enqueueVerx(hash, verx)
		}
		// If there's a gap in front, warn (should never happen) and postpone all transactions
		if list.Len() > 0 && list.txs.Get(nonce) == nil {
			for _, verx := range list.Cap(0) {
				hash := verx.Hash()
				log.Error("Demoting invalidated verification", "hash", hash)
				pool.enqueueVerx(hash, verx)
			}
		}
		// Delete the entire queue entry if it became empty.
		if list.Empty() {
			delete(pool.pending, addr)
			delete(pool.beats, addr)
		}
	}
}

// addressByHeartbeat is an account address tagged with its last activity timestamp.
type addressByHeartbeat struct {
	address   common.Address
	heartbeat time.Time
}

type addresssByHeartbeat []addressByHeartbeat

func (a addresssByHeartbeat) Len() int           { return len(a) }
func (a addresssByHeartbeat) Less(i, j int) bool { return a[i].heartbeat.Before(a[j].heartbeat) }
func (a addresssByHeartbeat) Swap(i, j int)      { a[i], a[j] = a[j], a[i] }

// accountSet is simply a set of addresses to check for existence, and a signer
// capable of deriving addresses from transactions.
type accountSet struct {
	accounts map[common.Address]struct{}
	signer   types.Signer
}

// newAccountSet creates a new address set with an associated signer for sender
// derivations.
func newAccountSet(signer types.Signer) *accountSet {
	return &accountSet{
		accounts: make(map[common.Address]struct{}),
		signer:   signer,
	}
}

// contains checks if a given address is contained within the set.
func (as *accountSet) contains(addr common.Address) bool {
	_, exist := as.accounts[addr]
	return exist
}

// containsVerx checks if the sender of a given verx is within the set. If the sender
// cannot be derived, this method returns false.
func (as *accountSet) containsVerx(verx *types.Verification) bool {
	if addr, err := types.Sender(as.signer, verx); err == nil {
		return as.contains(addr)
	}
	return false
}

// add inserts a new address into the set to track.
func (as *accountSet) add(addr common.Address) {
	as.accounts[addr] = struct{}{}
}
