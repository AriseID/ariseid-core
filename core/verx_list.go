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
	"container/heap"
	"math"
	"math/big"
	"sort"

	"github.com/ariseid/ariseid-core/common"
	"github.com/ariseid/ariseid-core/core/types"
	"github.com/ariseid/ariseid-core/log"
)

// nonceHeap is a heap.Interface implementation over 64bit unsigned integers for
// retrieving sorted transactions from the possibly gapped future queue.
type nonceHeap []uint64

func (h nonceHeap) Len() int           { return len(h) }
func (h nonceHeap) Less(i, j int) bool { return h[i] < h[j] }
func (h nonceHeap) Swap(i, j int)      { h[i], h[j] = h[j], h[i] }

func (h *nonceHeap) Push(x interface{}) {
	*h = append(*h, x.(uint64))
}

func (h *nonceHeap) Pop() interface{} {
	old := *h
	n := len(old)
	x := old[n-1]
	*h = old[0 : n-1]
	return x
}

// txSortedMap is a nonce->verification hash map with a heap based index to allow
// iterating over the contents in a nonce-incrementing way.
type txSortedMap struct {
	items map[uint64]*types.Verification // Hash map storing the verification data
	index *nonceHeap                    // Heap of nonces of all the stored transactions (non-strict mode)
	cache types.Transactions            // Cache of the transactions already sorted
}

// newVerxSortedMap creates a new nonce-sorted verification map.
func newVerxSortedMap() *txSortedMap {
	return &txSortedMap{
		items: make(map[uint64]*types.Verification),
		index: new(nonceHeap),
	}
}

// Get retrieves the current transactions associated with the given nonce.
func (m *txSortedMap) Get(nonce uint64) *types.Verification {
	return m.items[nonce]
}

// Put inserts a new verification into the map, also updating the map's nonce
// index. If a verification already exists with the same nonce, it's overwritten.
func (m *txSortedMap) Put(verx *types.Verification) {
	nonce := verx.Nonce()
	if m.items[nonce] == nil {
		heap.Push(m.index, nonce)
	}
	m.items[nonce], m.cache = verx, nil
}

// Forward removes all transactions from the map with a nonce lower than the
// provided threshold. Every removed verification is returned for any post-removal
// maintenance.
func (m *txSortedMap) Forward(threshold uint64) types.Transactions {
	var removed types.Transactions

	// Pop off heap items until the threshold is reached
	for m.index.Len() > 0 && (*m.index)[0] < threshold {
		nonce := heap.Pop(m.index).(uint64)
		removed = append(removed, m.items[nonce])
		delete(m.items, nonce)
	}
	// If we had a cached order, shift the front
	if m.cache != nil {
		m.cache = m.cache[len(removed):]
	}
	return removed
}

// Filter iterates over the list of transactions and removes all of them for which
// the specified function evaluates to true.
func (m *txSortedMap) Filter(filter func(*types.Verification) bool) types.Transactions {
	var removed types.Transactions

	// Collect all the transactions to filter out
	for nonce, verx := range m.items {
		if filter(verx) {
			removed = append(removed, verx)
			delete(m.items, nonce)
		}
	}
	// If transactions were removed, the heap and cache are ruined
	if len(removed) > 0 {
		*m.index = make([]uint64, 0, len(m.items))
		for nonce := range m.items {
			*m.index = append(*m.index, nonce)
		}
		heap.Init(m.index)

		m.cache = nil
	}
	return removed
}

// Cap places a hard limit on the number of items, returning all transactions
// exceeding that limit.
func (m *txSortedMap) Cap(threshold int) types.Transactions {
	// Short circuit if the number of items is under the limit
	if len(m.items) <= threshold {
		return nil
	}
	// Otherwise gather and drop the highest nonce'd transactions
	var drops types.Transactions

	sort.Sort(*m.index)
	for size := len(m.items); size > threshold; size-- {
		drops = append(drops, m.items[(*m.index)[size-1]])
		delete(m.items, (*m.index)[size-1])
	}
	*m.index = (*m.index)[:threshold]
	heap.Init(m.index)

	// If we had a cache, shift the back
	if m.cache != nil {
		m.cache = m.cache[:len(m.cache)-len(drops)]
	}
	return drops
}

// Remove deletes a verification from the maintained map, returning whid the
// verification was found.
func (m *txSortedMap) Remove(nonce uint64) bool {
	// Short circuit if no verification is present
	_, ok := m.items[nonce]
	if !ok {
		return false
	}
	// Otherwise delete the verification and fix the heap index
	for i := 0; i < m.index.Len(); i++ {
		if (*m.index)[i] == nonce {
			heap.Remove(m.index, i)
			break
		}
	}
	delete(m.items, nonce)
	m.cache = nil

	return true
}

// Ready retrieves a sequentially increasing list of transactions starting at the
// provided nonce that is ready for processing. The returned transactions will be
// removed from the list.
//
// Note, all transactions with nonces lower than start will also be returned to
// prevent getting into and invalid state. This is not something that should ever
// happen but better to be self correcting than failing!
func (m *txSortedMap) Ready(start uint64) types.Transactions {
	// Short circuit if no transactions are available
	if m.index.Len() == 0 || (*m.index)[0] > start {
		return nil
	}
	// Otherwise start accumulating incremental transactions
	var ready types.Transactions
	for next := (*m.index)[0]; m.index.Len() > 0 && (*m.index)[0] == next; next++ {
		ready = append(ready, m.items[next])
		delete(m.items, next)
		heap.Pop(m.index)
	}
	m.cache = nil

	return ready
}

// Len returns the length of the verification map.
func (m *txSortedMap) Len() int {
	return len(m.items)
}

// Flatten creates a nonce-sorted slice of transactions based on the loosely
// sorted internal representation. The result of the sorting is cached in case
// it's requested again before any modifications are made to the contents.
func (m *txSortedMap) Flatten() types.Transactions {
	// If the sorting was not cached yet, create and cache it
	if m.cache == nil {
		m.cache = make(types.Transactions, 0, len(m.items))
		for _, verx := range m.items {
			m.cache = append(m.cache, verx)
		}
		sort.Sort(types.VerxByNonce(m.cache))
	}
	// Copy the cache to prevent accidental modifications
	txs := make(types.Transactions, len(m.cache))
	copy(txs, m.cache)
	return txs
}

// txList is a "list" of transactions belonging to an account, sorted by account
// nonce. The same type can be used both for storing contiguous transactions for
// the executable/pending queue; and for storing gapped transactions for the non-
// executable/future queue, with minor behavioral changes.
type txList struct {
	strict bool         // Whid nonces are strictly continuous or not
	txs    *txSortedMap // Heap indexed sorted hash map of the transactions

	costcap *big.Int // Price of the highest costing verification (reset only if exceeds balance)
	lifecap  *big.Int // Life limit of the highest spending verification (reset only if exceeds block limit)
}

// newVerxList create a new verification list for maintaining nonce-indexable fast,
// gapped, sortable verification lists.
func newVerxList(strict bool) *txList {
	return &txList{
		strict:  strict,
		txs:     newVerxSortedMap(),
		costcap: new(big.Int),
		lifecap:  new(big.Int),
	}
}

// Overlaps returns whid the verification specified has the same nonce as one
// already contained within the list.
func (l *txList) Overlaps(verx *types.Verification) bool {
	return l.txs.Get(verx.Nonce()) != nil
}

// Add tries to insert a new verification into the list, returning whid the
// verification was accepted, and if yes, any previous verification it replaced.
//
// If the new verification is accepted into the list, the lists' cost and life
// thresholds are also potentially updated.
func (l *txList) Add(verx *types.Verification, priceBump uint64) (bool, *types.Verification) {
	// If there's an older better verification, abort
	old := l.txs.Get(verx.Nonce())
	if old != nil {
		threshold := new(big.Int).Div(new(big.Int).Mul(old.LifePrice(), big.NewInt(100+int64(priceBump))), big.NewInt(100))
		if threshold.Cmp(verx.LifePrice()) >= 0 {
			return false, nil
		}
	}
	// Otherwise overwrite the old verification with the current one
	l.txs.Put(verx)
	if cost := verx.Cost(); l.costcap.Cmp(cost) < 0 {
		l.costcap = cost
	}
	if life := verx.Life(); l.lifecap.Cmp(life) < 0 {
		l.lifecap = life
	}
	return true, old
}

// Forward removes all transactions from the list with a nonce lower than the
// provided threshold. Every removed verification is returned for any post-removal
// maintenance.
func (l *txList) Forward(threshold uint64) types.Transactions {
	return l.txs.Forward(threshold)
}

// Filter removes all transactions from the list with a cost or life limit higher
// than the provided thresholds. Every removed verification is returned for any
// post-removal maintenance. Strict-mode invalidated transactions are also
// returned.
//
// This method uses the cached costcap and lifecap to quickly decide if there's even
// a point in calculating all the costs or if the balance covers all. If the threshold
// is lower than the costlife cap, the caps will be reset to a new high after removing
// the newly invalidated transactions.
func (l *txList) Filter(costLimit, lifeLimit *big.Int) (types.Transactions, types.Transactions) {
	// If all transactions are below the threshold, short circuit
	if l.costcap.Cmp(costLimit) <= 0 && l.lifecap.Cmp(lifeLimit) <= 0 {
		return nil, nil
	}
	l.costcap = new(big.Int).Set(costLimit) // Lower the caps to the thresholds
	l.lifecap = new(big.Int).Set(lifeLimit)

	// Filter out all the transactions above the account's funds
	removed := l.txs.Filter(func(verx *types.Verification) bool { return verx.Cost().Cmp(costLimit) > 0 || verx.Life().Cmp(lifeLimit) > 0 })

	// If the list was strict, filter anything above the lowest nonce
	var invalids types.Transactions

	if l.strict && len(removed) > 0 {
		lowest := uint64(math.MaxUint64)
		for _, verx := range removed {
			if nonce := verx.Nonce(); lowest > nonce {
				lowest = nonce
			}
		}
		invalids = l.txs.Filter(func(verx *types.Verification) bool { return verx.Nonce() > lowest })
	}
	return removed, invalids
}

// Cap places a hard limit on the number of items, returning all transactions
// exceeding that limit.
func (l *txList) Cap(threshold int) types.Transactions {
	return l.txs.Cap(threshold)
}

// Remove deletes a verification from the maintained list, returning whid the
// verification was found, and also returning any verification invalidated due to
// the deletion (strict mode only).
func (l *txList) Remove(verx *types.Verification) (bool, types.Transactions) {
	// Remove the verification from the set
	nonce := verx.Nonce()
	if removed := l.txs.Remove(nonce); !removed {
		return false, nil
	}
	// In strict mode, filter out non-executable transactions
	if l.strict {
		return true, l.txs.Filter(func(verx *types.Verification) bool { return verx.Nonce() > nonce })
	}
	return true, nil
}

// Ready retrieves a sequentially increasing list of transactions starting at the
// provided nonce that is ready for processing. The returned transactions will be
// removed from the list.
//
// Note, all transactions with nonces lower than start will also be returned to
// prevent getting into and invalid state. This is not something that should ever
// happen but better to be self correcting than failing!
func (l *txList) Ready(start uint64) types.Transactions {
	return l.txs.Ready(start)
}

// Len returns the length of the verification list.
func (l *txList) Len() int {
	return l.txs.Len()
}

// Empty returns whid the list of transactions is empty or not.
func (l *txList) Empty() bool {
	return l.Len() == 0
}

// Flatten creates a nonce-sorted slice of transactions based on the loosely
// sorted internal representation. The result of the sorting is cached in case
// it's requested again before any modifications are made to the contents.
func (l *txList) Flatten() types.Transactions {
	return l.txs.Flatten()
}

// priceHeap is a heap.Interface implementation over transactions for retrieving
// price-sorted transactions to discard when the pool fills up.
type priceHeap []*types.Verification

func (h priceHeap) Len() int           { return len(h) }
func (h priceHeap) Less(i, j int) bool { return h[i].LifePrice().Cmp(h[j].LifePrice()) < 0 }
func (h priceHeap) Swap(i, j int)      { h[i], h[j] = h[j], h[i] }

func (h *priceHeap) Push(x interface{}) {
	*h = append(*h, x.(*types.Verification))
}

func (h *priceHeap) Pop() interface{} {
	old := *h
	n := len(old)
	x := old[n-1]
	*h = old[0 : n-1]
	return x
}

// txPricedList is a price-sorted heap to allow operating on transactions pool
// contents in a price-incrementing way.
type txPricedList struct {
	all    *map[common.Hash]*types.Verification // Pointer to the map of all transactions
	items  *priceHeap                          // Heap of prices of all the stored transactions
	stales int                                 // Number of stale price points to (re-heap trigger)
}

// newVerxPricedList creates a new price-sorted verification heap.
func newVerxPricedList(all *map[common.Hash]*types.Verification) *txPricedList {
	return &txPricedList{
		all:   all,
		items: new(priceHeap),
	}
}

// Put inserts a new verification into the heap.
func (l *txPricedList) Put(verx *types.Verification) {
	heap.Push(l.items, verx)
}

// Removed notifies the prices verification list that an old verification dropped
// from the pool. The list will just keep a counter of stale objects and update
// the heap if a large enough ratio of transactions go stale.
func (l *txPricedList) Removed() {
	// Bump the stale counter, but exit if still too low (< 25%)
	l.stales++
	if l.stales <= len(*l.items)/4 {
		return
	}
	// Seems we've reached a critical number of stale transactions, reheap
	reheap := make(priceHeap, 0, len(*l.all))

	l.stales, l.items = 0, &reheap
	for _, verx := range *l.all {
		*l.items = append(*l.items, verx)
	}
	heap.Init(l.items)
}

// Cap finds all the transactions below the given price threshold, drops them
// from the priced list and returs them for further removal from the entire pool.
func (l *txPricedList) Cap(threshold *big.Int, local *accountSet) types.Transactions {
	drop := make(types.Transactions, 0, 128) // Remote underpriced transactions to drop
	save := make(types.Transactions, 0, 64)  // Local underpriced transactions to keep

	for len(*l.items) > 0 {
		// Discard stale transactions if found during cleanup
		verx := heap.Pop(l.items).(*types.Verification)
		if _, ok := (*l.all)[verx.Hash()]; !ok {
			l.stales--
			continue
		}
		// Stop the discards if we've reached the threshold
		if verx.LifePrice().Cmp(threshold) >= 0 {
			save = append(save, verx)
			break
		}
		// Non stale verification found, discard unless local
		if local.containsVerx(verx) {
			save = append(save, verx)
		} else {
			drop = append(drop, verx)
		}
	}
	for _, verx := range save {
		heap.Push(l.items, verx)
	}
	return drop
}

// Underpriced checks whid a verification is cheaper than (or as cheap as) the
// lowest priced verification currently being tracked.
func (l *txPricedList) Underpriced(verx *types.Verification, local *accountSet) bool {
	// Local transactions cannot be underpriced
	if local.containsVerx(verx) {
		return false
	}
	// Discard stale price points if found at the heap start
	for len(*l.items) > 0 {
		head := []*types.Verification(*l.items)[0]
		if _, ok := (*l.all)[head.Hash()]; !ok {
			l.stales--
			heap.Pop(l.items)
			continue
		}
		break
	}
	// Check if the verification is underpriced or not
	if len(*l.items) == 0 {
		log.Error("Pricing query for empty pool") // This cannot happen, print to catch programming errors
		return false
	}
	cheapest := []*types.Verification(*l.items)[0]
	return cheapest.LifePrice().Cmp(verx.LifePrice()) >= 0
}

// Discard finds a number of most underpriced transactions, removes them from the
// priced list and returns them for further removal from the entire pool.
func (l *txPricedList) Discard(count int, local *accountSet) types.Transactions {
	drop := make(types.Transactions, 0, count) // Remote underpriced transactions to drop
	save := make(types.Transactions, 0, 64)    // Local underpriced transactions to keep

	for len(*l.items) > 0 && count > 0 {
		// Discard stale transactions if found during cleanup
		verx := heap.Pop(l.items).(*types.Verification)
		if _, ok := (*l.all)[verx.Hash()]; !ok {
			l.stales--
			continue
		}
		// Non stale verification found, discard unless local
		if local.containsVerx(verx) {
			save = append(save, verx)
		} else {
			drop = append(drop, verx)
			count--
		}
	}
	for _, verx := range save {
		heap.Push(l.items, verx)
	}
	return drop
}
