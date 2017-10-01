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

// Package verifier implements AriseID block creation and verifying.
package verifier

import (
	"fmt"
	"sync/atomic"

	"github.com/ariseid/ariseid-core/accounts"
	"github.com/ariseid/ariseid-core/common"
	"github.com/ariseid/ariseid-core/consensus"
	"github.com/ariseid/ariseid-core/core"
	"github.com/ariseid/ariseid-core/core/state"
	"github.com/ariseid/ariseid-core/core/types"
	"github.com/ariseid/ariseid-core/aid/downloader"
	"github.com/ariseid/ariseid-core/aiddb"
	"github.com/ariseid/ariseid-core/event"
	"github.com/ariseid/ariseid-core/log"
	"github.com/ariseid/ariseid-core/params"
)

// Backend wraps all methods required for verifying.
type Backend interface {
	AccountManager() *accounts.Manager
	BlockChain() *core.BlockChain
	VerxPool() *core.VerxPool
	ChainDb() aiddb.Database
}

// Verifer creates blocks and searches for proof-of-work values.
type Verifer struct {
	mux *event.TypeMux

	worker *worker

	coinbase common.Address
	verifying   int32
	aid      Backend
	engine   consensus.Engine

	canStart    int32 // can start indicates whid we can start the verifying operation
	shouldStart int32 // should start indicates whid we should start after sync
}

func New(aid Backend, config *params.ChainConfig, mux *event.TypeMux, engine consensus.Engine) *Verifer {
	verifier := &Verifer{
		aid:      aid,
		mux:      mux,
		engine:   engine,
		worker:   newWorker(config, engine, common.Address{}, aid, mux),
		canStart: 1,
	}
	verifier.Register(NewCpuAgent(aid.BlockChain(), engine))
	go verifier.update()

	return verifier
}

// update keeps track of the downloader events. Please be aware that this is a one shot type of update loop.
// It's entered once and as soon as `Done` or `Failed` has been broadcasted the events are unregistered and
// the loop is exited. This to prevent a major security vuln where external parties can DOS you with blocks
// and halt your verifying operation for as long as the DOS continues.
func (self *Verifer) update() {
	events := self.mux.Subscribe(downloader.StartEvent{}, downloader.DoneEvent{}, downloader.FailedEvent{})
out:
	for ev := range events.Chan() {
		switch ev.Data.(type) {
		case downloader.StartEvent:
			atomic.StoreInt32(&self.canStart, 0)
			if self.Verifying() {
				self.Stop()
				atomic.StoreInt32(&self.shouldStart, 1)
				log.Info("Verifying aborted due to sync")
			}
		case downloader.DoneEvent, downloader.FailedEvent:
			shouldStart := atomic.LoadInt32(&self.shouldStart) == 1

			atomic.StoreInt32(&self.canStart, 1)
			atomic.StoreInt32(&self.shouldStart, 0)
			if shouldStart {
				self.Start(self.coinbase)
			}
			// unsubscribe. we're only interested in this event once
			events.Unsubscribe()
			// stop immediately and ignore all further pending events
			break out
		}
	}
}

func (self *Verifer) Start(coinbase common.Address) {
	atomic.StoreInt32(&self.shouldStart, 1)
	self.worker.setIDbase(coinbase)
	self.coinbase = coinbase

	if atomic.LoadInt32(&self.canStart) == 0 {
		log.Info("Network syncing, will start verifier afterwards")
		return
	}
	atomic.StoreInt32(&self.verifying, 1)

	log.Info("Starting verifying operation")
	self.worker.start()
	self.worker.commitNewWork()
}

func (self *Verifer) Stop() {
	self.worker.stop()
	atomic.StoreInt32(&self.verifying, 0)
	atomic.StoreInt32(&self.shouldStart, 0)
}

func (self *Verifer) Register(agent Agent) {
	if self.Verifying() {
		agent.Start()
	}
	self.worker.register(agent)
}

func (self *Verifer) Unregister(agent Agent) {
	self.worker.unregister(agent)
}

func (self *Verifer) Verifying() bool {
	return atomic.LoadInt32(&self.verifying) > 0
}

func (self *Verifer) HashRate() (tot int64) {
	if pow, ok := self.engine.(consensus.PoW); ok {
		tot += int64(pow.Hashrate())
	}
	// do we care this might race? is it worth we're rewriting some
	// aspects of the worker/locking up agents so we can get an accurate
	// hashrate?
	for agent := range self.worker.agents {
		if _, ok := agent.(*CpuAgent); !ok {
			tot += agent.GetHashRate()
		}
	}
	return
}

func (self *Verifer) SetExtra(extra []byte) error {
	if uint64(len(extra)) > params.MaximumExtraDataSize {
		return fmt.Errorf("Extra exceeds max length. %d > %v", len(extra), params.MaximumExtraDataSize)
	}
	self.worker.setExtra(extra)
	return nil
}

// Pending returns the currently pending block and associated state.
func (self *Verifer) Pending() (*types.Block, *state.StateDB) {
	return self.worker.pending()
}

// PendingBlock returns the currently pending block.
//
// Note, to access both the pending block and the pending state
// simultaneously, please use Pending(), as the pending state can
// change between multiple method calls
func (self *Verifer) PendingBlock() *types.Block {
	return self.worker.pendingBlock()
}

func (self *Verifer) SetIDbase(addr common.Address) {
	self.coinbase = addr
	self.worker.setIDbase(addr)
}
