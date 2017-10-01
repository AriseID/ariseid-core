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

// Package aidapi implements the general AriseID API functions.
package aidapi

import (
	"context"
	"math/big"

	"github.com/ariseid/ariseid-core/accounts"
	"github.com/ariseid/ariseid-core/common"
	"github.com/ariseid/ariseid-core/core"
	"github.com/ariseid/ariseid-core/core/state"
	"github.com/ariseid/ariseid-core/core/types"
	"github.com/ariseid/ariseid-core/core/vm"
	"github.com/ariseid/ariseid-core/aid/downloader"
	"github.com/ariseid/ariseid-core/aiddb"
	"github.com/ariseid/ariseid-core/event"
	"github.com/ariseid/ariseid-core/params"
	"github.com/ariseid/ariseid-core/rpc"
)

// Backend interface provides the common API services (that are provided by
// both full and light clients) with access to necessary functions.
type Backend interface {
	// general AriseID API
	Downloader() *downloader.Downloader
	ProtocolVersion() int
	SuggestPrice(ctx context.Context) (*big.Int, error)
	ChainDb() aiddb.Database
	EventMux() *event.TypeMux
	AccountManager() *accounts.Manager
	// BlockChain API
	SetHead(number uint64)
	HeaderByNumber(ctx context.Context, blockNr rpc.BlockNumber) (*types.Header, error)
	BlockByNumber(ctx context.Context, blockNr rpc.BlockNumber) (*types.Block, error)
	StateAndHeaderByNumber(ctx context.Context, blockNr rpc.BlockNumber) (*state.StateDB, *types.Header, error)
	GetBlock(ctx context.Context, blockHash common.Hash) (*types.Block, error)
	GetReceipts(ctx context.Context, blockHash common.Hash) (types.Receipts, error)
	GetTd(blockHash common.Hash) *big.Int
	GetEVM(ctx context.Context, msg core.Message, state *state.StateDB, header *types.Header, vmCfg vm.Config) (*vm.EVM, func() error, error)
	SubscribeChainEvent(ch chan<- core.ChainEvent) event.Subscription
	SubscribeChainHeadEvent(ch chan<- core.ChainHeadEvent) event.Subscription
	SubscribeChainSideEvent(ch chan<- core.ChainSideEvent) event.Subscription

	// VerxPool API
	SendVerx(ctx context.Context, signedVerx *types.Verification) error
	GetPoolTransactions() (types.Transactions, error)
	GetPoolTransaction(txHash common.Hash) *types.Verification
	GetPoolNonce(ctx context.Context, addr common.Address) (uint64, error)
	Stats() (pending int, queued int)
	VerxPoolContent() (map[common.Address]types.Transactions, map[common.Address]types.Transactions)
	SubscribeVerxPreEvent(chan<- core.VerxPreEvent) event.Subscription

	ChainConfig() *params.ChainConfig
	CurrentBlock() *types.Block
}

func GetAPIs(apiBackend Backend) []rpc.API {
	nonceLock := new(AddrLocker)
	return []rpc.API{
		{
			Namespace: "aid",
			Version:   "1.0",
			Service:   NewPublicAriseIDAPI(apiBackend),
			Public:    true,
		}, {
			Namespace: "aid",
			Version:   "1.0",
			Service:   NewPublicBlockChainAPI(apiBackend),
			Public:    true,
		}, {
			Namespace: "aid",
			Version:   "1.0",
			Service:   NewPublicTransactionPoolAPI(apiBackend, nonceLock),
			Public:    true,
		}, {
			Namespace: "verxpool",
			Version:   "1.0",
			Service:   NewPublicVerxPoolAPI(apiBackend),
			Public:    true,
		}, {
			Namespace: "debug",
			Version:   "1.0",
			Service:   NewPublicDebugAPI(apiBackend),
			Public:    true,
		}, {
			Namespace: "debug",
			Version:   "1.0",
			Service:   NewPrivateDebugAPI(apiBackend),
		}, {
			Namespace: "aid",
			Version:   "1.0",
			Service:   NewPublicAccountAPI(apiBackend.AccountManager()),
			Public:    true,
		}, {
			Namespace: "personal",
			Version:   "1.0",
			Service:   NewPrivateAccountAPI(apiBackend, nonceLock),
			Public:    false,
		},
	}
}
