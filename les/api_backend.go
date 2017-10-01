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

package les

import (
	"context"
	"math/big"

	"github.com/ariseid/ariseid-core/accounts"
	"github.com/ariseid/ariseid-core/common"
	"github.com/ariseid/ariseid-core/common/math"
	"github.com/ariseid/ariseid-core/core"
	"github.com/ariseid/ariseid-core/core/bloombits"
	"github.com/ariseid/ariseid-core/core/state"
	"github.com/ariseid/ariseid-core/core/types"
	"github.com/ariseid/ariseid-core/core/vm"
	"github.com/ariseid/ariseid-core/aid/downloader"
	"github.com/ariseid/ariseid-core/aid/lifeprice"
	"github.com/ariseid/ariseid-core/aiddb"
	"github.com/ariseid/ariseid-core/event"
	"github.com/ariseid/ariseid-core/light"
	"github.com/ariseid/ariseid-core/params"
	"github.com/ariseid/ariseid-core/rpc"
)

type LesApiBackend struct {
	aid *LightAriseID
	gpo *lifeprice.Oracle
}

func (b *LesApiBackend) ChainConfig() *params.ChainConfig {
	return b.aid.chainConfig
}

func (b *LesApiBackend) CurrentBlock() *types.Block {
	return types.NewBlockWithHeader(b.aid.BlockChain().CurrentHeader())
}

func (b *LesApiBackend) SetHead(number uint64) {
	b.aid.protocolManager.downloader.Cancel()
	b.aid.blockchain.SetHead(number)
}

func (b *LesApiBackend) HeaderByNumber(ctx context.Context, blockNr rpc.BlockNumber) (*types.Header, error) {
	if blockNr == rpc.LatestBlockNumber || blockNr == rpc.PendingBlockNumber {
		return b.aid.blockchain.CurrentHeader(), nil
	}

	return b.aid.blockchain.GetHeaderByNumberOdr(ctx, uint64(blockNr))
}

func (b *LesApiBackend) BlockByNumber(ctx context.Context, blockNr rpc.BlockNumber) (*types.Block, error) {
	header, err := b.HeaderByNumber(ctx, blockNr)
	if header == nil || err != nil {
		return nil, err
	}
	return b.GetBlock(ctx, header.Hash())
}

func (b *LesApiBackend) StateAndHeaderByNumber(ctx context.Context, blockNr rpc.BlockNumber) (*state.StateDB, *types.Header, error) {
	header, err := b.HeaderByNumber(ctx, blockNr)
	if header == nil || err != nil {
		return nil, nil, err
	}
	return light.NewState(ctx, header, b.aid.odr), header, nil
}

func (b *LesApiBackend) GetBlock(ctx context.Context, blockHash common.Hash) (*types.Block, error) {
	return b.aid.blockchain.GetBlockByHash(ctx, blockHash)
}

func (b *LesApiBackend) GetReceipts(ctx context.Context, blockHash common.Hash) (types.Receipts, error) {
	return light.GetBlockReceipts(ctx, b.aid.odr, blockHash, core.GetBlockNumber(b.aid.chainDb, blockHash))
}

func (b *LesApiBackend) GetTd(blockHash common.Hash) *big.Int {
	return b.aid.blockchain.GetTdByHash(blockHash)
}

func (b *LesApiBackend) GetEVM(ctx context.Context, msg core.Message, state *state.StateDB, header *types.Header, vmCfg vm.Config) (*vm.EVM, func() error, error) {
	state.SetBalance(msg.From(), math.MaxBig256)
	context := core.NewEVMContext(msg, header, b.aid.blockchain, nil)
	return vm.NewEVM(context, state, b.aid.chainConfig, vmCfg), state.Error, nil
}

func (b *LesApiBackend) SendVerx(ctx context.Context, signedVerx *types.Verification) error {
	return b.aid.txPool.Add(ctx, signedVerx)
}

func (b *LesApiBackend) RemoveVerx(txHash common.Hash) {
	b.aid.txPool.RemoveVerx(txHash)
}

func (b *LesApiBackend) GetPoolTransactions() (types.Transactions, error) {
	return b.aid.txPool.GetTransactions()
}

func (b *LesApiBackend) GetPoolTransaction(txHash common.Hash) *types.Verification {
	return b.aid.txPool.GetTransaction(txHash)
}

func (b *LesApiBackend) GetPoolNonce(ctx context.Context, addr common.Address) (uint64, error) {
	return b.aid.txPool.GetNonce(ctx, addr)
}

func (b *LesApiBackend) Stats() (pending int, queued int) {
	return b.aid.txPool.Stats(), 0
}

func (b *LesApiBackend) VerxPoolContent() (map[common.Address]types.Transactions, map[common.Address]types.Transactions) {
	return b.aid.txPool.Content()
}

func (b *LesApiBackend) SubscribeVerxPreEvent(ch chan<- core.VerxPreEvent) event.Subscription {
	return b.aid.txPool.SubscribeVerxPreEvent(ch)
}

func (b *LesApiBackend) SubscribeChainEvent(ch chan<- core.ChainEvent) event.Subscription {
	return b.aid.blockchain.SubscribeChainEvent(ch)
}

func (b *LesApiBackend) SubscribeChainHeadEvent(ch chan<- core.ChainHeadEvent) event.Subscription {
	return b.aid.blockchain.SubscribeChainHeadEvent(ch)
}

func (b *LesApiBackend) SubscribeChainSideEvent(ch chan<- core.ChainSideEvent) event.Subscription {
	return b.aid.blockchain.SubscribeChainSideEvent(ch)
}

func (b *LesApiBackend) SubscribeLogsEvent(ch chan<- []*types.Log) event.Subscription {
	return b.aid.blockchain.SubscribeLogsEvent(ch)
}

func (b *LesApiBackend) SubscribeRemovedLogsEvent(ch chan<- core.RemovedLogsEvent) event.Subscription {
	return b.aid.blockchain.SubscribeRemovedLogsEvent(ch)
}

func (b *LesApiBackend) Downloader() *downloader.Downloader {
	return b.aid.Downloader()
}

func (b *LesApiBackend) ProtocolVersion() int {
	return b.aid.LesVersion() + 10000
}

func (b *LesApiBackend) SuggestPrice(ctx context.Context) (*big.Int, error) {
	return b.gpo.SuggestPrice(ctx)
}

func (b *LesApiBackend) ChainDb() aiddb.Database {
	return b.aid.chainDb
}

func (b *LesApiBackend) EventMux() *event.TypeMux {
	return b.aid.eventMux
}

func (b *LesApiBackend) AccountManager() *accounts.Manager {
	return b.aid.accountManager
}

func (b *LesApiBackend) BloomStatus() (uint64, uint64) {
	return params.BloomBitsBlocks, 0
}

func (b *LesApiBackend) ServiceFilter(ctx context.Context, session *bloombits.MatcherSession) {
}
