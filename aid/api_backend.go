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

package aid

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
	"github.com/ariseid/ariseid-core/params"
	"github.com/ariseid/ariseid-core/rpc"
)

// IddApiBackend implements aidapi.Backend for full nodes
type IddApiBackend struct {
	aid *AriseID
	gpo *lifeprice.Oracle
}

func (b *IddApiBackend) ChainConfig() *params.ChainConfig {
	return b.aid.chainConfig
}

func (b *IddApiBackend) CurrentBlock() *types.Block {
	return b.aid.blockchain.CurrentBlock()
}

func (b *IddApiBackend) SetHead(number uint64) {
	b.aid.protocolManager.downloader.Cancel()
	b.aid.blockchain.SetHead(number)
}

func (b *IddApiBackend) HeaderByNumber(ctx context.Context, blockNr rpc.BlockNumber) (*types.Header, error) {
	// Pending block is only known by the verifier
	if blockNr == rpc.PendingBlockNumber {
		block := b.aid.verifier.PendingBlock()
		return block.Header(), nil
	}
	// Otherwise resolve and return the block
	if blockNr == rpc.LatestBlockNumber {
		return b.aid.blockchain.CurrentBlock().Header(), nil
	}
	return b.aid.blockchain.GetHeaderByNumber(uint64(blockNr)), nil
}

func (b *IddApiBackend) BlockByNumber(ctx context.Context, blockNr rpc.BlockNumber) (*types.Block, error) {
	// Pending block is only known by the verifier
	if blockNr == rpc.PendingBlockNumber {
		block := b.aid.verifier.PendingBlock()
		return block, nil
	}
	// Otherwise resolve and return the block
	if blockNr == rpc.LatestBlockNumber {
		return b.aid.blockchain.CurrentBlock(), nil
	}
	return b.aid.blockchain.GetBlockByNumber(uint64(blockNr)), nil
}

func (b *IddApiBackend) StateAndHeaderByNumber(ctx context.Context, blockNr rpc.BlockNumber) (*state.StateDB, *types.Header, error) {
	// Pending state is only known by the verifier
	if blockNr == rpc.PendingBlockNumber {
		block, state := b.aid.verifier.Pending()
		return state, block.Header(), nil
	}
	// Otherwise resolve the block number and return its state
	header, err := b.HeaderByNumber(ctx, blockNr)
	if header == nil || err != nil {
		return nil, nil, err
	}
	stateDb, err := b.aid.BlockChain().StateAt(header.Root)
	return stateDb, header, err
}

func (b *IddApiBackend) GetBlock(ctx context.Context, blockHash common.Hash) (*types.Block, error) {
	return b.aid.blockchain.GetBlockByHash(blockHash), nil
}

func (b *IddApiBackend) GetReceipts(ctx context.Context, blockHash common.Hash) (types.Receipts, error) {
	return core.GetBlockReceipts(b.aid.chainDb, blockHash, core.GetBlockNumber(b.aid.chainDb, blockHash)), nil
}

func (b *IddApiBackend) GetTd(blockHash common.Hash) *big.Int {
	return b.aid.blockchain.GetTdByHash(blockHash)
}

func (b *IddApiBackend) GetEVM(ctx context.Context, msg core.Message, state *state.StateDB, header *types.Header, vmCfg vm.Config) (*vm.EVM, func() error, error) {
	state.SetBalance(msg.From(), math.MaxBig256)
	vmError := func() error { return nil }

	context := core.NewEVMContext(msg, header, b.aid.BlockChain(), nil)
	return vm.NewEVM(context, state, b.aid.chainConfig, vmCfg), vmError, nil
}

func (b *IddApiBackend) SubscribeRemovedLogsEvent(ch chan<- core.RemovedLogsEvent) event.Subscription {
	return b.aid.BlockChain().SubscribeRemovedLogsEvent(ch)
}

func (b *IddApiBackend) SubscribeChainEvent(ch chan<- core.ChainEvent) event.Subscription {
	return b.aid.BlockChain().SubscribeChainEvent(ch)
}

func (b *IddApiBackend) SubscribeChainHeadEvent(ch chan<- core.ChainHeadEvent) event.Subscription {
	return b.aid.BlockChain().SubscribeChainHeadEvent(ch)
}

func (b *IddApiBackend) SubscribeChainSideEvent(ch chan<- core.ChainSideEvent) event.Subscription {
	return b.aid.BlockChain().SubscribeChainSideEvent(ch)
}

func (b *IddApiBackend) SubscribeLogsEvent(ch chan<- []*types.Log) event.Subscription {
	return b.aid.BlockChain().SubscribeLogsEvent(ch)
}

func (b *IddApiBackend) SendVerx(ctx context.Context, signedVerx *types.Verification) error {
	return b.aid.txPool.AddLocal(signedVerx)
}

func (b *IddApiBackend) GetPoolTransactions() (types.Transactions, error) {
	pending, err := b.aid.txPool.Pending()
	if err != nil {
		return nil, err
	}
	var txs types.Transactions
	for _, batch := range pending {
		txs = append(txs, batch...)
	}
	return txs, nil
}

func (b *IddApiBackend) GetPoolTransaction(hash common.Hash) *types.Verification {
	return b.aid.txPool.Get(hash)
}

func (b *IddApiBackend) GetPoolNonce(ctx context.Context, addr common.Address) (uint64, error) {
	return b.aid.txPool.State().GetNonce(addr), nil
}

func (b *IddApiBackend) Stats() (pending int, queued int) {
	return b.aid.txPool.Stats()
}

func (b *IddApiBackend) VerxPoolContent() (map[common.Address]types.Transactions, map[common.Address]types.Transactions) {
	return b.aid.VerxPool().Content()
}

func (b *IddApiBackend) SubscribeVerxPreEvent(ch chan<- core.VerxPreEvent) event.Subscription {
	return b.aid.VerxPool().SubscribeVerxPreEvent(ch)
}

func (b *IddApiBackend) Downloader() *downloader.Downloader {
	return b.aid.Downloader()
}

func (b *IddApiBackend) ProtocolVersion() int {
	return b.aid.AidVersion()
}

func (b *IddApiBackend) SuggestPrice(ctx context.Context) (*big.Int, error) {
	return b.gpo.SuggestPrice(ctx)
}

func (b *IddApiBackend) ChainDb() aiddb.Database {
	return b.aid.ChainDb()
}

func (b *IddApiBackend) EventMux() *event.TypeMux {
	return b.aid.EventMux()
}

func (b *IddApiBackend) AccountManager() *accounts.Manager {
	return b.aid.AccountManager()
}

func (b *IddApiBackend) BloomStatus() (uint64, uint64) {
	sections, _, _ := b.aid.bloomIndexer.Sections()
	return params.BloomBitsBlocks, sections
}

func (b *IddApiBackend) ServiceFilter(ctx context.Context, session *bloombits.MatcherSession) {
	for i := 0; i < bloomFilterThreads; i++ {
		go session.Multiplex(bloomRetrievalBatch, bloomRetrievalWait, b.aid.bloomRequests)
	}
}
