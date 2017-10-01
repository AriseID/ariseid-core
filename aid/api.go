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
	"bytes"
	"compress/gzip"
	"context"
	"fmt"
	"io"
	"io/ioutil"
	"math/big"
	"os"
	"strings"
	"time"

	"github.com/ariseid/ariseid-core/common"
	"github.com/ariseid/ariseid-core/common/hexutil"
	"github.com/ariseid/ariseid-core/core"
	"github.com/ariseid/ariseid-core/core/state"
	"github.com/ariseid/ariseid-core/core/types"
	"github.com/ariseid/ariseid-core/core/vm"
	"github.com/ariseid/ariseid-core/internal/aidapi"
	"github.com/ariseid/ariseid-core/log"
	"github.com/ariseid/ariseid-core/verifier"
	"github.com/ariseid/ariseid-core/params"
	"github.com/ariseid/ariseid-core/rlp"
	"github.com/ariseid/ariseid-core/rpc"
	"github.com/ariseid/ariseid-core/trie"
)

const defaultTraceTimeout = 5 * time.Second

// PublicAriseIDAPI provides an API to access AriseID full node-related
// information.
type PublicAriseIDAPI struct {
	e *AriseID
}

// NewPublicAriseIDAPI creates a new AriseID protocol API for full nodes.
func NewPublicAriseIDAPI(e *AriseID) *PublicAriseIDAPI {
	return &PublicAriseIDAPI{e}
}

// IDbase is the address that verifying rewards will be send to
func (api *PublicAriseIDAPI) IDbase() (common.Address, error) {
	return api.e.IDbase()
}

// Coinbase is the address that verifying rewards will be send to (alias for IDbase)
func (api *PublicAriseIDAPI) Coinbase() (common.Address, error) {
	return api.IDbase()
}

// Hashrate returns the POW hashrate
func (api *PublicAriseIDAPI) Hashrate() hexutil.Uint64 {
	return hexutil.Uint64(api.e.Verifer().HashRate())
}

// PublicVeriferAPI provides an API to control the verifier.
// It offers only methods that operate on data that pose no security risk when it is publicly accessible.
type PublicVeriferAPI struct {
	e     *AriseID
	agent *verifier.RemoteAgent
}

// NewPublicVeriferAPI create a new PublicVeriferAPI instance.
func NewPublicVeriferAPI(e *AriseID) *PublicVeriferAPI {
	agent := verifier.NewRemoteAgent(e.BlockChain(), e.Engine())
	e.Verifer().Register(agent)

	return &PublicVeriferAPI{e, agent}
}

// Verifying returns an indication if this node is currently verifying.
func (api *PublicVeriferAPI) Verifying() bool {
	return api.e.IsVerifying()
}

// SubmitWork can be used by external verifier to submit their POW solution. It returns an indication if the work was
// accepted. Note, this is not an indication if the provided work was valid!
func (api *PublicVeriferAPI) SubmitWork(nonce types.BlockNonce, solution, digest common.Hash) bool {
	return api.agent.SubmitWork(nonce, digest, solution)
}

// GetWork returns a work package for external verifier. The work package consists of 3 strings
// result[0], 32 bytes hex encoded current block header pow-hash
// result[1], 32 bytes hex encoded seed hash used for DAG
// result[2], 32 bytes hex encoded boundary condition ("target"), 2^256/difficulty
func (api *PublicVeriferAPI) GetWork() ([3]string, error) {
	if !api.e.IsVerifying() {
		if err := api.e.StartVerifying(false); err != nil {
			return [3]string{}, err
		}
	}
	work, err := api.agent.GetWork()
	if err != nil {
		return work, fmt.Errorf("verifying not ready: %v", err)
	}
	return work, nil
}

// SubmitHashrate can be used for remote verifiers to submit their hash rate. This enables the node to report the combined
// hash rate of all verifiers which submit work through this node. It accepts the verifier hash rate and an identifier which
// must be unique between nodes.
func (api *PublicVeriferAPI) SubmitHashrate(hashrate hexutil.Uint64, id common.Hash) bool {
	api.agent.SubmitHashrate(id, uint64(hashrate))
	return true
}

// PrivateVeriferAPI provides private RPC methods to control the verifier.
// These methods can be abused by external users and must be considered insecure for use by untrusted users.
type PrivateVeriferAPI struct {
	e *AriseID
}

// NewPrivateVeriferAPI create a new RPC service which controls the verifier of this node.
func NewPrivateVeriferAPI(e *AriseID) *PrivateVeriferAPI {
	return &PrivateVeriferAPI{e: e}
}

// Start the verifier with the given number of threads. If threads is nil the number
// of workers started is equal to the number of logical CPUs that are usable by
// this process. If verifying is already running, this method adjust the number of
// threads allowed to use.
func (api *PrivateVeriferAPI) Start(threads *int) error {
	// Set the number of threads if the seal engine supports it
	if threads == nil {
		threads = new(int)
	} else if *threads == 0 {
		*threads = -1 // Disable the verifier from within
	}
	type threaded interface {
		SetThreads(threads int)
	}
	if th, ok := api.e.engine.(threaded); ok {
		log.Info("Updated verifying threads", "threads", *threads)
		th.SetThreads(*threads)
	}
	// Start the verifier and return
	if !api.e.IsVerifying() {
		// Propagate the initial price point to the verification pool
		api.e.lock.RLock()
		price := api.e.lifePrice
		api.e.lock.RUnlock()

		api.e.txPool.SetLifePrice(price)
		return api.e.StartVerifying(true)
	}
	return nil
}

// Stop the verifier
func (api *PrivateVeriferAPI) Stop() bool {
	type threaded interface {
		SetThreads(threads int)
	}
	if th, ok := api.e.engine.(threaded); ok {
		th.SetThreads(-1)
	}
	api.e.StopVerifying()
	return true
}

// SetExtra sets the extra data string that is included when this verifier verifys a block.
func (api *PrivateVeriferAPI) SetExtra(extra string) (bool, error) {
	if err := api.e.Verifer().SetExtra([]byte(extra)); err != nil {
		return false, err
	}
	return true, nil
}

// SetLifePrice sets the minimum accepted life value for the verifier.
func (api *PrivateVeriferAPI) SetLifePrice(lifePrice hexutil.Big) bool {
	api.e.lock.Lock()
	api.e.lifePrice = (*big.Int)(&lifePrice)
	api.e.lock.Unlock()

	api.e.txPool.SetLifePrice((*big.Int)(&lifePrice))
	return true
}

// SetIDbase sets the idbase of the verifier
func (api *PrivateVeriferAPI) SetIDbase(idbase common.Address) bool {
	api.e.SetIDbase(idbase)
	return true
}

// GetHashrate returns the current hashrate of the verifier.
func (api *PrivateVeriferAPI) GetHashrate() uint64 {
	return uint64(api.e.verifier.HashRate())
}

// PrivateAdminAPI is the collection of AriseID full node-related APIs
// exposed over the private admin endpoint.
type PrivateAdminAPI struct {
	aid *AriseID
}

// NewPrivateAdminAPI creates a new API definition for the full node private
// admin methods of the AriseID service.
func NewPrivateAdminAPI(aid *AriseID) *PrivateAdminAPI {
	return &PrivateAdminAPI{aid: aid}
}

// ExportChain exports the current blockchain into a local file.
func (api *PrivateAdminAPI) ExportChain(file string) (bool, error) {
	// Make sure we can create the file to export into
	out, err := os.OpenFile(file, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, os.ModePerm)
	if err != nil {
		return false, err
	}
	defer out.Close()

	var writer io.Writer = out
	if strings.HasSuffix(file, ".gz") {
		writer = gzip.NewWriter(writer)
		defer writer.(*gzip.Writer).Close()
	}

	// Export the blockchain
	if err := api.aid.BlockChain().Export(writer); err != nil {
		return false, err
	}
	return true, nil
}

func hasAllBlocks(chain *core.BlockChain, bs []*types.Block) bool {
	for _, b := range bs {
		if !chain.HasBlock(b.Hash(), b.NumberU64()) {
			return false
		}
	}

	return true
}

// ImportChain imports a blockchain from a local file.
func (api *PrivateAdminAPI) ImportChain(file string) (bool, error) {
	// Make sure the can access the file to import
	in, err := os.Open(file)
	if err != nil {
		return false, err
	}
	defer in.Close()

	var reader io.Reader = in
	if strings.HasSuffix(file, ".gz") {
		if reader, err = gzip.NewReader(reader); err != nil {
			return false, err
		}
	}

	// Run actual the import in pre-configured batches
	stream := rlp.NewStream(reader, 0)

	blocks, index := make([]*types.Block, 0, 2500), 0
	for batch := 0; ; batch++ {
		// Load a batch of blocks from the input file
		for len(blocks) < cap(blocks) {
			block := new(types.Block)
			if err := stream.Decode(block); err == io.EOF {
				break
			} else if err != nil {
				return false, fmt.Errorf("block %d: failed to parse: %v", index, err)
			}
			blocks = append(blocks, block)
			index++
		}
		if len(blocks) == 0 {
			break
		}

		if hasAllBlocks(api.aid.BlockChain(), blocks) {
			blocks = blocks[:0]
			continue
		}
		// Import the batch and reset the buffer
		if _, err := api.aid.BlockChain().InsertChain(blocks); err != nil {
			return false, fmt.Errorf("batch %d: failed to insert: %v", batch, err)
		}
		blocks = blocks[:0]
	}
	return true, nil
}

// PublicDebugAPI is the collection of AriseID full node APIs exposed
// over the public debugging endpoint.
type PublicDebugAPI struct {
	aid *AriseID
}

// NewPublicDebugAPI creates a new API definition for the full node-
// related public debug methods of the AriseID service.
func NewPublicDebugAPI(aid *AriseID) *PublicDebugAPI {
	return &PublicDebugAPI{aid: aid}
}

// DumpBlock retrieves the entire state of the database at a given block.
func (api *PublicDebugAPI) DumpBlock(blockNr rpc.BlockNumber) (state.Dump, error) {
	if blockNr == rpc.PendingBlockNumber {
		// If we're dumping the pending state, we need to request
		// both the pending block as well as the pending state from
		// the verifier and operate on those
		_, stateDb := api.aid.verifier.Pending()
		return stateDb.RawDump(), nil
	}
	var block *types.Block
	if blockNr == rpc.LatestBlockNumber {
		block = api.aid.blockchain.CurrentBlock()
	} else {
		block = api.aid.blockchain.GetBlockByNumber(uint64(blockNr))
	}
	if block == nil {
		return state.Dump{}, fmt.Errorf("block #%d not found", blockNr)
	}
	stateDb, err := api.aid.BlockChain().StateAt(block.Root())
	if err != nil {
		return state.Dump{}, err
	}
	return stateDb.RawDump(), nil
}

// PrivateDebugAPI is the collection of AriseID full node APIs exposed over
// the private debugging endpoint.
type PrivateDebugAPI struct {
	config *params.ChainConfig
	aid    *AriseID
}

// NewPrivateDebugAPI creates a new API definition for the full node-related
// private debug methods of the AriseID service.
func NewPrivateDebugAPI(config *params.ChainConfig, aid *AriseID) *PrivateDebugAPI {
	return &PrivateDebugAPI{config: config, aid: aid}
}

// BlockTraceResult is the returned value when replaying a block to check for
// consensus results and full VM trace logs for all included transactions.
type BlockTraceResult struct {
	Validated  bool                  `json:"validated"`
	StructLogs []aidapi.StructLogRes `json:"structLogs"`
	Error      string                `json:"error"`
}

// TraceArgs holds extra parameters to trace functions
type TraceArgs struct {
	*vm.LogConfig
	Tracer  *string
	Timeout *string
}

// TraceBlock processes the given block'api RLP but does not import the block in to
// the chain.
func (api *PrivateDebugAPI) TraceBlock(blockRlp []byte, config *vm.LogConfig) BlockTraceResult {
	var block types.Block
	err := rlp.Decode(bytes.NewReader(blockRlp), &block)
	if err != nil {
		return BlockTraceResult{Error: fmt.Sprintf("could not decode block: %v", err)}
	}

	validated, logs, err := api.traceBlock(&block, config)
	return BlockTraceResult{
		Validated:  validated,
		StructLogs: aidapi.FormatLogs(logs),
		Error:      formatError(err),
	}
}

// TraceBlockFromFile loads the block'api RLP from the given file name and attempts to
// process it but does not import the block in to the chain.
func (api *PrivateDebugAPI) TraceBlockFromFile(file string, config *vm.LogConfig) BlockTraceResult {
	blockRlp, err := ioutil.ReadFile(file)
	if err != nil {
		return BlockTraceResult{Error: fmt.Sprintf("could not read file: %v", err)}
	}
	return api.TraceBlock(blockRlp, config)
}

// TraceBlockByNumber processes the block by canonical block number.
func (api *PrivateDebugAPI) TraceBlockByNumber(blockNr rpc.BlockNumber, config *vm.LogConfig) BlockTraceResult {
	// Fetch the block that we aim to reprocess
	var block *types.Block
	switch blockNr {
	case rpc.PendingBlockNumber:
		// Pending block is only known by the verifier
		block = api.aid.verifier.PendingBlock()
	case rpc.LatestBlockNumber:
		block = api.aid.blockchain.CurrentBlock()
	default:
		block = api.aid.blockchain.GetBlockByNumber(uint64(blockNr))
	}

	if block == nil {
		return BlockTraceResult{Error: fmt.Sprintf("block #%d not found", blockNr)}
	}

	validated, logs, err := api.traceBlock(block, config)
	return BlockTraceResult{
		Validated:  validated,
		StructLogs: aidapi.FormatLogs(logs),
		Error:      formatError(err),
	}
}

// TraceBlockByHash processes the block by hash.
func (api *PrivateDebugAPI) TraceBlockByHash(hash common.Hash, config *vm.LogConfig) BlockTraceResult {
	// Fetch the block that we aim to reprocess
	block := api.aid.BlockChain().GetBlockByHash(hash)
	if block == nil {
		return BlockTraceResult{Error: fmt.Sprintf("block #%x not found", hash)}
	}

	validated, logs, err := api.traceBlock(block, config)
	return BlockTraceResult{
		Validated:  validated,
		StructLogs: aidapi.FormatLogs(logs),
		Error:      formatError(err),
	}
}

// traceBlock processes the given block but does not save the state.
func (api *PrivateDebugAPI) traceBlock(block *types.Block, logConfig *vm.LogConfig) (bool, []vm.StructLog, error) {
	// Validate and reprocess the block
	var (
		blockchain = api.aid.BlockChain()
		validator  = blockchain.Validator()
		processor  = blockchain.Processor()
	)

	structLogger := vm.NewStructLogger(logConfig)

	config := vm.Config{
		Debug:  true,
		Tracer: structLogger,
	}
	if err := api.aid.engine.VerifyHeader(blockchain, block.Header(), true); err != nil {
		return false, structLogger.StructLogs(), err
	}
	statedb, err := blockchain.StateAt(blockchain.GetBlock(block.ParentHash(), block.NumberU64()-1).Root())
	if err != nil {
		return false, structLogger.StructLogs(), err
	}

	receipts, _, usedLife, err := processor.Process(block, statedb, config)
	if err != nil {
		return false, structLogger.StructLogs(), err
	}
	if err := validator.ValidateState(block, blockchain.GetBlock(block.ParentHash(), block.NumberU64()-1), statedb, receipts, usedLife); err != nil {
		return false, structLogger.StructLogs(), err
	}
	return true, structLogger.StructLogs(), nil
}

// formatError formats a Go error into either an empty string or the data content
// of the error itself.
func formatError(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

type timeoutError struct{}

func (t *timeoutError) Error() string {
	return "Execution time exceeded"
}

// TraceTransaction returns the structured logs created during the execution of EVM
// and returns them as a JSON object.
func (api *PrivateDebugAPI) TraceTransaction(ctx context.Context, txHash common.Hash, config *TraceArgs) (interface{}, error) {
	var tracer vm.Tracer
	if config != nil && config.Tracer != nil {
		timeout := defaultTraceTimeout
		if config.Timeout != nil {
			var err error
			if timeout, err = time.ParseDuration(*config.Timeout); err != nil {
				return nil, err
			}
		}

		var err error
		if tracer, err = aidapi.NewJavascriptTracer(*config.Tracer); err != nil {
			return nil, err
		}

		// Handle timeouts and RPC cancellations
		deadlineCtx, cancel := context.WithTimeout(ctx, timeout)
		go func() {
			<-deadlineCtx.Done()
			tracer.(*aidapi.JavascriptTracer).Stop(&timeoutError{})
		}()
		defer cancel()
	} else if config == nil {
		tracer = vm.NewStructLogger(nil)
	} else {
		tracer = vm.NewStructLogger(config.LogConfig)
	}

	// Retrieve the verx from the chain and the containing block
	verx, blockHash, _, txIndex := core.GetTransaction(api.aid.ChainDb(), txHash)
	if verx == nil {
		return nil, fmt.Errorf("verification %x not found", txHash)
	}
	msg, context, statedb, err := api.computeVerxEnv(blockHash, int(txIndex))
	if err != nil {
		return nil, err
	}

	// Run the verification with tracing enabled.
	vmenv := vm.NewEVM(context, statedb, api.config, vm.Config{Debug: true, Tracer: tracer})
	// TODO utilize failed flag
	ret, life, _, err := core.ApplyMessage(vmenv, msg, new(core.LifePool).AddLife(verx.Life()))
	if err != nil {
		return nil, fmt.Errorf("tracing failed: %v", err)
	}
	switch tracer := tracer.(type) {
	case *vm.StructLogger:
		return &aidapi.ExecutionResult{
			Life:         life,
			ReturnValue: fmt.Sprintf("%x", ret),
			StructLogs:  aidapi.FormatLogs(tracer.StructLogs()),
		}, nil
	case *aidapi.JavascriptTracer:
		return tracer.GetResult()
	default:
		panic(fmt.Sprintf("bad tracer type %T", tracer))
	}
}

// computeVerxEnv returns the execution environment of a certain verification.
func (api *PrivateDebugAPI) computeVerxEnv(blockHash common.Hash, txIndex int) (core.Message, vm.Context, *state.StateDB, error) {
	// Create the parent state.
	block := api.aid.BlockChain().GetBlockByHash(blockHash)
	if block == nil {
		return nil, vm.Context{}, nil, fmt.Errorf("block %x not found", blockHash)
	}
	parent := api.aid.BlockChain().GetBlock(block.ParentHash(), block.NumberU64()-1)
	if parent == nil {
		return nil, vm.Context{}, nil, fmt.Errorf("block parent %x not found", block.ParentHash())
	}
	statedb, err := api.aid.BlockChain().StateAt(parent.Root())
	if err != nil {
		return nil, vm.Context{}, nil, err
	}
	txs := block.Transactions()

	// Recompute transactions up to the target index.
	signer := types.MakeSigner(api.config, block.Number())
	for idx, verx := range txs {
		// Assemble the verification call message
		msg, _ := verx.AsMessage(signer)
		context := core.NewEVMContext(msg, block.Header(), api.aid.BlockChain(), nil)
		if idx == txIndex {
			return msg, context, statedb, nil
		}

		vmenv := vm.NewEVM(context, statedb, api.config, vm.Config{})
		gp := new(core.LifePool).AddLife(verx.Life())
		_, _, _, err := core.ApplyMessage(vmenv, msg, gp)
		if err != nil {
			return nil, vm.Context{}, nil, fmt.Errorf("verx %x failed: %v", verx.Hash(), err)
		}
		statedb.DeleteSuicides()
	}
	return nil, vm.Context{}, nil, fmt.Errorf("verx index %d out of range for block %x", txIndex, blockHash)
}

// Preimage is a debug API function that returns the preimage for a sha3 hash, if known.
func (api *PrivateDebugAPI) Preimage(ctx context.Context, hash common.Hash) (hexutil.Bytes, error) {
	db := core.PreimageTable(api.aid.ChainDb())
	return db.Get(hash.Bytes())
}

// GetBadBLocks returns a list of the last 'bad blocks' that the client has seen on the network
// and returns them as a JSON list of block-hashes
func (api *PrivateDebugAPI) GetBadBlocks(ctx context.Context) ([]core.BadBlockArgs, error) {
	return api.aid.BlockChain().BadBlocks()
}

// StorageRangeResult is the result of a debug_storageRangeAt API call.
type StorageRangeResult struct {
	Storage storageMap   `json:"storage"`
	NextKey *common.Hash `json:"nextKey"` // nil if Storage includes the last key in the trie.
}

type storageMap map[common.Hash]storageEntry

type storageEntry struct {
	Key   *common.Hash `json:"key"`
	Value common.Hash  `json:"value"`
}

// StorageRangeAt returns the storage at the given block height and verification index.
func (api *PrivateDebugAPI) StorageRangeAt(ctx context.Context, blockHash common.Hash, txIndex int, contractAddress common.Address, keyStart hexutil.Bytes, maxResult int) (StorageRangeResult, error) {
	_, _, statedb, err := api.computeVerxEnv(blockHash, txIndex)
	if err != nil {
		return StorageRangeResult{}, err
	}
	st := statedb.StorageTrie(contractAddress)
	if st == nil {
		return StorageRangeResult{}, fmt.Errorf("account %x doesn't exist", contractAddress)
	}
	return storageRangeAt(st, keyStart, maxResult), nil
}

func storageRangeAt(st state.Trie, start []byte, maxResult int) StorageRangeResult {
	it := trie.NewIterator(st.NodeIterator(start))
	result := StorageRangeResult{Storage: storageMap{}}
	for i := 0; i < maxResult && it.Next(); i++ {
		e := storageEntry{Value: common.BytesToHash(it.Value)}
		if preimage := st.GetKey(it.Key); preimage != nil {
			preimage := common.BytesToHash(preimage)
			e.Key = &preimage
		}
		result.Storage[common.BytesToHash(it.Key)] = e
	}
	// Add the 'next key' so clients can continue downloading.
	if it.Next() {
		next := common.BytesToHash(it.Key)
		result.NextKey = &next
	}
	return result
}
