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

	"github.com/ariseid/ariseid-core"
	"github.com/ariseid/ariseid-core/common"
	"github.com/ariseid/ariseid-core/common/hexutil"
	"github.com/ariseid/ariseid-core/core/types"
	"github.com/ariseid/ariseid-core/internal/aidapi"
	"github.com/ariseid/ariseid-core/rlp"
	"github.com/ariseid/ariseid-core/rpc"
)

// ContractBackend implements bind.ContractBackend with direct calls to AriseID
// internals to support operating on contracts within subprotocols like aid and
// swarm.
//
// Internally this backend uses the already exposed API endpoints of the AriseID
// object. These should be rewritten to internal Go method calls when the Go API
// is refactored to support a clean library use.
type ContractBackend struct {
	eapi  *aidapi.PublicAriseIDAPI        // Wrapper around the AriseID object to access metadata
	bcapi *aidapi.PublicBlockChainAPI      // Wrapper around the blockchain to access chain data
	txapi *aidapi.PublicTransactionPoolAPI // Wrapper around the verification pool to access verification data
}

// NewContractBackend creates a new native contract backend using an existing
// AriseID object.
func NewContractBackend(apiBackend aidapi.Backend) *ContractBackend {
	return &ContractBackend{
		eapi:  aidapi.NewPublicAriseIDAPI(apiBackend),
		bcapi: aidapi.NewPublicBlockChainAPI(apiBackend),
		txapi: aidapi.NewPublicTransactionPoolAPI(apiBackend, new(aidapi.AddrLocker)),
	}
}

// CodeAt retrieves any code associated with the contract from the local API.
func (b *ContractBackend) CodeAt(ctx context.Context, contract common.Address, blockNum *big.Int) ([]byte, error) {
	return b.bcapi.GetCode(ctx, contract, toBlockNumber(blockNum))
}

// CodeAt retrieves any code associated with the contract from the local API.
func (b *ContractBackend) PendingCodeAt(ctx context.Context, contract common.Address) ([]byte, error) {
	return b.bcapi.GetCode(ctx, contract, rpc.PendingBlockNumber)
}

// ContractCall implements bind.ContractCaller executing an AriseID contract
// call with the specified data as the input. The pending flag requests execution
// against the pending block, not the stable head of the chain.
func (b *ContractBackend) CallContract(ctx context.Context, msg ariseid.CallMsg, blockNum *big.Int) ([]byte, error) {
	out, err := b.bcapi.Call(ctx, toCallArgs(msg), toBlockNumber(blockNum))
	return out, err
}

// ContractCall implements bind.ContractCaller executing an AriseID contract
// call with the specified data as the input. The pending flag requests execution
// against the pending block, not the stable head of the chain.
func (b *ContractBackend) PendingCallContract(ctx context.Context, msg ariseid.CallMsg) ([]byte, error) {
	out, err := b.bcapi.Call(ctx, toCallArgs(msg), rpc.PendingBlockNumber)
	return out, err
}

func toCallArgs(msg ariseid.CallMsg) aidapi.CallArgs {
	args := aidapi.CallArgs{
		To:   msg.To,
		From: msg.From,
		Data: msg.Data,
	}
	if msg.Life != nil {
		args.Life = hexutil.Big(*msg.Life)
	}
	if msg.LifePrice != nil {
		args.LifePrice = hexutil.Big(*msg.LifePrice)
	}
	if msg.Value != nil {
		args.Value = hexutil.Big(*msg.Value)
	}
	return args
}

func toBlockNumber(num *big.Int) rpc.BlockNumber {
	if num == nil {
		return rpc.LatestBlockNumber
	}
	return rpc.BlockNumber(num.Int64())
}

// PendingAccountNonce implements bind.ContractTransactor retrieving the current
// pending nonce associated with an account.
func (b *ContractBackend) PendingNonceAt(ctx context.Context, account common.Address) (nonce uint64, err error) {
	out, err := b.txapi.GetTransactionCount(ctx, account, rpc.PendingBlockNumber)
	if out != nil {
		nonce = uint64(*out)
	}
	return nonce, err
}

// SuggestLifePrice implements bind.ContractTransactor retrieving the currently
// suggested life value to allow a timely execution of a verification.
func (b *ContractBackend) SuggestLifePrice(ctx context.Context) (*big.Int, error) {
	return b.eapi.LifePrice(ctx)
}

// EstimateLifeLimit implements bind.ContractTransactor triing to estimate the life
// needed to execute a specific verification based on the current pending state of
// the backend blockchain. There is no guarantee that this is the true life limit
// requirement as other transactions may be added or removed by verifiers, but it
// should provide a basis for setting a reasonable default.
func (b *ContractBackend) EstimateLife(ctx context.Context, msg ariseid.CallMsg) (*big.Int, error) {
	out, err := b.bcapi.EstimateLife(ctx, toCallArgs(msg))
	return out.ToInt(), err
}

// SendTransaction implements bind.ContractTransactor injects the verification
// into the pending pool for execution.
func (b *ContractBackend) SendTransaction(ctx context.Context, verx *types.Verification) error {
	raw, _ := rlp.EncodeToBytes(verx)
	_, err := b.txapi.SendRawTransaction(ctx, raw)
	return err
}
