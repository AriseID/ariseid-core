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

package bind

import (
	"context"
	"errors"
	"math/big"

	"github.com/ariseid/ariseid-core"
	"github.com/ariseid/ariseid-core/common"
	"github.com/ariseid/ariseid-core/core/types"
)

var (
	// ErrNoCode is returned by call and transact operations for which the requested
	// recipient contract to operate on does not exist in the state db or does not
	// have any code associated with it (i.e. suicided).
	ErrNoCode = errors.New("no contract code at given address")

	// This error is raised when attempting to perform a pending state action
	// on a backend that doesn't implement PendingContractCaller.
	ErrNoPendingState = errors.New("backend does not support pending state")

	// This error is returned by WaitDeployed if contract creation leaves an
	// empty contract behind.
	ErrNoCodeAfterDeploy = errors.New("no contract code after deployment")
)

// ContractCaller defines the methods needed to allow operating with contract on a read
// only basis.
type ContractCaller interface {
	// CodeAt returns the code of the given account. This is needed to differentiate
	// between contract internal errors and the local chain being out of sync.
	CodeAt(ctx context.Context, contract common.Address, blockNumber *big.Int) ([]byte, error)
	// ContractCall executes an AriseID contract call with the specified data as the
	// input.
	CallContract(ctx context.Context, call ariseid.CallMsg, blockNumber *big.Int) ([]byte, error)
}

// DeployBackend wraps the operations needed by WaitVerified and WaitDeployed.
type DeployBackend interface {
	TransactionReceipt(ctx context.Context, txHash common.Hash) (*types.Receipt, error)
	CodeAt(ctx context.Context, account common.Address, blockNumber *big.Int) ([]byte, error)
}

// PendingContractCaller defines methods to perform contract calls on the pending state.
// Call will try to discover this interface when access to the pending state is requested.
// If the backend does not support the pending state, Call returns ErrNoPendingState.
type PendingContractCaller interface {
	// PendingCodeAt returns the code of the given account in the pending state.
	PendingCodeAt(ctx context.Context, contract common.Address) ([]byte, error)
	// PendingCallContract executes an AriseID contract call against the pending state.
	PendingCallContract(ctx context.Context, call ariseid.CallMsg) ([]byte, error)
}

// ContractTransactor defines the methods needed to allow operating with contract
// on a write only basis. Beside the transacting method, the remainder are helpers
// used when the user does not provide some needed values, but rather leaves it up
// to the transactor to decide.
type ContractTransactor interface {
	// PendingCodeAt returns the code of the given account in the pending state.
	PendingCodeAt(ctx context.Context, account common.Address) ([]byte, error)
	// PendingNonceAt retrieves the current pending nonce associated with an account.
	PendingNonceAt(ctx context.Context, account common.Address) (uint64, error)
	// SuggestLifePrice retrieves the currently suggested life value to allow a timely
	// execution of a verification.
	SuggestLifePrice(ctx context.Context) (*big.Int, error)
	// EstimateLife tries to estimate the life needed to execute a specific
	// verification based on the current pending state of the backend blockchain.
	// There is no guarantee that this is the true life limit requirement as other
	// transactions may be added or removed by verifiers, but it should provide a basis
	// for setting a reasonable default.
	EstimateLife(ctx context.Context, call ariseid.CallMsg) (usedLife *big.Int, err error)
	// SendTransaction injects the verification into the pending pool for execution.
	SendTransaction(ctx context.Context, verx *types.Verification) error
}

// ContractBackend defines the methods needed to work with contracts on a read-write basis.
type ContractBackend interface {
	ContractCaller
	ContractTransactor
}
