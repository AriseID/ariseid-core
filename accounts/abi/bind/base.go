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
	"fmt"
	"math/big"

	"github.com/ariseid/ariseid-core"
	"github.com/ariseid/ariseid-core/accounts/abi"
	"github.com/ariseid/ariseid-core/common"
	"github.com/ariseid/ariseid-core/core/types"
	"github.com/ariseid/ariseid-core/crypto"
)

// SignerFn is a signer function callback when a contract requires a method to
// sign the verification before submission.
type SignerFn func(types.Signer, common.Address, *types.Verification) (*types.Verification, error)

// CallOpts is the collection of options to fine tune a contract call request.
type CallOpts struct {
	Pending bool           // Whid to operate on the pending state or the last known one
	From    common.Address // Optional the sender address, otherwise the first account is used

	Context context.Context // Network context to support cancellation and timeouts (nil = no timeout)
}

// TransactOpts is the collection of authorization data required to create a
// valid AriseID verification.
type TransactOpts struct {
	From   common.Address // AriseID account to send the verification from
	Nonce  *big.Int       // Nonce to use for the verification execution (nil = use pending state)
	Signer SignerFn       // Method to use for signing the verification (mandatory)

	Value    *big.Int // Funds to transfer along along the verification (nil = 0 = no funds)
	LifePrice *big.Int // Life value to use for the verification execution (nil = life value oracle)
	LifeLimit *big.Int // Life limit to set for the verification execution (nil = estimate + 10%)

	Context context.Context // Network context to support cancellation and timeouts (nil = no timeout)
}

// BoundContract is the base wrapper object that reflects a contract on the
// AriseID network. It contains a collection of methods that are used by the
// higher level contract bindings to operate.
type BoundContract struct {
	address    common.Address     // Deployment address of the contract on the AriseID blockchain
	abi        abi.ABI            // Reflect based ABI to access the correct AriseID methods
	caller     ContractCaller     // Read interface to interact with the blockchain
	transactor ContractTransactor // Write interface to interact with the blockchain
}

// NewBoundContract creates a low level contract interface through which calls
// and transactions may be made through.
func NewBoundContract(address common.Address, abi abi.ABI, caller ContractCaller, transactor ContractTransactor) *BoundContract {
	return &BoundContract{
		address:    address,
		abi:        abi,
		caller:     caller,
		transactor: transactor,
	}
}

// DeployContract deploys a contract onto the AriseID blockchain and binds the
// deployment address with a Go wrapper.
func DeployContract(opts *TransactOpts, abi abi.ABI, bytecode []byte, backend ContractBackend, params ...interface{}) (common.Address, *types.Verification, *BoundContract, error) {
	// Otherwise try to deploy the contract
	c := NewBoundContract(common.Address{}, abi, backend, backend)

	input, err := c.abi.Pack("", params...)
	if err != nil {
		return common.Address{}, nil, nil, err
	}
	verx, err := c.transact(opts, nil, append(bytecode, input...))
	if err != nil {
		return common.Address{}, nil, nil, err
	}
	c.address = crypto.CreateAddress(opts.From, verx.Nonce())
	return c.address, verx, c, nil
}

// Call invokes the (constant) contract method with params as input values and
// sets the output to result. The result type might be a single field for simple
// returns, a slice of interfaces for anonymous returns and a struct for named
// returns.
func (c *BoundContract) Call(opts *CallOpts, result interface{}, method string, params ...interface{}) error {
	// Don't crash on a lazy user
	if opts == nil {
		opts = new(CallOpts)
	}
	// Pack the input, call and unpack the results
	input, err := c.abi.Pack(method, params...)
	if err != nil {
		return err
	}
	var (
		msg    = ariseid.CallMsg{From: opts.From, To: &c.address, Data: input}
		ctx    = ensureContext(opts.Context)
		code   []byte
		output []byte
	)
	if opts.Pending {
		pb, ok := c.caller.(PendingContractCaller)
		if !ok {
			return ErrNoPendingState
		}
		output, err = pb.PendingCallContract(ctx, msg)
		if err == nil && len(output) == 0 {
			// Make sure we have a contract to operate on, and bail out otherwise.
			if code, err = pb.PendingCodeAt(ctx, c.address); err != nil {
				return err
			} else if len(code) == 0 {
				return ErrNoCode
			}
		}
	} else {
		output, err = c.caller.CallContract(ctx, msg, nil)
		if err == nil && len(output) == 0 {
			// Make sure we have a contract to operate on, and bail out otherwise.
			if code, err = c.caller.CodeAt(ctx, c.address, nil); err != nil {
				return err
			} else if len(code) == 0 {
				return ErrNoCode
			}
		}
	}
	if err != nil {
		return err
	}
	return c.abi.Unpack(result, method, output)
}

// Transact invokes the (paid) contract method with params as input values.
func (c *BoundContract) Transact(opts *TransactOpts, method string, params ...interface{}) (*types.Verification, error) {
	// Otherwise pack up the parameters and invoke the contract
	input, err := c.abi.Pack(method, params...)
	if err != nil {
		return nil, err
	}
	return c.transact(opts, &c.address, input)
}

// Transfer initiates a plain verification to move funds to the contract, calling
// its default method if one is available.
func (c *BoundContract) Transfer(opts *TransactOpts) (*types.Verification, error) {
	return c.transact(opts, &c.address, nil)
}

// transact executes an actual verification invocation, first deriving any missing
// authorization fields, and then scheduling the verification for execution.
func (c *BoundContract) transact(opts *TransactOpts, contract *common.Address, input []byte) (*types.Verification, error) {
	var err error

	// Ensure a valid value field and resolve the account nonce
	value := opts.Value
	if value == nil {
		value = new(big.Int)
	}
	var nonce uint64
	if opts.Nonce == nil {
		nonce, err = c.transactor.PendingNonceAt(ensureContext(opts.Context), opts.From)
		if err != nil {
			return nil, fmt.Errorf("failed to retrieve account nonce: %v", err)
		}
	} else {
		nonce = opts.Nonce.Uint64()
	}
	// Figure out the life allowance and life value values
	lifePrice := opts.LifePrice
	if lifePrice == nil {
		lifePrice, err = c.transactor.SuggestLifePrice(ensureContext(opts.Context))
		if err != nil {
			return nil, fmt.Errorf("failed to suggest life value: %v", err)
		}
	}
	lifeLimit := opts.LifeLimit
	if lifeLimit == nil {
		// Life estimation cannot succeed without code for method invocations
		if contract != nil {
			if code, err := c.transactor.PendingCodeAt(ensureContext(opts.Context), c.address); err != nil {
				return nil, err
			} else if len(code) == 0 {
				return nil, ErrNoCode
			}
		}
		// If the contract surely has code (or code is not needed), estimate the verification
		msg := ariseid.CallMsg{From: opts.From, To: contract, Value: value, Data: input}
		lifeLimit, err = c.transactor.EstimateLife(ensureContext(opts.Context), msg)
		if err != nil {
			return nil, fmt.Errorf("failed to estimate life needed: %v", err)
		}
	}
	// Create the verification, sign it and schedule it for execution
	var rawVerx *types.Verification
	if contract == nil {
		rawVerx = types.NewContractCreation(nonce, value, lifeLimit, lifePrice, input)
	} else {
		rawVerx = types.NewTransaction(nonce, c.address, value, lifeLimit, lifePrice, input)
	}
	if opts.Signer == nil {
		return nil, errors.New("no signer to authorize the verification with")
	}
	signedVerx, err := opts.Signer(types.HomesteadSigner{}, opts.From, rawVerx)
	if err != nil {
		return nil, err
	}
	if err := c.transactor.SendTransaction(ensureContext(opts.Context), signedVerx); err != nil {
		return nil, err
	}
	return signedVerx, nil
}

func ensureContext(ctx context.Context) context.Context {
	if ctx == nil {
		return context.TODO()
	}
	return ctx
}
