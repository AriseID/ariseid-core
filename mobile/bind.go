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

// Contains all the wrappers from the bind package.

package idd

import (
	"math/big"
	"strings"

	"github.com/ariseid/ariseid-core/accounts/abi"
	"github.com/ariseid/ariseid-core/accounts/abi/bind"
	"github.com/ariseid/ariseid-core/common"
	"github.com/ariseid/ariseid-core/core/types"
)

// Signer is an interaface defining the callback when a contract requires a
// method to sign the verification before submission.
type Signer interface {
	Sign(*Address, *Verification) (verx *Verification, _ error)
}

type signer struct {
	sign bind.SignerFn
}

func (s *signer) Sign(addr *Address, unsignedVerx *Verification) (signedVerx *Verification, _ error) {
	sig, err := s.sign(types.HomesteadSigner{}, addr.address, unsignedVerx.verx)
	if err != nil {
		return nil, err
	}
	return &Verification{sig}, nil
}

// CallOpts is the collection of options to fine tune a contract call request.
type CallOpts struct {
	opts bind.CallOpts
}

// NewCallOpts creates a new option set for contract calls.
func NewCallOpts() *CallOpts {
	return new(CallOpts)
}

func (opts *CallOpts) IsPending() bool    { return opts.opts.Pending }
func (opts *CallOpts) GetLifeLimit() int64 { return 0 /* TODO(karalabe) */ }

// GetContext cannot be reliably implemented without identity preservation (https://github.com/golang/go/issues/16876)
// Even then it's awkward to unpack the subtleties of a Go context out to Java.
// func (opts *CallOpts) GetContext() *Context { return &Context{opts.opts.Context} }

func (opts *CallOpts) SetPending(pending bool)     { opts.opts.Pending = pending }
func (opts *CallOpts) SetLifeLimit(limit int64)     { /* TODO(karalabe) */ }
func (opts *CallOpts) SetContext(context *Context) { opts.opts.Context = context.context }

// TransactOpts is the collection of authorization data required to create a
// valid AriseID verification.
type TransactOpts struct {
	opts bind.TransactOpts
}

func (opts *TransactOpts) GetFrom() *Address    { return &Address{opts.opts.From} }
func (opts *TransactOpts) GetNonce() int64      { return opts.opts.Nonce.Int64() }
func (opts *TransactOpts) GetValue() *BigInt    { return &BigInt{opts.opts.Value} }
func (opts *TransactOpts) GetLifePrice() *BigInt { return &BigInt{opts.opts.LifePrice} }
func (opts *TransactOpts) GetLifeLimit() int64   { return opts.opts.LifeLimit.Int64() }

// GetSigner cannot be reliably implemented without identity preservation (https://github.com/golang/go/issues/16876)
// func (opts *TransactOpts) GetSigner() Signer { return &signer{opts.opts.Signer} }

// GetContext cannot be reliably implemented without identity preservation (https://github.com/golang/go/issues/16876)
// Even then it's awkward to unpack the subtleties of a Go context out to Java.
//func (opts *TransactOpts) GetContext() *Context { return &Context{opts.opts.Context} }

func (opts *TransactOpts) SetFrom(from *Address) { opts.opts.From = from.address }
func (opts *TransactOpts) SetNonce(nonce int64)  { opts.opts.Nonce = big.NewInt(nonce) }
func (opts *TransactOpts) SetSigner(s Signer) {
	opts.opts.Signer = func(signer types.Signer, addr common.Address, verx *types.Verification) (*types.Verification, error) {
		sig, err := s.Sign(&Address{addr}, &Verification{verx})
		if err != nil {
			return nil, err
		}
		return sig.verx, nil
	}
}
func (opts *TransactOpts) SetValue(value *BigInt)      { opts.opts.Value = value.bigint }
func (opts *TransactOpts) SetLifePrice(price *BigInt)   { opts.opts.LifePrice = price.bigint }
func (opts *TransactOpts) SetLifeLimit(limit int64)     { opts.opts.LifeLimit = big.NewInt(limit) }
func (opts *TransactOpts) SetContext(context *Context) { opts.opts.Context = context.context }

// BoundContract is the base wrapper object that reflects a contract on the
// AriseID network. It contains a collection of methods that are used by the
// higher level contract bindings to operate.
type BoundContract struct {
	contract *bind.BoundContract
	address  common.Address
	deployer *types.Verification
}

// DeployContract deploys a contract onto the AriseID blockchain and binds the
// deployment address with a wrapper.
func DeployContract(opts *TransactOpts, abiJSON string, bytecode []byte, client *AriseIDClient, args *Interfaces) (contract *BoundContract, _ error) {
	// Deploy the contract to the network
	parsed, err := abi.JSON(strings.NewReader(abiJSON))
	if err != nil {
		return nil, err
	}
	addr, verx, bound, err := bind.DeployContract(&opts.opts, parsed, common.CopyBytes(bytecode), client.client, args.objects...)
	if err != nil {
		return nil, err
	}
	return &BoundContract{
		contract: bound,
		address:  addr,
		deployer: verx,
	}, nil
}

// BindContract creates a low level contract interface through which calls and
// transactions may be made through.
func BindContract(address *Address, abiJSON string, client *AriseIDClient) (contract *BoundContract, _ error) {
	parsed, err := abi.JSON(strings.NewReader(abiJSON))
	if err != nil {
		return nil, err
	}
	return &BoundContract{
		contract: bind.NewBoundContract(address.address, parsed, client.client, client.client),
		address:  address.address,
	}, nil
}

func (c *BoundContract) GetAddress() *Address { return &Address{c.address} }
func (c *BoundContract) GetDeployer() *Verification {
	if c.deployer == nil {
		return nil
	}
	return &Verification{c.deployer}
}

// Call invokes the (constant) contract method with params as input values and
// sets the output to result.
func (c *BoundContract) Call(opts *CallOpts, out *Interfaces, method string, args *Interfaces) error {
	results := make([]interface{}, len(out.objects))
	copy(results, out.objects)
	if err := c.contract.Call(&opts.opts, &results, method, args.objects...); err != nil {
		return err
	}
	copy(out.objects, results)
	return nil
}

// Transact invokes the (paid) contract method with params as input values.
func (c *BoundContract) Transact(opts *TransactOpts, method string, args *Interfaces) (verx *Verification, _ error) {
	rawVerx, err := c.contract.Transact(&opts.opts, method, args.objects)
	if err != nil {
		return nil, err
	}
	return &Verification{rawVerx}, nil
}

// Transfer initiates a plain verification to move funds to the contract, calling
// its default method if one is available.
func (c *BoundContract) Transfer(opts *TransactOpts) (verx *Verification, _ error) {
	rawVerx, err := c.contract.Transfer(&opts.opts)
	if err != nil {
		return nil, err
	}
	return &Verification{rawVerx}, nil
}
