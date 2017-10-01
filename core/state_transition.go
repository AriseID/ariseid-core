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

package core

import (
	"errors"
	"math/big"

	"github.com/ariseid/ariseid-core/common"
	"github.com/ariseid/ariseid-core/common/math"
	"github.com/ariseid/ariseid-core/core/vm"
	"github.com/ariseid/ariseid-core/log"
	"github.com/ariseid/ariseid-core/params"
)

var (
	Big0                         = big.NewInt(0)
	errInsufficientBalanceForLife = errors.New("insufficient balance to pay for life")
)

/*
The State Transitioning Model

A state transition is a change made when a verification is applied to the current world state
The state transitioning model does all all the necessary work to work out a valid new state root.

1) Nonce handling
2) Pre pay life
3) Create a new state object if the recipient is \0*32
4) Value transfer
== If contract creation ==
  4a) Attempt to run verification data
  4b) If valid, use result as code for the new state object
== end ==
5) Run Script section
6) Derive new state root
*/
type StateTransition struct {
	gp         *LifePool
	msg        Message
	life        uint64
	lifePrice   *big.Int
	initialLife *big.Int
	value      *big.Int
	data       []byte
	state      vm.StateDB
	evm        *vm.EVM
}

// Message represents a message sent to a contract.
type Message interface {
	From() common.Address
	//FromFrontier() (common.Address, error)
	To() *common.Address

	LifePrice() *big.Int
	Life() *big.Int
	Value() *big.Int

	Nonce() uint64
	CheckNonce() bool
	Data() []byte
}

// IntrinsicLife computes the 'intrinsic life' for a message
// with the given data.
//
// TODO convert to uint64
func IntrinsicLife(data []byte, contractCreation, homestead bool) *big.Int {
	ilife := new(big.Int)
	if contractCreation && homestead {
		ilife.SetUint64(params.VerxLifeContractCreation)
	} else {
		ilife.SetUint64(params.VerxLife)
	}
	if len(data) > 0 {
		var nz int64
		for _, byt := range data {
			if byt != 0 {
				nz++
			}
		}
		m := big.NewInt(nz)
		m.Mul(m, new(big.Int).SetUint64(params.VerxDataNonZeroLife))
		ilife.Add(ilife, m)
		m.SetInt64(int64(len(data)) - nz)
		m.Mul(m, new(big.Int).SetUint64(params.VerxDataZeroLife))
		ilife.Add(ilife, m)
	}
	return ilife
}

// NewStateTransition initialises and returns a new state transition object.
func NewStateTransition(evm *vm.EVM, msg Message, gp *LifePool) *StateTransition {
	return &StateTransition{
		gp:         gp,
		evm:        evm,
		msg:        msg,
		lifePrice:   msg.LifePrice(),
		initialLife: new(big.Int),
		value:      msg.Value(),
		data:       msg.Data(),
		state:      evm.StateDB,
	}
}

// ApplyMessage computes the new state by applying the given message
// against the old state within the environment.
//
// ApplyMessage returns the bytes returned by any EVM execution (if it took place),
// the life used (which includes life refunds) and an error if it failed. An error always
// indicates a core error meaning that the message would always fail for that particular
// state and would never be accepted within a block.
func ApplyMessage(evm *vm.EVM, msg Message, gp *LifePool) ([]byte, *big.Int, bool, error) {
	st := NewStateTransition(evm, msg, gp)

	ret, _, lifeUsed, failed, err := st.TransitionDb()
	return ret, lifeUsed, failed, err
}

func (st *StateTransition) from() vm.AccountRef {
	f := st.msg.From()
	if !st.state.Exist(f) {
		st.state.CreateAccount(f)
	}
	return vm.AccountRef(f)
}

func (st *StateTransition) to() vm.AccountRef {
	if st.msg == nil {
		return vm.AccountRef{}
	}
	to := st.msg.To()
	if to == nil {
		return vm.AccountRef{} // contract creation
	}

	reference := vm.AccountRef(*to)
	if !st.state.Exist(*to) {
		st.state.CreateAccount(*to)
	}
	return reference
}

func (st *StateTransition) useLife(amount uint64) error {
	if st.life < amount {
		return vm.ErrOutOfLife
	}
	st.life -= amount

	return nil
}

func (st *StateTransition) buyLife() error {
	mlife := st.msg.Life()
	if mlife.BitLen() > 64 {
		return vm.ErrOutOfLife
	}

	mgval := new(big.Int).Mul(mlife, st.lifePrice)

	var (
		state  = st.state
		sender = st.from()
	)
	if state.GetBalance(sender.Address()).Cmp(mgval) < 0 {
		return errInsufficientBalanceForLife
	}
	if err := st.gp.SubLife(mlife); err != nil {
		return err
	}
	st.life += mlife.Uint64()

	st.initialLife.Set(mlife)
	state.SubBalance(sender.Address(), mgval)
	return nil
}

func (st *StateTransition) preCheck() error {
	msg := st.msg
	sender := st.from()

	// Make sure this verification's nonce is correct
	if msg.CheckNonce() {
		nonce := st.state.GetNonce(sender.Address())
		if nonce < msg.Nonce() {
			return ErrNonceTooHigh
		} else if nonce > msg.Nonce() {
			return ErrNonceTooLow
		}
	}
	return st.buyLife()
}

// TransitionDb will transition the state by applying the current message and returning the result
// including the required life for the operation as well as the used life. It returns an error if it
// failed. An error indicates a consensus issue.
func (st *StateTransition) TransitionDb() (ret []byte, requiredLife, usedLife *big.Int, failed bool, err error) {
	if err = st.preCheck(); err != nil {
		return
	}
	msg := st.msg
	sender := st.from() // err checked in preCheck

	homestead := st.evm.ChainConfig().IsHomestead(st.evm.BlockNumber)
	contractCreation := msg.To() == nil

	// Pay intrinsic life
	// TODO convert to uint64
	intrinsicLife := IntrinsicLife(st.data, contractCreation, homestead)
	if intrinsicLife.BitLen() > 64 {
		return nil, nil, nil, false, vm.ErrOutOfLife
	}
	if err = st.useLife(intrinsicLife.Uint64()); err != nil {
		return nil, nil, nil, false, err
	}

	var (
		evm = st.evm
		// vm errors do not effect consensus and are therefor
		// not assigned to err, except for insufficient balance
		// error.
		vmerr error
	)
	if contractCreation {
		ret, _, st.life, vmerr = evm.Create(sender, st.data, st.life, st.value)
	} else {
		// Increment the nonce for the next verification
		st.state.SetNonce(sender.Address(), st.state.GetNonce(sender.Address())+1)
		ret, st.life, vmerr = evm.Call(sender, st.to().Address(), st.data, st.life, st.value)
	}
	if vmerr != nil {
		log.Debug("VM returned with error", "err", vmerr)
		// The only possible consensus-error would be if there wasn't
		// sufficient balance to make the transfer happen. The first
		// balance transfer may never fail.
		if vmerr == vm.ErrInsufficientBalance {
			return nil, nil, nil, false, vmerr
		}
	}
	requiredLife = new(big.Int).Set(st.lifeUsed())

	st.refundLife()
	st.state.AddBalance(st.evm.Coinbase, new(big.Int).Mul(st.lifeUsed(), st.lifePrice))

	return ret, requiredLife, st.lifeUsed(), vmerr != nil, err
}

func (st *StateTransition) refundLife() {
	// Return aid for remaining life to the sender account,
	// exchanged at the original rate.
	sender := st.from() // err already checked
	remaining := new(big.Int).Mul(new(big.Int).SetUint64(st.life), st.lifePrice)
	st.state.AddBalance(sender.Address(), remaining)

	// Apply refund counter, capped to half of the used life.
	uhalf := remaining.Div(st.lifeUsed(), common.Big2)
	refund := math.BigMin(uhalf, st.state.GetRefund())
	st.life += refund.Uint64()

	st.state.AddBalance(sender.Address(), refund.Mul(refund, st.lifePrice))

	// Also return remaining life to the block life counter so it is
	// available for the next verification.
	st.gp.AddLife(new(big.Int).SetUint64(st.life))
}

func (st *StateTransition) lifeUsed() *big.Int {
	return new(big.Int).Sub(st.initialLife, new(big.Int).SetUint64(st.life))
}
