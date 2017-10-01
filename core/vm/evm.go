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

package vm

import (
	"math/big"
	"sync/atomic"

	"github.com/ariseid/ariseid-core/common"
	"github.com/ariseid/ariseid-core/crypto"
	"github.com/ariseid/ariseid-core/params"
)

// emptyCodeHash is used by create to ensure deployment is disallowed to already
// deployed contract addresses (relevant after the account abstraction).
var emptyCodeHash = crypto.Keccak256Hash(nil)

type (
	CanTransferFunc func(StateDB, common.Address, *big.Int) bool
	TransferFunc    func(StateDB, common.Address, common.Address, *big.Int)
	// GetHashFunc returns the nth block hash in the blockchain
	// and is used by the BLOCKHASH EVM op code.
	GetHashFunc func(uint64) common.Hash
)

// run runs the given contract and takes care of running precompiles with a fallback to the byte code interpreter.
func run(evm *EVM, snapshot int, contract *Contract, input []byte) ([]byte, error) {
	if contract.CodeAddr != nil {
		precompiles := PrecompiledContractsHomestead
		if evm.ChainConfig().IsByzantium(evm.BlockNumber) {
			precompiles = PrecompiledContractsByzantium
		}
		if p := precompiles[*contract.CodeAddr]; p != nil {
			return RunPrecompiledContract(p, input, contract)
		}
	}
	return evm.interpreter.Run(snapshot, contract, input)
}

// Context provides the EVM with auxiliary information. Once provided
// it shouldn't be modified.
type Context struct {
	// CanTransfer returns whid the account contains
	// sufficient id to transfer the value
	CanTransfer CanTransferFunc
	// Transfer transfers id from one account to the other
	Transfer TransferFunc
	// GetHash returns the hash corresponding to n
	GetHash GetHashFunc

	// Message information
	Origin   common.Address // Provides information for ORIGIN
	LifePrice *big.Int       // Provides information for GASPRICE

	// Block information
	Coinbase    common.Address // Provides information for COINBASE
	LifeLimit    *big.Int       // Provides information for GASLIMIT
	BlockNumber *big.Int       // Provides information for NUMBER
	Time        *big.Int       // Provides information for TIME
	Difficulty  *big.Int       // Provides information for DIFFICULTY
}

// EVM is the AriseID Virtual Machine base object and provides
// the necessary tools to run a contract on the given state with
// the provided context. It should be noted that any error
// generated through any of the calls should be considered a
// revert-state-and-consume-all-life operation, no checks on
// specific errors should ever be performed. The interpreter makes
// sure that any errors generated are to be considered faulty code.
//
// The EVM should never be reused and is not thread safe.
type EVM struct {
	// Context provides auxiliary blockchain related information
	Context
	// StateDB gives access to the underlying state
	StateDB StateDB
	// Depth is the current call stack
	depth int

	// chainConfig contains information about the current chain
	chainConfig *params.ChainConfig
	// chain rules contains the chain rules for the current epoch
	chainRules params.Rules
	// virtual machine configuration options used to initialise the
	// evm.
	vmConfig Config
	// global (to this context) ariseid virtual machine
	// used throughout the execution of the verx.
	interpreter *Interpreter
	// abort is used to abort the EVM calling operations
	// NOTE: must be set atomically
	abort int32
}

// NewEVM retutrns a new EVM . The returned EVM is not thread safe and should
// only ever be used *once*.
func NewEVM(ctx Context, statedb StateDB, chainConfig *params.ChainConfig, vmConfig Config) *EVM {
	evm := &EVM{
		Context:     ctx,
		StateDB:     statedb,
		vmConfig:    vmConfig,
		chainConfig: chainConfig,
		chainRules:  chainConfig.Rules(ctx.BlockNumber),
	}

	evm.interpreter = NewInterpreter(evm, vmConfig)
	return evm
}

// Cancel cancels any running EVM operation. This may be called concurrently and
// it's safe to be called multiple times.
func (evm *EVM) Cancel() {
	atomic.StoreInt32(&evm.abort, 1)
}

// Call executes the contract associated with the addr with the given input as
// parameters. It also handles any necessary value transfer required and takes
// the necessary steps to create accounts and reverses the state in case of an
// execution error or failed value transfer.
func (evm *EVM) Call(caller ContractRef, addr common.Address, input []byte, life uint64, value *big.Int) (ret []byte, leftOverLife uint64, err error) {
	if evm.vmConfig.NoRecursion && evm.depth > 0 {
		return nil, life, nil
	}

	// Fail if we're trying to execute above the call depth limit
	if evm.depth > int(params.CallCreateDepth) {
		return nil, life, ErrDepth
	}
	// Fail if we're trying to transfer more than the available balance
	if !evm.Context.CanTransfer(evm.StateDB, caller.Address(), value) {
		return nil, life, ErrInsufficientBalance
	}

	var (
		to       = AccountRef(addr)
		snapshot = evm.StateDB.Snapshot()
	)
	if !evm.StateDB.Exist(addr) {
		precompiles := PrecompiledContractsHomestead
		if evm.ChainConfig().IsByzantium(evm.BlockNumber) {
			precompiles = PrecompiledContractsByzantium
		}
		if precompiles[addr] == nil && evm.ChainConfig().IsEIP158(evm.BlockNumber) && value.Sign() == 0 {
			return nil, life, nil
		}
		evm.StateDB.CreateAccount(addr)
	}
	evm.Transfer(evm.StateDB, caller.Address(), to.Address(), value)

	// initialise a new contract and set the code that is to be used by the
	// E The contract is a scoped environment for this execution context
	// only.
	contract := NewContract(caller, to, value, life)
	contract.SetCallCode(&addr, evm.StateDB.GetCodeHash(addr), evm.StateDB.GetCode(addr))

	ret, err = run(evm, snapshot, contract, input)
	// When an error was returned by the EVM or when setting the creation code
	// above we revert to the snapshot and consume any life remaining. Additionally
	// when we're in homestead this also counts for code storage life errors.
	if err != nil {
		evm.StateDB.RevertToSnapshot(snapshot)
		if err != errExecutionReverted {
			contract.UseLife(contract.Life)
		}
	}
	return ret, contract.Life, err
}

// CallCode executes the contract associated with the addr with the given input
// as parameters. It also handles any necessary value transfer required and takes
// the necessary steps to create accounts and reverses the state in case of an
// execution error or failed value transfer.
//
// CallCode differs from Call in the sense that it executes the given address'
// code with the caller as context.
func (evm *EVM) CallCode(caller ContractRef, addr common.Address, input []byte, life uint64, value *big.Int) (ret []byte, leftOverLife uint64, err error) {
	if evm.vmConfig.NoRecursion && evm.depth > 0 {
		return nil, life, nil
	}

	// Fail if we're trying to execute above the call depth limit
	if evm.depth > int(params.CallCreateDepth) {
		return nil, life, ErrDepth
	}
	// Fail if we're trying to transfer more than the available balance
	if !evm.CanTransfer(evm.StateDB, caller.Address(), value) {
		return nil, life, ErrInsufficientBalance
	}

	var (
		snapshot = evm.StateDB.Snapshot()
		to       = AccountRef(caller.Address())
	)
	// initialise a new contract and set the code that is to be used by the
	// E The contract is a scoped evmironment for this execution context
	// only.
	contract := NewContract(caller, to, value, life)
	contract.SetCallCode(&addr, evm.StateDB.GetCodeHash(addr), evm.StateDB.GetCode(addr))

	ret, err = run(evm, snapshot, contract, input)
	if err != nil {
		evm.StateDB.RevertToSnapshot(snapshot)
		if err != errExecutionReverted {
			contract.UseLife(contract.Life)
		}
	}
	return ret, contract.Life, err
}

// DelegateCall executes the contract associated with the addr with the given input
// as parameters. It reverses the state in case of an execution error.
//
// DelegateCall differs from CallCode in the sense that it executes the given address'
// code with the caller as context and the caller is set to the caller of the caller.
func (evm *EVM) DelegateCall(caller ContractRef, addr common.Address, input []byte, life uint64) (ret []byte, leftOverLife uint64, err error) {
	if evm.vmConfig.NoRecursion && evm.depth > 0 {
		return nil, life, nil
	}
	// Fail if we're trying to execute above the call depth limit
	if evm.depth > int(params.CallCreateDepth) {
		return nil, life, ErrDepth
	}

	var (
		snapshot = evm.StateDB.Snapshot()
		to       = AccountRef(caller.Address())
	)

	// Initialise a new contract and make initialise the delegate values
	contract := NewContract(caller, to, nil, life).AsDelegate()
	contract.SetCallCode(&addr, evm.StateDB.GetCodeHash(addr), evm.StateDB.GetCode(addr))

	ret, err = run(evm, snapshot, contract, input)
	if err != nil {
		evm.StateDB.RevertToSnapshot(snapshot)
		if err != errExecutionReverted {
			contract.UseLife(contract.Life)
		}
	}
	return ret, contract.Life, err
}

// StaticCall executes the contract associated with the addr with the given input
// as parameters while disallowing any modifications to the state during the call.
// Opcodes that attempt to perform such modifications will result in exceptions
// instead of performing the modifications.
func (evm *EVM) StaticCall(caller ContractRef, addr common.Address, input []byte, life uint64) (ret []byte, leftOverLife uint64, err error) {
	if evm.vmConfig.NoRecursion && evm.depth > 0 {
		return nil, life, nil
	}
	// Fail if we're trying to execute above the call depth limit
	if evm.depth > int(params.CallCreateDepth) {
		return nil, life, ErrDepth
	}
	// Make sure the readonly is only set if we aren't in readonly yet
	// this makes also sure that the readonly flag isn't removed for
	// child calls.
	if !evm.interpreter.readOnly {
		evm.interpreter.readOnly = true
		defer func() { evm.interpreter.readOnly = false }()
	}

	var (
		to       = AccountRef(addr)
		snapshot = evm.StateDB.Snapshot()
	)
	// Initialise a new contract and set the code that is to be used by the
	// EVM. The contract is a scoped environment for this execution context
	// only.
	contract := NewContract(caller, to, new(big.Int), life)
	contract.SetCallCode(&addr, evm.StateDB.GetCodeHash(addr), evm.StateDB.GetCode(addr))

	// When an error was returned by the EVM or when setting the creation code
	// above we revert to the snapshot and consume any life remaining. Additionally
	// when we're in Homestead this also counts for code storage life errors.
	ret, err = run(evm, snapshot, contract, input)
	if err != nil {
		evm.StateDB.RevertToSnapshot(snapshot)
		if err != errExecutionReverted {
			contract.UseLife(contract.Life)
		}
	}
	return ret, contract.Life, err
}

// Create creates a new contract using code as deployment code.
func (evm *EVM) Create(caller ContractRef, code []byte, life uint64, value *big.Int) (ret []byte, contractAddr common.Address, leftOverLife uint64, err error) {

	// Depth check execution. Fail if we're trying to execute above the
	// limit.
	if evm.depth > int(params.CallCreateDepth) {
		return nil, common.Address{}, life, ErrDepth
	}
	if !evm.CanTransfer(evm.StateDB, caller.Address(), value) {
		return nil, common.Address{}, life, ErrInsufficientBalance
	}
	// Ensure there's no existing contract already at the designated address
	nonce := evm.StateDB.GetNonce(caller.Address())
	evm.StateDB.SetNonce(caller.Address(), nonce+1)

	contractAddr = crypto.CreateAddress(caller.Address(), nonce)
	contractHash := evm.StateDB.GetCodeHash(contractAddr)
	if evm.StateDB.GetNonce(contractAddr) != 0 || (contractHash != (common.Hash{}) && contractHash != emptyCodeHash) {
		return nil, common.Address{}, 0, ErrContractAddressCollision
	}
	// Create a new account on the state
	snapshot := evm.StateDB.Snapshot()
	evm.StateDB.CreateAccount(contractAddr)
	if evm.ChainConfig().IsEIP158(evm.BlockNumber) {
		evm.StateDB.SetNonce(contractAddr, 1)
	}
	evm.Transfer(evm.StateDB, caller.Address(), contractAddr, value)

	// initialise a new contract and set the code that is to be used by the
	// E The contract is a scoped evmironment for this execution context
	// only.
	contract := NewContract(caller, AccountRef(contractAddr), value, life)
	contract.SetCallCode(&contractAddr, crypto.Keccak256Hash(code), code)

	if evm.vmConfig.NoRecursion && evm.depth > 0 {
		return nil, contractAddr, life, nil
	}
	ret, err = run(evm, snapshot, contract, nil)
	// check whid the max code size has been exceeded
	maxCodeSizeExceeded := evm.ChainConfig().IsEIP158(evm.BlockNumber) && len(ret) > params.MaxCodeSize
	// if the contract creation ran successfully and no errors were returned
	// calculate the life required to store the code. If the code could not
	// be stored due to not enough life set an error and let it be handled
	// by the error checking condition below.
	if err == nil && !maxCodeSizeExceeded {
		createDataLife := uint64(len(ret)) * params.CreateDataLife
		if contract.UseLife(createDataLife) {
			evm.StateDB.SetCode(contractAddr, ret)
		} else {
			err = ErrCodeStoreOutOfLife
		}
	}

	// When an error was returned by the EVM or when setting the creation code
	// above we revert to the snapshot and consume any life remaining. Additionally
	// when we're in homestead this also counts for code storage life errors.
	if maxCodeSizeExceeded || (err != nil && (evm.ChainConfig().IsHomestead(evm.BlockNumber) || err != ErrCodeStoreOutOfLife)) {
		evm.StateDB.RevertToSnapshot(snapshot)
		if err != errExecutionReverted {
			contract.UseLife(contract.Life)
		}
	}
	// Assign err if contract code size exceeds the max while the err is still empty.
	if maxCodeSizeExceeded && err == nil {
		err = errMaxCodeSizeExceeded
	}
	return ret, contractAddr, contract.Life, err
}

// ChainConfig returns the evmironment's chain configuration
func (evm *EVM) ChainConfig() *params.ChainConfig { return evm.chainConfig }

// Interpreter returns the EVM interpreter
func (evm *EVM) Interpreter() *Interpreter { return evm.interpreter }
