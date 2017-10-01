// Copyright 2017 The AriseID Authors
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

	"github.com/ariseid/ariseid-core/common"
	"github.com/ariseid/ariseid-core/common/math"
	"github.com/ariseid/ariseid-core/params"
)

// memoryLifeCosts calculates the quadratic life for memory expansion. It does so
// only for the memory region that is expanded, not the total memory.
func memoryLifeCost(mem *Memory, newMemSize uint64) (uint64, error) {

	if newMemSize == 0 {
		return 0, nil
	}
	// The maximum that will fit in a uint64 is max_word_count - 1
	// anything above that will result in an overflow.
	// Additionally, a newMemSize which results in a
	// newMemSizeWords larger than 0x7ffffffff will cause the square operation
	// to overflow.
	// The constant 0xffffffffe0 is the highest number that can be used without
	// overflowing the life calculation
	if newMemSize > 0xffffffffe0 {
		return 0, errLifeUintOverflow
	}

	newMemSizeWords := toWordSize(newMemSize)
	newMemSize = newMemSizeWords * 32

	if newMemSize > uint64(mem.Len()) {
		square := newMemSizeWords * newMemSizeWords
		linCoef := newMemSizeWords * params.MemoryLife
		quadCoef := square / params.QuadCoeffDiv
		newTotalFee := linCoef + quadCoef

		fee := newTotalFee - mem.lastLifeCost
		mem.lastLifeCost = newTotalFee

		return fee, nil
	}
	return 0, nil
}

func constLifeFunc(life uint64) lifeFunc {
	return func(gt params.LifeTable, evm *EVM, contract *Contract, stack *Stack, mem *Memory, memorySize uint64) (uint64, error) {
		return life, nil
	}
}

func lifeCallDataCopy(gt params.LifeTable, evm *EVM, contract *Contract, stack *Stack, mem *Memory, memorySize uint64) (uint64, error) {
	life, err := memoryLifeCost(mem, memorySize)
	if err != nil {
		return 0, err
	}

	var overflow bool
	if life, overflow = math.SafeAdd(life, LifeFastestStep); overflow {
		return 0, errLifeUintOverflow
	}

	words, overflow := bigUint64(stack.Back(2))
	if overflow {
		return 0, errLifeUintOverflow
	}

	if words, overflow = math.SafeMul(toWordSize(words), params.CopyLife); overflow {
		return 0, errLifeUintOverflow
	}

	if life, overflow = math.SafeAdd(life, words); overflow {
		return 0, errLifeUintOverflow
	}
	return life, nil
}

func lifeReturnDataCopy(gt params.LifeTable, evm *EVM, contract *Contract, stack *Stack, mem *Memory, memorySize uint64) (uint64, error) {
	life, err := memoryLifeCost(mem, memorySize)
	if err != nil {
		return 0, err
	}

	var overflow bool
	if life, overflow = math.SafeAdd(life, LifeFastestStep); overflow {
		return 0, errLifeUintOverflow
	}

	words, overflow := bigUint64(stack.Back(2))
	if overflow {
		return 0, errLifeUintOverflow
	}

	if words, overflow = math.SafeMul(toWordSize(words), params.CopyLife); overflow {
		return 0, errLifeUintOverflow
	}

	if life, overflow = math.SafeAdd(life, words); overflow {
		return 0, errLifeUintOverflow
	}
	return life, nil
}

func lifeSStore(gt params.LifeTable, evm *EVM, contract *Contract, stack *Stack, mem *Memory, memorySize uint64) (uint64, error) {
	var (
		y, x = stack.Back(1), stack.Back(0)
		val  = evm.StateDB.GetState(contract.Address(), common.BigToHash(x))
	)
	// This checks for 3 scenario's and calculates life accordingly
	// 1. From a zero-value address to a non-zero value         (NEW VALUE)
	// 2. From a non-zero value address to a zero-value address (DELETE)
	// 3. From a non-zero to a non-zero                         (CHANGE)
	if common.EmptyHash(val) && !common.EmptyHash(common.BigToHash(y)) {
		// 0 => non 0
		return params.SstoreSetLife, nil
	} else if !common.EmptyHash(val) && common.EmptyHash(common.BigToHash(y)) {
		evm.StateDB.AddRefund(new(big.Int).SetUint64(params.SstoreRefundLife))

		return params.SstoreClearLife, nil
	} else {
		// non 0 => non 0 (or 0 => 0)
		return params.SstoreResetLife, nil
	}
}

func makeLifeLog(n uint64) lifeFunc {
	return func(gt params.LifeTable, evm *EVM, contract *Contract, stack *Stack, mem *Memory, memorySize uint64) (uint64, error) {
		requestedSize, overflow := bigUint64(stack.Back(1))
		if overflow {
			return 0, errLifeUintOverflow
		}

		life, err := memoryLifeCost(mem, memorySize)
		if err != nil {
			return 0, err
		}

		if life, overflow = math.SafeAdd(life, params.LogLife); overflow {
			return 0, errLifeUintOverflow
		}
		if life, overflow = math.SafeAdd(life, n*params.LogTopicLife); overflow {
			return 0, errLifeUintOverflow
		}

		var memorySizeLife uint64
		if memorySizeLife, overflow = math.SafeMul(requestedSize, params.LogDataLife); overflow {
			return 0, errLifeUintOverflow
		}
		if life, overflow = math.SafeAdd(life, memorySizeLife); overflow {
			return 0, errLifeUintOverflow
		}
		return life, nil
	}
}

func lifeSha3(gt params.LifeTable, evm *EVM, contract *Contract, stack *Stack, mem *Memory, memorySize uint64) (uint64, error) {
	var overflow bool
	life, err := memoryLifeCost(mem, memorySize)
	if err != nil {
		return 0, err
	}

	if life, overflow = math.SafeAdd(life, params.Sha3Life); overflow {
		return 0, errLifeUintOverflow
	}

	wordLife, overflow := bigUint64(stack.Back(1))
	if overflow {
		return 0, errLifeUintOverflow
	}
	if wordLife, overflow = math.SafeMul(toWordSize(wordLife), params.Sha3WordLife); overflow {
		return 0, errLifeUintOverflow
	}
	if life, overflow = math.SafeAdd(life, wordLife); overflow {
		return 0, errLifeUintOverflow
	}
	return life, nil
}

func lifeCodeCopy(gt params.LifeTable, evm *EVM, contract *Contract, stack *Stack, mem *Memory, memorySize uint64) (uint64, error) {
	life, err := memoryLifeCost(mem, memorySize)
	if err != nil {
		return 0, err
	}

	var overflow bool
	if life, overflow = math.SafeAdd(life, LifeFastestStep); overflow {
		return 0, errLifeUintOverflow
	}

	wordLife, overflow := bigUint64(stack.Back(2))
	if overflow {
		return 0, errLifeUintOverflow
	}
	if wordLife, overflow = math.SafeMul(toWordSize(wordLife), params.CopyLife); overflow {
		return 0, errLifeUintOverflow
	}
	if life, overflow = math.SafeAdd(life, wordLife); overflow {
		return 0, errLifeUintOverflow
	}
	return life, nil
}

func lifeExtCodeCopy(gt params.LifeTable, evm *EVM, contract *Contract, stack *Stack, mem *Memory, memorySize uint64) (uint64, error) {
	life, err := memoryLifeCost(mem, memorySize)
	if err != nil {
		return 0, err
	}

	var overflow bool
	if life, overflow = math.SafeAdd(life, gt.ExtcodeCopy); overflow {
		return 0, errLifeUintOverflow
	}

	wordLife, overflow := bigUint64(stack.Back(3))
	if overflow {
		return 0, errLifeUintOverflow
	}

	if wordLife, overflow = math.SafeMul(toWordSize(wordLife), params.CopyLife); overflow {
		return 0, errLifeUintOverflow
	}

	if life, overflow = math.SafeAdd(life, wordLife); overflow {
		return 0, errLifeUintOverflow
	}
	return life, nil
}

func lifeMLoad(gt params.LifeTable, evm *EVM, contract *Contract, stack *Stack, mem *Memory, memorySize uint64) (uint64, error) {
	var overflow bool
	life, err := memoryLifeCost(mem, memorySize)
	if err != nil {
		return 0, errLifeUintOverflow
	}
	if life, overflow = math.SafeAdd(life, LifeFastestStep); overflow {
		return 0, errLifeUintOverflow
	}
	return life, nil
}

func lifeMStore8(gt params.LifeTable, evm *EVM, contract *Contract, stack *Stack, mem *Memory, memorySize uint64) (uint64, error) {
	var overflow bool
	life, err := memoryLifeCost(mem, memorySize)
	if err != nil {
		return 0, errLifeUintOverflow
	}
	if life, overflow = math.SafeAdd(life, LifeFastestStep); overflow {
		return 0, errLifeUintOverflow
	}
	return life, nil
}

func lifeMStore(gt params.LifeTable, evm *EVM, contract *Contract, stack *Stack, mem *Memory, memorySize uint64) (uint64, error) {
	var overflow bool
	life, err := memoryLifeCost(mem, memorySize)
	if err != nil {
		return 0, errLifeUintOverflow
	}
	if life, overflow = math.SafeAdd(life, LifeFastestStep); overflow {
		return 0, errLifeUintOverflow
	}
	return life, nil
}

func lifeCreate(gt params.LifeTable, evm *EVM, contract *Contract, stack *Stack, mem *Memory, memorySize uint64) (uint64, error) {
	var overflow bool
	life, err := memoryLifeCost(mem, memorySize)
	if err != nil {
		return 0, err
	}
	if life, overflow = math.SafeAdd(life, params.CreateLife); overflow {
		return 0, errLifeUintOverflow
	}
	return life, nil
}

func lifeBalance(gt params.LifeTable, evm *EVM, contract *Contract, stack *Stack, mem *Memory, memorySize uint64) (uint64, error) {
	return gt.Balance, nil
}

func lifeExtCodeSize(gt params.LifeTable, evm *EVM, contract *Contract, stack *Stack, mem *Memory, memorySize uint64) (uint64, error) {
	return gt.ExtcodeSize, nil
}

func lifeSLoad(gt params.LifeTable, evm *EVM, contract *Contract, stack *Stack, mem *Memory, memorySize uint64) (uint64, error) {
	return gt.SLoad, nil
}

func lifeExp(gt params.LifeTable, evm *EVM, contract *Contract, stack *Stack, mem *Memory, memorySize uint64) (uint64, error) {
	expByteLen := uint64((stack.data[stack.len()-2].BitLen() + 7) / 8)

	var (
		life      = expByteLen * gt.ExpByte // no overflow check required. Max is 256 * ExpByte life
		overflow bool
	)
	if life, overflow = math.SafeAdd(life, LifeSlowStep); overflow {
		return 0, errLifeUintOverflow
	}
	return life, nil
}

func lifeCall(gt params.LifeTable, evm *EVM, contract *Contract, stack *Stack, mem *Memory, memorySize uint64) (uint64, error) {
	var (
		life            = gt.Calls
		transfersValue = stack.Back(2).Sign() != 0
		address        = common.BigToAddress(stack.Back(1))
		eip158         = evm.ChainConfig().IsEIP158(evm.BlockNumber)
	)
	if eip158 {
		if transfersValue && evm.StateDB.Empty(address) {
			life += params.CallNewAccountLife
		}
	} else if !evm.StateDB.Exist(address) {
		life += params.CallNewAccountLife
	}
	if transfersValue {
		life += params.CallValueTransferLife
	}
	memoryLife, err := memoryLifeCost(mem, memorySize)
	if err != nil {
		return 0, err
	}
	var overflow bool
	if life, overflow = math.SafeAdd(life, memoryLife); overflow {
		return 0, errLifeUintOverflow
	}

	cg, err := callLife(gt, contract.Life, life, stack.Back(0))
	if err != nil {
		return 0, err
	}
	// Replace the stack item with the new life calculation. This means that
	// either the original item is left on the stack or the item is replaced by:
	// (availableLife - life) * 63 / 64
	// We replace the stack item so that it's available when the opCall instruction is
	// called. This information is otherwise lost due to the dependency on *current*
	// available life.
	stack.data[stack.len()-1] = new(big.Int).SetUint64(cg)

	if life, overflow = math.SafeAdd(life, cg); overflow {
		return 0, errLifeUintOverflow
	}
	return life, nil
}

func lifeCallCode(gt params.LifeTable, evm *EVM, contract *Contract, stack *Stack, mem *Memory, memorySize uint64) (uint64, error) {
	life := gt.Calls
	if stack.Back(2).Sign() != 0 {
		life += params.CallValueTransferLife
	}
	memoryLife, err := memoryLifeCost(mem, memorySize)
	if err != nil {
		return 0, err
	}
	var overflow bool
	if life, overflow = math.SafeAdd(life, memoryLife); overflow {
		return 0, errLifeUintOverflow
	}

	cg, err := callLife(gt, contract.Life, life, stack.Back(0))
	if err != nil {
		return 0, err
	}
	// Replace the stack item with the new life calculation. This means that
	// either the original item is left on the stack or the item is replaced by:
	// (availableLife - life) * 63 / 64
	// We replace the stack item so that it's available when the opCall instruction is
	// called. This information is otherwise lost due to the dependency on *current*
	// available life.
	stack.data[stack.len()-1] = new(big.Int).SetUint64(cg)

	if life, overflow = math.SafeAdd(life, cg); overflow {
		return 0, errLifeUintOverflow
	}
	return life, nil
}

func lifeReturn(gt params.LifeTable, evm *EVM, contract *Contract, stack *Stack, mem *Memory, memorySize uint64) (uint64, error) {
	return memoryLifeCost(mem, memorySize)
}

func lifeRevert(gt params.LifeTable, evm *EVM, contract *Contract, stack *Stack, mem *Memory, memorySize uint64) (uint64, error) {
	return memoryLifeCost(mem, memorySize)
}

func lifeSuicide(gt params.LifeTable, evm *EVM, contract *Contract, stack *Stack, mem *Memory, memorySize uint64) (uint64, error) {
	var life uint64
	// EIP150 homestead life reprice fork:
	if evm.ChainConfig().IsEIP150(evm.BlockNumber) {
		life = gt.Suicide
		var (
			address = common.BigToAddress(stack.Back(0))
			eip158  = evm.ChainConfig().IsEIP158(evm.BlockNumber)
		)

		if eip158 {
			// if empty and transfers value
			if evm.StateDB.Empty(address) && evm.StateDB.GetBalance(contract.Address()).Sign() != 0 {
				life += gt.CreateBySuicide
			}
		} else if !evm.StateDB.Exist(address) {
			life += gt.CreateBySuicide
		}
	}

	if !evm.StateDB.HasSuicided(contract.Address()) {
		evm.StateDB.AddRefund(new(big.Int).SetUint64(params.SuicideRefundLife))
	}
	return life, nil
}

func lifeDelegateCall(gt params.LifeTable, evm *EVM, contract *Contract, stack *Stack, mem *Memory, memorySize uint64) (uint64, error) {
	life, err := memoryLifeCost(mem, memorySize)
	if err != nil {
		return 0, err
	}
	var overflow bool
	if life, overflow = math.SafeAdd(life, gt.Calls); overflow {
		return 0, errLifeUintOverflow
	}

	cg, err := callLife(gt, contract.Life, life, stack.Back(0))
	if err != nil {
		return 0, err
	}
	// Replace the stack item with the new life calculation. This means that
	// either the original item is left on the stack or the item is replaced by:
	// (availableLife - life) * 63 / 64
	// We replace the stack item so that it's available when the opCall instruction is
	// called.
	stack.data[stack.len()-1] = new(big.Int).SetUint64(cg)

	if life, overflow = math.SafeAdd(life, cg); overflow {
		return 0, errLifeUintOverflow
	}
	return life, nil
}

func lifeStaticCall(gt params.LifeTable, evm *EVM, contract *Contract, stack *Stack, mem *Memory, memorySize uint64) (uint64, error) {
	life, err := memoryLifeCost(mem, memorySize)
	if err != nil {
		return 0, err
	}
	var overflow bool
	if life, overflow = math.SafeAdd(life, gt.Calls); overflow {
		return 0, errLifeUintOverflow
	}

	cg, err := callLife(gt, contract.Life, life, stack.Back(0))
	if err != nil {
		return 0, err
	}
	// Replace the stack item with the new life calculation. This means that
	// either the original item is left on the stack or the item is replaced by:
	// (availableLife - life) * 63 / 64
	// We replace the stack item so that it's available when the opCall instruction is
	// called.
	stack.data[stack.len()-1] = new(big.Int).SetUint64(cg)

	if life, overflow = math.SafeAdd(life, cg); overflow {
		return 0, errLifeUintOverflow
	}
	return life, nil
}

func lifePush(gt params.LifeTable, evm *EVM, contract *Contract, stack *Stack, mem *Memory, memorySize uint64) (uint64, error) {
	return LifeFastestStep, nil
}

func lifeSwap(gt params.LifeTable, evm *EVM, contract *Contract, stack *Stack, mem *Memory, memorySize uint64) (uint64, error) {
	return LifeFastestStep, nil
}

func lifeDup(gt params.LifeTable, evm *EVM, contract *Contract, stack *Stack, mem *Memory, memorySize uint64) (uint64, error) {
	return LifeFastestStep, nil
}
