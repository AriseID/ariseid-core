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

package vm

import (
	"errors"
	"math/big"

	"github.com/ariseid/ariseid-core/params"
)

type (
	executionFunc       func(pc *uint64, env *EVM, contract *Contract, memory *Memory, stack *Stack) ([]byte, error)
	lifeFunc             func(params.LifeTable, *EVM, *Contract, *Stack, *Memory, uint64) (uint64, error) // last parameter is the requested memory size as a uint64
	stackValidationFunc func(*Stack) error
	memorySizeFunc      func(*Stack) *big.Int
)

var errLifeUintOverflow = errors.New("life uint64 overflow")

type operation struct {
	// op is the operation function
	execute executionFunc
	// lifeCost is the life function and returns the life required for execution
	lifeCost lifeFunc
	// validateStack validates the stack (size) for the operation
	validateStack stackValidationFunc
	// memorySize returns the memory size required for the operation
	memorySize memorySizeFunc

	halts   bool // indicates whid the operation shoult halt further execution
	jumps   bool // indicates whid the program counter should not increment
	writes  bool // determines whid this a state modifying operation
	valid   bool // indication whid the retrieved operation is valid and known
	reverts bool // determines whid the operation reverts state (implicitly halts)
	returns bool // determines whid the opertions sets the return data content
}

var (
	frontierInstructionSet  = NewFrontierInstructionSet()
	homesteadInstructionSet = NewHomesteadInstructionSet()
	byzantiumInstructionSet = NewByzantiumInstructionSet()
)

// NewByzantiumInstructionSet returns the frontier, homestead and
// byzantium instructions.
func NewByzantiumInstructionSet() [256]operation {
	// instructions that can be executed during the homestead phase.
	instructionSet := NewHomesteadInstructionSet()
	instructionSet[STATICCALL] = operation{
		execute:       opStaticCall,
		lifeCost:       lifeStaticCall,
		validateStack: makeStackFunc(6, 1),
		memorySize:    memoryStaticCall,
		valid:         true,
		returns:       true,
	}
	instructionSet[RETURNDATASIZE] = operation{
		execute:       opReturnDataSize,
		lifeCost:       constLifeFunc(LifeQuickStep),
		validateStack: makeStackFunc(0, 1),
		valid:         true,
	}
	instructionSet[RETURNDATACOPY] = operation{
		execute:       opReturnDataCopy,
		lifeCost:       lifeReturnDataCopy,
		validateStack: makeStackFunc(3, 0),
		memorySize:    memoryReturnDataCopy,
		valid:         true,
	}
	instructionSet[REVERT] = operation{
		execute:       opRevert,
		lifeCost:       lifeRevert,
		validateStack: makeStackFunc(2, 0),
		memorySize:    memoryRevert,
		valid:         true,
		reverts:       true,
		returns:       true,
	}
	return instructionSet
}

// NewHomesteadInstructionSet returns the frontier and homestead
// instructions that can be executed during the homestead phase.
func NewHomesteadInstructionSet() [256]operation {
	instructionSet := NewFrontierInstructionSet()
	instructionSet[DELEGATECALL] = operation{
		execute:       opDelegateCall,
		lifeCost:       lifeDelegateCall,
		validateStack: makeStackFunc(6, 1),
		memorySize:    memoryDelegateCall,
		valid:         true,
		returns:       true,
	}
	return instructionSet
}

// NewFrontierInstructionSet returns the frontier instructions
// that can be executed during the frontier phase.
func NewFrontierInstructionSet() [256]operation {
	return [256]operation{
		STOP: {
			execute:       opStop,
			lifeCost:       constLifeFunc(0),
			validateStack: makeStackFunc(0, 0),
			halts:         true,
			valid:         true,
		},
		ADD: {
			execute:       opAdd,
			lifeCost:       constLifeFunc(LifeFastestStep),
			validateStack: makeStackFunc(2, 1),
			valid:         true,
		},
		MUL: {
			execute:       opMul,
			lifeCost:       constLifeFunc(LifeFastStep),
			validateStack: makeStackFunc(2, 1),
			valid:         true,
		},
		SUB: {
			execute:       opSub,
			lifeCost:       constLifeFunc(LifeFastestStep),
			validateStack: makeStackFunc(2, 1),
			valid:         true,
		},
		DIV: {
			execute:       opDiv,
			lifeCost:       constLifeFunc(LifeFastStep),
			validateStack: makeStackFunc(2, 1),
			valid:         true,
		},
		SDIV: {
			execute:       opSdiv,
			lifeCost:       constLifeFunc(LifeFastStep),
			validateStack: makeStackFunc(2, 1),
			valid:         true,
		},
		MOD: {
			execute:       opMod,
			lifeCost:       constLifeFunc(LifeFastStep),
			validateStack: makeStackFunc(2, 1),
			valid:         true,
		},
		SMOD: {
			execute:       opSmod,
			lifeCost:       constLifeFunc(LifeFastStep),
			validateStack: makeStackFunc(2, 1),
			valid:         true,
		},
		ADDMOD: {
			execute:       opAddmod,
			lifeCost:       constLifeFunc(LifeMidStep),
			validateStack: makeStackFunc(3, 1),
			valid:         true,
		},
		MULMOD: {
			execute:       opMulmod,
			lifeCost:       constLifeFunc(LifeMidStep),
			validateStack: makeStackFunc(3, 1),
			valid:         true,
		},
		EXP: {
			execute:       opExp,
			lifeCost:       lifeExp,
			validateStack: makeStackFunc(2, 1),
			valid:         true,
		},
		SIGNEXTEND: {
			execute:       opSignExtend,
			lifeCost:       constLifeFunc(LifeFastStep),
			validateStack: makeStackFunc(2, 1),
			valid:         true,
		},
		LT: {
			execute:       opLt,
			lifeCost:       constLifeFunc(LifeFastestStep),
			validateStack: makeStackFunc(2, 1),
			valid:         true,
		},
		GT: {
			execute:       opGt,
			lifeCost:       constLifeFunc(LifeFastestStep),
			validateStack: makeStackFunc(2, 1),
			valid:         true,
		},
		SLT: {
			execute:       opSlt,
			lifeCost:       constLifeFunc(LifeFastestStep),
			validateStack: makeStackFunc(2, 1),
			valid:         true,
		},
		SGT: {
			execute:       opSgt,
			lifeCost:       constLifeFunc(LifeFastestStep),
			validateStack: makeStackFunc(2, 1),
			valid:         true,
		},
		EQ: {
			execute:       opEq,
			lifeCost:       constLifeFunc(LifeFastestStep),
			validateStack: makeStackFunc(2, 1),
			valid:         true,
		},
		ISZERO: {
			execute:       opIszero,
			lifeCost:       constLifeFunc(LifeFastestStep),
			validateStack: makeStackFunc(1, 1),
			valid:         true,
		},
		AND: {
			execute:       opAnd,
			lifeCost:       constLifeFunc(LifeFastestStep),
			validateStack: makeStackFunc(2, 1),
			valid:         true,
		},
		XOR: {
			execute:       opXor,
			lifeCost:       constLifeFunc(LifeFastestStep),
			validateStack: makeStackFunc(2, 1),
			valid:         true,
		},
		OR: {
			execute:       opOr,
			lifeCost:       constLifeFunc(LifeFastestStep),
			validateStack: makeStackFunc(2, 1),
			valid:         true,
		},
		NOT: {
			execute:       opNot,
			lifeCost:       constLifeFunc(LifeFastestStep),
			validateStack: makeStackFunc(1, 1),
			valid:         true,
		},
		BYTE: {
			execute:       opByte,
			lifeCost:       constLifeFunc(LifeFastestStep),
			validateStack: makeStackFunc(2, 1),
			valid:         true,
		},
		SHA3: {
			execute:       opSha3,
			lifeCost:       lifeSha3,
			validateStack: makeStackFunc(2, 1),
			memorySize:    memorySha3,
			valid:         true,
		},
		ADDRESS: {
			execute:       opAddress,
			lifeCost:       constLifeFunc(LifeQuickStep),
			validateStack: makeStackFunc(0, 1),
			valid:         true,
		},
		BALANCE: {
			execute:       opBalance,
			lifeCost:       lifeBalance,
			validateStack: makeStackFunc(1, 1),
			valid:         true,
		},
		ORIGIN: {
			execute:       opOrigin,
			lifeCost:       constLifeFunc(LifeQuickStep),
			validateStack: makeStackFunc(0, 1),
			valid:         true,
		},
		CALLER: {
			execute:       opCaller,
			lifeCost:       constLifeFunc(LifeQuickStep),
			validateStack: makeStackFunc(0, 1),
			valid:         true,
		},
		CALLVALUE: {
			execute:       opCallValue,
			lifeCost:       constLifeFunc(LifeQuickStep),
			validateStack: makeStackFunc(0, 1),
			valid:         true,
		},
		CALLDATALOAD: {
			execute:       opCallDataLoad,
			lifeCost:       constLifeFunc(LifeFastestStep),
			validateStack: makeStackFunc(1, 1),
			valid:         true,
		},
		CALLDATASIZE: {
			execute:       opCallDataSize,
			lifeCost:       constLifeFunc(LifeQuickStep),
			validateStack: makeStackFunc(0, 1),
			valid:         true,
		},
		CALLDATACOPY: {
			execute:       opCallDataCopy,
			lifeCost:       lifeCallDataCopy,
			validateStack: makeStackFunc(3, 0),
			memorySize:    memoryCallDataCopy,
			valid:         true,
		},
		CODESIZE: {
			execute:       opCodeSize,
			lifeCost:       constLifeFunc(LifeQuickStep),
			validateStack: makeStackFunc(0, 1),
			valid:         true,
		},
		CODECOPY: {
			execute:       opCodeCopy,
			lifeCost:       lifeCodeCopy,
			validateStack: makeStackFunc(3, 0),
			memorySize:    memoryCodeCopy,
			valid:         true,
		},
		GASPRICE: {
			execute:       opLifeprice,
			lifeCost:       constLifeFunc(LifeQuickStep),
			validateStack: makeStackFunc(0, 1),
			valid:         true,
		},
		EXTCODESIZE: {
			execute:       opExtCodeSize,
			lifeCost:       lifeExtCodeSize,
			validateStack: makeStackFunc(1, 1),
			valid:         true,
		},
		EXTCODECOPY: {
			execute:       opExtCodeCopy,
			lifeCost:       lifeExtCodeCopy,
			validateStack: makeStackFunc(4, 0),
			memorySize:    memoryExtCodeCopy,
			valid:         true,
		},
		BLOCKHASH: {
			execute:       opBlockhash,
			lifeCost:       constLifeFunc(LifeExtStep),
			validateStack: makeStackFunc(1, 1),
			valid:         true,
		},
		COINBASE: {
			execute:       opCoinbase,
			lifeCost:       constLifeFunc(LifeQuickStep),
			validateStack: makeStackFunc(0, 1),
			valid:         true,
		},
		TIMESTAMP: {
			execute:       opTimestamp,
			lifeCost:       constLifeFunc(LifeQuickStep),
			validateStack: makeStackFunc(0, 1),
			valid:         true,
		},
		NUMBER: {
			execute:       opNumber,
			lifeCost:       constLifeFunc(LifeQuickStep),
			validateStack: makeStackFunc(0, 1),
			valid:         true,
		},
		DIFFICULTY: {
			execute:       opDifficulty,
			lifeCost:       constLifeFunc(LifeQuickStep),
			validateStack: makeStackFunc(0, 1),
			valid:         true,
		},
		GASLIMIT: {
			execute:       opLifeLimit,
			lifeCost:       constLifeFunc(LifeQuickStep),
			validateStack: makeStackFunc(0, 1),
			valid:         true,
		},
		POP: {
			execute:       opPop,
			lifeCost:       constLifeFunc(LifeQuickStep),
			validateStack: makeStackFunc(1, 0),
			valid:         true,
		},
		MLOAD: {
			execute:       opMload,
			lifeCost:       lifeMLoad,
			validateStack: makeStackFunc(1, 1),
			memorySize:    memoryMLoad,
			valid:         true,
		},
		MSTORE: {
			execute:       opMstore,
			lifeCost:       lifeMStore,
			validateStack: makeStackFunc(2, 0),
			memorySize:    memoryMStore,
			valid:         true,
		},
		MSTORE8: {
			execute:       opMstore8,
			lifeCost:       lifeMStore8,
			memorySize:    memoryMStore8,
			validateStack: makeStackFunc(2, 0),

			valid: true,
		},
		SLOAD: {
			execute:       opSload,
			lifeCost:       lifeSLoad,
			validateStack: makeStackFunc(1, 1),
			valid:         true,
		},
		SSTORE: {
			execute:       opSstore,
			lifeCost:       lifeSStore,
			validateStack: makeStackFunc(2, 0),
			valid:         true,
			writes:        true,
		},
		JUMP: {
			execute:       opJump,
			lifeCost:       constLifeFunc(LifeMidStep),
			validateStack: makeStackFunc(1, 0),
			jumps:         true,
			valid:         true,
		},
		JUMPI: {
			execute:       opJumpi,
			lifeCost:       constLifeFunc(LifeSlowStep),
			validateStack: makeStackFunc(2, 0),
			jumps:         true,
			valid:         true,
		},
		PC: {
			execute:       opPc,
			lifeCost:       constLifeFunc(LifeQuickStep),
			validateStack: makeStackFunc(0, 1),
			valid:         true,
		},
		MSIZE: {
			execute:       opMsize,
			lifeCost:       constLifeFunc(LifeQuickStep),
			validateStack: makeStackFunc(0, 1),
			valid:         true,
		},
		GAS: {
			execute:       opLife,
			lifeCost:       constLifeFunc(LifeQuickStep),
			validateStack: makeStackFunc(0, 1),
			valid:         true,
		},
		JUMPDEST: {
			execute:       opJumpdest,
			lifeCost:       constLifeFunc(params.JumpdestLife),
			validateStack: makeStackFunc(0, 0),
			valid:         true,
		},
		PUSH1: {
			execute:       makePush(1, 1),
			lifeCost:       lifePush,
			validateStack: makeStackFunc(0, 1),
			valid:         true,
		},
		PUSH2: {
			execute:       makePush(2, 2),
			lifeCost:       lifePush,
			validateStack: makeStackFunc(0, 1),
			valid:         true,
		},
		PUSH3: {
			execute:       makePush(3, 3),
			lifeCost:       lifePush,
			validateStack: makeStackFunc(0, 1),
			valid:         true,
		},
		PUSH4: {
			execute:       makePush(4, 4),
			lifeCost:       lifePush,
			validateStack: makeStackFunc(0, 1),
			valid:         true,
		},
		PUSH5: {
			execute:       makePush(5, 5),
			lifeCost:       lifePush,
			validateStack: makeStackFunc(0, 1),
			valid:         true,
		},
		PUSH6: {
			execute:       makePush(6, 6),
			lifeCost:       lifePush,
			validateStack: makeStackFunc(0, 1),
			valid:         true,
		},
		PUSH7: {
			execute:       makePush(7, 7),
			lifeCost:       lifePush,
			validateStack: makeStackFunc(0, 1),
			valid:         true,
		},
		PUSH8: {
			execute:       makePush(8, 8),
			lifeCost:       lifePush,
			validateStack: makeStackFunc(0, 1),
			valid:         true,
		},
		PUSH9: {
			execute:       makePush(9, 9),
			lifeCost:       lifePush,
			validateStack: makeStackFunc(0, 1),
			valid:         true,
		},
		PUSH10: {
			execute:       makePush(10, 10),
			lifeCost:       lifePush,
			validateStack: makeStackFunc(0, 1),
			valid:         true,
		},
		PUSH11: {
			execute:       makePush(11, 11),
			lifeCost:       lifePush,
			validateStack: makeStackFunc(0, 1),
			valid:         true,
		},
		PUSH12: {
			execute:       makePush(12, 12),
			lifeCost:       lifePush,
			validateStack: makeStackFunc(0, 1),
			valid:         true,
		},
		PUSH13: {
			execute:       makePush(13, 13),
			lifeCost:       lifePush,
			validateStack: makeStackFunc(0, 1),
			valid:         true,
		},
		PUSH14: {
			execute:       makePush(14, 14),
			lifeCost:       lifePush,
			validateStack: makeStackFunc(0, 1),
			valid:         true,
		},
		PUSH15: {
			execute:       makePush(15, 15),
			lifeCost:       lifePush,
			validateStack: makeStackFunc(0, 1),
			valid:         true,
		},
		PUSH16: {
			execute:       makePush(16, 16),
			lifeCost:       lifePush,
			validateStack: makeStackFunc(0, 1),
			valid:         true,
		},
		PUSH17: {
			execute:       makePush(17, 17),
			lifeCost:       lifePush,
			validateStack: makeStackFunc(0, 1),
			valid:         true,
		},
		PUSH18: {
			execute:       makePush(18, 18),
			lifeCost:       lifePush,
			validateStack: makeStackFunc(0, 1),
			valid:         true,
		},
		PUSH19: {
			execute:       makePush(19, 19),
			lifeCost:       lifePush,
			validateStack: makeStackFunc(0, 1),
			valid:         true,
		},
		PUSH20: {
			execute:       makePush(20, 20),
			lifeCost:       lifePush,
			validateStack: makeStackFunc(0, 1),
			valid:         true,
		},
		PUSH21: {
			execute:       makePush(21, 21),
			lifeCost:       lifePush,
			validateStack: makeStackFunc(0, 1),
			valid:         true,
		},
		PUSH22: {
			execute:       makePush(22, 22),
			lifeCost:       lifePush,
			validateStack: makeStackFunc(0, 1),
			valid:         true,
		},
		PUSH23: {
			execute:       makePush(23, 23),
			lifeCost:       lifePush,
			validateStack: makeStackFunc(0, 1),
			valid:         true,
		},
		PUSH24: {
			execute:       makePush(24, 24),
			lifeCost:       lifePush,
			validateStack: makeStackFunc(0, 1),
			valid:         true,
		},
		PUSH25: {
			execute:       makePush(25, 25),
			lifeCost:       lifePush,
			validateStack: makeStackFunc(0, 1),
			valid:         true,
		},
		PUSH26: {
			execute:       makePush(26, 26),
			lifeCost:       lifePush,
			validateStack: makeStackFunc(0, 1),
			valid:         true,
		},
		PUSH27: {
			execute:       makePush(27, 27),
			lifeCost:       lifePush,
			validateStack: makeStackFunc(0, 1),
			valid:         true,
		},
		PUSH28: {
			execute:       makePush(28, 28),
			lifeCost:       lifePush,
			validateStack: makeStackFunc(0, 1),
			valid:         true,
		},
		PUSH29: {
			execute:       makePush(29, 29),
			lifeCost:       lifePush,
			validateStack: makeStackFunc(0, 1),
			valid:         true,
		},
		PUSH30: {
			execute:       makePush(30, 30),
			lifeCost:       lifePush,
			validateStack: makeStackFunc(0, 1),
			valid:         true,
		},
		PUSH31: {
			execute:       makePush(31, 31),
			lifeCost:       lifePush,
			validateStack: makeStackFunc(0, 1),
			valid:         true,
		},
		PUSH32: {
			execute:       makePush(32, 32),
			lifeCost:       lifePush,
			validateStack: makeStackFunc(0, 1),
			valid:         true,
		},
		DUP1: {
			execute:       makeDup(1),
			lifeCost:       lifeDup,
			validateStack: makeDupStackFunc(1),
			valid:         true,
		},
		DUP2: {
			execute:       makeDup(2),
			lifeCost:       lifeDup,
			validateStack: makeDupStackFunc(2),
			valid:         true,
		},
		DUP3: {
			execute:       makeDup(3),
			lifeCost:       lifeDup,
			validateStack: makeDupStackFunc(3),
			valid:         true,
		},
		DUP4: {
			execute:       makeDup(4),
			lifeCost:       lifeDup,
			validateStack: makeDupStackFunc(4),
			valid:         true,
		},
		DUP5: {
			execute:       makeDup(5),
			lifeCost:       lifeDup,
			validateStack: makeDupStackFunc(5),
			valid:         true,
		},
		DUP6: {
			execute:       makeDup(6),
			lifeCost:       lifeDup,
			validateStack: makeDupStackFunc(6),
			valid:         true,
		},
		DUP7: {
			execute:       makeDup(7),
			lifeCost:       lifeDup,
			validateStack: makeDupStackFunc(7),
			valid:         true,
		},
		DUP8: {
			execute:       makeDup(8),
			lifeCost:       lifeDup,
			validateStack: makeDupStackFunc(8),
			valid:         true,
		},
		DUP9: {
			execute:       makeDup(9),
			lifeCost:       lifeDup,
			validateStack: makeDupStackFunc(9),
			valid:         true,
		},
		DUP10: {
			execute:       makeDup(10),
			lifeCost:       lifeDup,
			validateStack: makeDupStackFunc(10),
			valid:         true,
		},
		DUP11: {
			execute:       makeDup(11),
			lifeCost:       lifeDup,
			validateStack: makeDupStackFunc(11),
			valid:         true,
		},
		DUP12: {
			execute:       makeDup(12),
			lifeCost:       lifeDup,
			validateStack: makeDupStackFunc(12),
			valid:         true,
		},
		DUP13: {
			execute:       makeDup(13),
			lifeCost:       lifeDup,
			validateStack: makeDupStackFunc(13),
			valid:         true,
		},
		DUP14: {
			execute:       makeDup(14),
			lifeCost:       lifeDup,
			validateStack: makeDupStackFunc(14),
			valid:         true,
		},
		DUP15: {
			execute:       makeDup(15),
			lifeCost:       lifeDup,
			validateStack: makeDupStackFunc(15),
			valid:         true,
		},
		DUP16: {
			execute:       makeDup(16),
			lifeCost:       lifeDup,
			validateStack: makeDupStackFunc(16),
			valid:         true,
		},
		SWAP1: {
			execute:       makeSwap(1),
			lifeCost:       lifeSwap,
			validateStack: makeSwapStackFunc(2),
			valid:         true,
		},
		SWAP2: {
			execute:       makeSwap(2),
			lifeCost:       lifeSwap,
			validateStack: makeSwapStackFunc(3),
			valid:         true,
		},
		SWAP3: {
			execute:       makeSwap(3),
			lifeCost:       lifeSwap,
			validateStack: makeSwapStackFunc(4),
			valid:         true,
		},
		SWAP4: {
			execute:       makeSwap(4),
			lifeCost:       lifeSwap,
			validateStack: makeSwapStackFunc(5),
			valid:         true,
		},
		SWAP5: {
			execute:       makeSwap(5),
			lifeCost:       lifeSwap,
			validateStack: makeSwapStackFunc(6),
			valid:         true,
		},
		SWAP6: {
			execute:       makeSwap(6),
			lifeCost:       lifeSwap,
			validateStack: makeSwapStackFunc(7),
			valid:         true,
		},
		SWAP7: {
			execute:       makeSwap(7),
			lifeCost:       lifeSwap,
			validateStack: makeSwapStackFunc(8),
			valid:         true,
		},
		SWAP8: {
			execute:       makeSwap(8),
			lifeCost:       lifeSwap,
			validateStack: makeSwapStackFunc(9),
			valid:         true,
		},
		SWAP9: {
			execute:       makeSwap(9),
			lifeCost:       lifeSwap,
			validateStack: makeSwapStackFunc(10),
			valid:         true,
		},
		SWAP10: {
			execute:       makeSwap(10),
			lifeCost:       lifeSwap,
			validateStack: makeSwapStackFunc(11),
			valid:         true,
		},
		SWAP11: {
			execute:       makeSwap(11),
			lifeCost:       lifeSwap,
			validateStack: makeSwapStackFunc(12),
			valid:         true,
		},
		SWAP12: {
			execute:       makeSwap(12),
			lifeCost:       lifeSwap,
			validateStack: makeSwapStackFunc(13),
			valid:         true,
		},
		SWAP13: {
			execute:       makeSwap(13),
			lifeCost:       lifeSwap,
			validateStack: makeSwapStackFunc(14),
			valid:         true,
		},
		SWAP14: {
			execute:       makeSwap(14),
			lifeCost:       lifeSwap,
			validateStack: makeSwapStackFunc(15),
			valid:         true,
		},
		SWAP15: {
			execute:       makeSwap(15),
			lifeCost:       lifeSwap,
			validateStack: makeSwapStackFunc(16),
			valid:         true,
		},
		SWAP16: {
			execute:       makeSwap(16),
			lifeCost:       lifeSwap,
			validateStack: makeSwapStackFunc(17),
			valid:         true,
		},
		LOG0: {
			execute:       makeLog(0),
			lifeCost:       makeLifeLog(0),
			validateStack: makeStackFunc(2, 0),
			memorySize:    memoryLog,
			valid:         true,
			writes:        true,
		},
		LOG1: {
			execute:       makeLog(1),
			lifeCost:       makeLifeLog(1),
			validateStack: makeStackFunc(3, 0),
			memorySize:    memoryLog,
			valid:         true,
			writes:        true,
		},
		LOG2: {
			execute:       makeLog(2),
			lifeCost:       makeLifeLog(2),
			validateStack: makeStackFunc(4, 0),
			memorySize:    memoryLog,
			valid:         true,
			writes:        true,
		},
		LOG3: {
			execute:       makeLog(3),
			lifeCost:       makeLifeLog(3),
			validateStack: makeStackFunc(5, 0),
			memorySize:    memoryLog,
			valid:         true,
			writes:        true,
		},
		LOG4: {
			execute:       makeLog(4),
			lifeCost:       makeLifeLog(4),
			validateStack: makeStackFunc(6, 0),
			memorySize:    memoryLog,
			valid:         true,
			writes:        true,
		},
		CREATE: {
			execute:       opCreate,
			lifeCost:       lifeCreate,
			validateStack: makeStackFunc(3, 1),
			memorySize:    memoryCreate,
			valid:         true,
			writes:        true,
			returns:       true,
		},
		CALL: {
			execute:       opCall,
			lifeCost:       lifeCall,
			validateStack: makeStackFunc(7, 1),
			memorySize:    memoryCall,
			valid:         true,
			returns:       true,
		},
		CALLCODE: {
			execute:       opCallCode,
			lifeCost:       lifeCallCode,
			validateStack: makeStackFunc(7, 1),
			memorySize:    memoryCall,
			valid:         true,
			returns:       true,
		},
		RETURN: {
			execute:       opReturn,
			lifeCost:       lifeReturn,
			validateStack: makeStackFunc(2, 0),
			memorySize:    memoryReturn,
			halts:         true,
			valid:         true,
		},
		SELFDESTRUCT: {
			execute:       opSuicide,
			lifeCost:       lifeSuicide,
			validateStack: makeStackFunc(1, 0),
			halts:         true,
			valid:         true,
			writes:        true,
		},
	}
}
