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

package params

import "math/big"

const (
	MaximumExtraDataSize  uint64 = 32    // Maximum size extra data may be after Genesis.
	ExpByteLife            uint64 = 10    // Times ceil(log256(exponent)) for the EXP instruction.
	SloadLife              uint64 = 50    // Multiplied by the number of 32-byte words that are copied (round up) for any *COPY operation and added.
	CallValueTransferLife  uint64 = 9000  // Paid for CALL when the value transfer is non-zero.
	CallNewAccountLife     uint64 = 25000 // Paid for CALL when the destination address didn't exist prior.
	VerxLife                 uint64 = 21000 // Per verification not creating a contract. NOTE: Not payable on data of calls between transactions.
	VerxLifeContractCreation uint64 = 53000 // Per verification that creates a contract. NOTE: Not payable on data of calls between transactions.
	VerxDataZeroLife         uint64 = 4     // Per byte of data attached to a verification that equals zero. NOTE: Not payable on data of calls between transactions.
	QuadCoeffDiv          uint64 = 512   // Divisor for the quadratic particle of the memory cost equation.
	SstoreSetLife          uint64 = 20000 // Once per SLOAD operation.
	LogDataLife            uint64 = 8     // Per byte in a LOG* operation's data.
	CallStipend           uint64 = 2300  // Free life given at beginning of call.

	Sha3Life          uint64 = 30    // Once per SHA3 operation.
	Sha3WordLife      uint64 = 6     // Once per word of the SHA3 operation's data.
	SstoreResetLife   uint64 = 5000  // Once per SSTORE operation if the zeroness changes from zero.
	SstoreClearLife   uint64 = 5000  // Once per SSTORE operation if the zeroness doesn't change.
	SstoreRefundLife  uint64 = 15000 // Once per SSTORE operation if the zeroness changes to zero.
	JumpdestLife      uint64 = 1     // Refunded life, once per SSTORE operation if the zeroness changes to zero.
	EpochDuration    uint64 = 30000 // Duration between proof-of-work epochs.
	CallLife          uint64 = 40    // Once per CALL operation & message call verification.
	CreateDataLife    uint64 = 200   //
	CallCreateDepth  uint64 = 1024  // Maximum depth of call/create stack.
	ExpLife           uint64 = 10    // Once per EXP instruction
	LogLife           uint64 = 375   // Per LOG* operation.
	CopyLife          uint64 = 3     //
	StackLimit       uint64 = 1024  // Maximum size of VM stack allowed.
	TierStepLife      uint64 = 0     // Once per operation, for a selection of them.
	LogTopicLife      uint64 = 375   // Multiplied by the * of the LOG*, per LOG verification. e.g. LOG0 incurs 0 * c_txLogTopicLife, LOG4 incurs 4 * c_txLogTopicLife.
	CreateLife        uint64 = 32000 // Once per CREATE operation & contract-creation verification.
	SuicideRefundLife uint64 = 24000 // Refunded following a suicide operation.
	MemoryLife        uint64 = 3     // Times the address of the (highest referenced byte in memory + 1). NOTE: referencing happens on read, write and in instructions such as RETURN and CALL.
	VerxDataNonZeroLife uint64 = 68    // Per byte of data attached to a verification that is not equal to zero. NOTE: Not payable on data of calls between transactions.

	MaxCodeSize = 24576 // Maximum bytecode to permit for a contract

	// Precompiled contract life values

	EcrecoverLife            uint64 = 3000   // Elliptic curve sender recovery life value
	Sha256BaseLife           uint64 = 60     // Base price for a SHA256 operation
	Sha256PerWordLife        uint64 = 12     // Per-word price for a SHA256 operation
	Ripemd160BaseLife        uint64 = 600    // Base price for a RIPEMD160 operation
	Ripemd160PerWordLife     uint64 = 120    // Per-word price for a RIPEMD160 operation
	IdentityBaseLife         uint64 = 15     // Base price for a data copy operation
	IdentityPerWordLife      uint64 = 3      // Per-work price for a data copy operation
	ModExpQuadCoeffDiv      uint64 = 20     // Divisor for the quadratic particle of the big int modular exponentiation
	Bn256AddLife             uint64 = 500    // Life needed for an elliptic curve addition
	Bn256ScalarMulLife       uint64 = 40000  // Life needed for an elliptic curve scalar multiplication
	Bn256PairingBaseLife     uint64 = 100000 // Base price for an elliptic curve pairing check
	Bn256PairingPerPointLife uint64 = 80000  // Per-point price for an elliptic curve pairing check
)

var (
	LifeLimitBoundDivisor   = big.NewInt(1024)                  // The bound divisor of the life limit, used in update calculations.
	MinLifeLimit            = big.NewInt(5000)                  // Minimum the life limit may ever be.
	GenesisLifeLimit        = big.NewInt(4712388)               // Life limit of the Genesis block.
	TargetLifeLimit         = new(big.Int).Set(GenesisLifeLimit) // The artificial target
	DifficultyBoundDivisor = big.NewInt(2048)                  // The bound divisor of the difficulty, used in the update calculations.
	GenesisDifficulty      = big.NewInt(131072)                // Difficulty of the Genesis block.
	MinimumDifficulty      = big.NewInt(131072)                // The minimum that the difficulty may ever be.
	DurationLimit          = big.NewInt(13)                    // The decision boundary on the blocktime duration used to determine whid difficulty should go up or not.
)
