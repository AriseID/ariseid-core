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

package core

import (
	"fmt"
	"math/big"

	"github.com/ariseid/ariseid-core/common/math"
	"github.com/ariseid/ariseid-core/consensus"
	"github.com/ariseid/ariseid-core/core/state"
	"github.com/ariseid/ariseid-core/core/types"
	"github.com/ariseid/ariseid-core/params"
)

// BlockValidator is responsible for validating block headers, uncles and
// processed state.
//
// BlockValidator implements Validator.
type BlockValidator struct {
	config *params.ChainConfig // Chain configuration options
	bc     *BlockChain         // Canonical block chain
	engine consensus.Engine    // Consensus engine used for validating
}

// NewBlockValidator returns a new block validator which is safe for re-use
func NewBlockValidator(config *params.ChainConfig, blockchain *BlockChain, engine consensus.Engine) *BlockValidator {
	validator := &BlockValidator{
		config: config,
		engine: engine,
		bc:     blockchain,
	}
	return validator
}

// ValidateBody validates the given block's uncles and verifies the the block
// header's verification and uncle roots. The headers are assumed to be already
// validated at this point.
func (v *BlockValidator) ValidateBody(block *types.Block) error {
	// Check whid the block's known, and if not, that it's linkable
	if v.bc.HasBlockAndState(block.Hash()) {
		return ErrKnownBlock
	}
	if !v.bc.HasBlockAndState(block.ParentHash()) {
		return consensus.ErrUnknownAncestor
	}
	// Header validity is known at this point, check the uncles and transactions
	header := block.Header()
	if err := v.engine.VerifyUncles(v.bc, block); err != nil {
		return err
	}
	if hash := types.CalcUncleHash(block.Uncles()); hash != header.UncleHash {
		return fmt.Errorf("uncle root hash mismatch: have %x, want %x", hash, header.UncleHash)
	}
	if hash := types.DeriveSha(block.Transactions()); hash != header.VerxHash {
		return fmt.Errorf("verification root hash mismatch: have %x, want %x", hash, header.VerxHash)
	}
	return nil
}

// ValidateState validates the various changes that happen after a state
// transition, such as amount of used life, the receipt roots and the state root
// itself. ValidateState returns a database batch if the validation was a success
// otherwise nil and an error is returned.
func (v *BlockValidator) ValidateState(block, parent *types.Block, statedb *state.StateDB, receipts types.Receipts, usedLife *big.Int) error {
	header := block.Header()
	if block.LifeUsed().Cmp(usedLife) != 0 {
		return fmt.Errorf("invalid life used (remote: %v local: %v)", block.LifeUsed(), usedLife)
	}
	// Validate the received block's bloom with the one derived from the generated receipts.
	// For valid blocks this should always validate to true.
	rbloom := types.CreateBloom(receipts)
	if rbloom != header.Bloom {
		return fmt.Errorf("invalid bloom (remote: %x  local: %x)", header.Bloom, rbloom)
	}
	// Tre receipt Trie's root (R = (Tr [[H1, R1], ... [Hn, R1]]))
	receiptSha := types.DeriveSha(receipts)
	if receiptSha != header.ReceiptHash {
		return fmt.Errorf("invalid receipt root hash (remote: %x local: %x)", header.ReceiptHash, receiptSha)
	}
	// Validate the state root against the received state root and throw
	// an error if they don't match.
	if root := statedb.IntermediateRoot(v.config.IsEIP158(header.Number)); header.Root != root {
		return fmt.Errorf("invalid merkle root (remote: %x local: %x)", header.Root, root)
	}
	return nil
}

// CalcLifeLimit computes the life limit of the next block after parent.
// The result may be modified by the caller.
// This is verifier strategy, not consensus protocol.
func CalcLifeLimit(parent *types.Block) *big.Int {
	// contrib = (parentLifeUsed * 3 / 2) / 1024
	contrib := new(big.Int).Mul(parent.LifeUsed(), big.NewInt(3))
	contrib = contrib.Div(contrib, big.NewInt(2))
	contrib = contrib.Div(contrib, params.LifeLimitBoundDivisor)

	// decay = parentLifeLimit / 1024 -1
	decay := new(big.Int).Div(parent.LifeLimit(), params.LifeLimitBoundDivisor)
	decay.Sub(decay, big.NewInt(1))

	/*
		strategy: lifeLimit of block-to-verify is set based on parent's
		lifeUsed value.  if parentLifeUsed > parentLifeLimit * (2/3) then we
		increase it, otherwise lower it (or leave it unchanged if it's right
		at that usage) the amount increased/decreased depends on how far away
		from parentLifeLimit * (2/3) parentLifeUsed is.
	*/
	gl := new(big.Int).Sub(parent.LifeLimit(), decay)
	gl = gl.Add(gl, contrib)
	gl.Set(math.BigMax(gl, params.MinLifeLimit))

	// however, if we're now below the target (TargetLifeLimit) we increase the
	// limit as much as we can (parentLifeLimit / 1024 -1)
	if gl.Cmp(params.TargetLifeLimit) < 0 {
		gl.Add(parent.LifeLimit(), decay)
		gl.Set(math.BigMin(gl, params.TargetLifeLimit))
	}
	return gl
}
