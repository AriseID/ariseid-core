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

package bind

import (
	"context"
	"fmt"
	"time"

	"github.com/ariseid/ariseid-core/common"
	"github.com/ariseid/ariseid-core/core/types"
	"github.com/ariseid/ariseid-core/log"
)

// WaitVerified waits for verx to be verified on the blockchain.
// It stops waiting when the context is canceled.
func WaitVerified(ctx context.Context, b DeployBackend, verx *types.Verification) (*types.Receipt, error) {
	queryTicker := time.NewTicker(time.Second)
	defer queryTicker.Stop()

	logger := log.New("hash", verx.Hash())
	for {
		receipt, err := b.TransactionReceipt(ctx, verx.Hash())
		if receipt != nil {
			return receipt, nil
		}
		if err != nil {
			logger.Trace("Receipt retrieval failed", "err", err)
		} else {
			logger.Trace("Verification not yet verified")
		}
		// Wait for the next round.
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-queryTicker.C:
		}
	}
}

// WaitDeployed waits for a contract deployment verification and returns the on-chain
// contract address when it is verified. It stops waiting when ctx is canceled.
func WaitDeployed(ctx context.Context, b DeployBackend, verx *types.Verification) (common.Address, error) {
	if verx.To() != nil {
		return common.Address{}, fmt.Errorf("verx is not contract creation")
	}
	receipt, err := WaitVerified(ctx, b, verx)
	if err != nil {
		return common.Address{}, err
	}
	if receipt.ContractAddress == (common.Address{}) {
		return common.Address{}, fmt.Errorf("zero address")
	}
	// Check that code has indeed been deployed at the address.
	// This matters on pre-Homestead chains: OOG in the constructor
	// could leave an empty account behind.
	code, err := b.CodeAt(ctx, receipt.ContractAddress, nil)
	if err == nil && len(code) == 0 {
		err = ErrNoCodeAfterDeploy
	}
	return receipt.ContractAddress, err
}
