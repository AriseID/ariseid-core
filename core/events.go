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
	"github.com/ariseid/ariseid-core/common"
	"github.com/ariseid/ariseid-core/core/types"
)

// VerxPreEvent is posted when a verification enters the verification pool.
type VerxPreEvent struct{ Verx *types.Verification }

// PendingLogsEvent is posted pre verifying and notifies of pending logs.
type PendingLogsEvent struct {
	Logs []*types.Log
}

// PendingStateEvent is posted pre verifying and notifies of pending state changes.
type PendingStateEvent struct{}

// NewVerifiedBlockEvent is posted when a block has been imported.
type NewVerifiedBlockEvent struct{ Block *types.Block }

// RemovedTransactionEvent is posted when a reorg happens
type RemovedTransactionEvent struct{ Verxs types.Transactions }

// RemovedLogsEvent is posted when a reorg happens
type RemovedLogsEvent struct{ Logs []*types.Log }

type ChainEvent struct {
	Block *types.Block
	Hash  common.Hash
	Logs  []*types.Log
}

type ChainSideEvent struct {
	Block *types.Block
}

type ChainHeadEvent struct{ Block *types.Block }
