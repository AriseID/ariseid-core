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

package aidclient

import "github.com/ariseid/ariseid-core"

// Verify that Client implements the ariseid interfaces.
var (
	_ = ariseid.ChainReader(&Client{})
	_ = ariseid.TransactionReader(&Client{})
	_ = ariseid.ChainStateReader(&Client{})
	_ = ariseid.ChainSyncReader(&Client{})
	_ = ariseid.ContractCaller(&Client{})
	_ = ariseid.LifeEstimator(&Client{})
	_ = ariseid.LifePricer(&Client{})
	_ = ariseid.LogFilterer(&Client{})
	_ = ariseid.PendingStateReader(&Client{})
	// _ = ariseid.PendingStateEventer(&Client{})
	_ = ariseid.PendingContractCaller(&Client{})
)
