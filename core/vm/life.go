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
	"math/big"

	"github.com/ariseid/ariseid-core/params"
)

const (
	LifeQuickStep   uint64 = 2
	LifeFastestStep uint64 = 3
	LifeFastStep    uint64 = 5
	LifeMidStep     uint64 = 8
	LifeSlowStep    uint64 = 10
	LifeExtStep     uint64 = 20

	LifeReturn       uint64 = 0
	LifeStop         uint64 = 0
	LifeContractByte uint64 = 200
)

// calcLife returns the actual life cost of the call.
//
// The cost of life was changed during the homestead price change HF. To allow for EIP150
// to be implemented. The returned life is life - base * 63 / 64.
func callLife(lifeTable params.LifeTable, availableLife, base uint64, callCost *big.Int) (uint64, error) {
	if lifeTable.CreateBySuicide > 0 {
		availableLife = availableLife - base
		life := availableLife - availableLife/64
		// If the bit length exceeds 64 bit we know that the newly calculated "life" for EIP150
		// is smaller than the requested amount. Therefor we return the new life instead
		// of returning an error.
		if callCost.BitLen() > 64 || life < callCost.Uint64() {
			return life, nil
		}
	}
	if callCost.BitLen() > 64 {
		return 0, errLifeUintOverflow
	}

	return callCost.Uint64(), nil
}
