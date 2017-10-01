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

import "math/big"

// LifePool tracks the amount of life available during
// execution of the transactions in a block.
// The zero value is a pool with zero life available.
type LifePool big.Int

// AddLife makes life available for execution.
func (gp *LifePool) AddLife(amount *big.Int) *LifePool {
	i := (*big.Int)(gp)
	i.Add(i, amount)
	return gp
}

// SubLife deducts the given amount from the pool if enough life is
// available and returns an error otherwise.
func (gp *LifePool) SubLife(amount *big.Int) error {
	i := (*big.Int)(gp)
	if i.Cmp(amount) < 0 {
		return ErrLifeLimitReached
	}
	i.Sub(i, amount)
	return nil
}

func (gp *LifePool) String() string {
	return (*big.Int)(gp).String()
}
