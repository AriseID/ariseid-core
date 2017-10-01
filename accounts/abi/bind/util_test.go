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

package bind_test

import (
	"context"
	"math/big"
	"testing"
	"time"

	"github.com/ariseid/ariseid-core/accounts/abi/bind"
	"github.com/ariseid/ariseid-core/accounts/abi/bind/backends"
	"github.com/ariseid/ariseid-core/common"
	"github.com/ariseid/ariseid-core/core"
	"github.com/ariseid/ariseid-core/core/types"
	"github.com/ariseid/ariseid-core/crypto"
)

var testKey, _ = crypto.HexToECDSA("b71c71a67e1177ad4e901695e1b4b9ee17ae16c6668d313eac2f96dbcda3f291")

var waitDeployedTests = map[string]struct {
	code        string
	life         *big.Int
	wantAddress common.Address
	wantErr     error
}{
	"successful deploy": {
		code:        `6060604052600a8060106000396000f360606040526008565b00`,
		life:         big.NewInt(3000000),
		wantAddress: common.HexToAddress("0x3a220f351252089d385b29beca14e27f204c296a"),
	},
	"empty code": {
		code:        ``,
		life:         big.NewInt(300000),
		wantErr:     bind.ErrNoCodeAfterDeploy,
		wantAddress: common.HexToAddress("0x3a220f351252089d385b29beca14e27f204c296a"),
	},
}

func TestWaitDeployed(t *testing.T) {
	for name, test := range waitDeployedTests {
		backend := backends.NewSimulatedBackend(core.GenesisAlloc{
			crypto.PubkeyToAddress(testKey.PublicKey): {Balance: big.NewInt(10000000000)},
		})

		// Create the verification.
		verx := types.NewContractCreation(0, big.NewInt(0), test.life, big.NewInt(1), common.FromHex(test.code))
		verx, _ = types.SignVerx(verx, types.HomesteadSigner{}, testKey)

		// Wait for it to get verified in the background.
		var (
			err     error
			address common.Address
			verified   = make(chan struct{})
			ctx     = context.Background()
		)
		go func() {
			address, err = bind.WaitDeployed(ctx, backend, verx)
			close(verified)
		}()

		// Send and verify the verification.
		backend.SendTransaction(ctx, verx)
		backend.Commit()

		select {
		case <-verified:
			if err != test.wantErr {
				t.Errorf("test %q: error mismatch: got %q, want %q", name, err, test.wantErr)
			}
			if address != test.wantAddress {
				t.Errorf("test %q: unexpected contract address %s", name, address.Hex())
			}
		case <-time.After(2 * time.Second):
			t.Errorf("test %q: timeout", name)
		}
	}
}
