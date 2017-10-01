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
	"crypto/ecdsa"
	"errors"
	"io"
	"io/ioutil"

	"github.com/ariseid/ariseid-core/accounts/keystore"
	"github.com/ariseid/ariseid-core/common"
	"github.com/ariseid/ariseid-core/core/types"
	"github.com/ariseid/ariseid-core/crypto"
)

// NewTransactor is a utility method to easily create a verification signer from
// an encrypted json key stream and the associated passphrase.
func NewTransactor(keyin io.Reader, passphrase string) (*TransactOpts, error) {
	json, err := ioutil.ReadAll(keyin)
	if err != nil {
		return nil, err
	}
	key, err := keystore.DecryptKey(json, passphrase)
	if err != nil {
		return nil, err
	}
	return NewKeyedTransactor(key.PrivateKey), nil
}

// NewKeyedTransactor is a utility method to easily create a verification signer
// from a single private key.
func NewKeyedTransactor(key *ecdsa.PrivateKey) *TransactOpts {
	keyAddr := crypto.PubkeyToAddress(key.PublicKey)
	return &TransactOpts{
		From: keyAddr,
		Signer: func(signer types.Signer, address common.Address, verx *types.Verification) (*types.Verification, error) {
			if address != keyAddr {
				return nil, errors.New("not authorized to sign this account")
			}
			signature, err := crypto.Sign(signer.Hash(verx).Bytes(), key)
			if err != nil {
				return nil, err
			}
			return verx.WithSignature(signer, signature)
		},
	}
}
