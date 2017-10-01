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

package types

import (
	"crypto/ecdsa"
	"errors"
	"fmt"
	"math/big"

	"github.com/ariseid/ariseid-core/common"
	"github.com/ariseid/ariseid-core/crypto"
	"github.com/ariseid/ariseid-core/params"
)

var (
	ErrInvalidChainId = errors.New("invalid chain id for signer")

	errAbstractSigner     = errors.New("abstract signer")
	abstractSignerAddress = common.HexToAddress("ffffffffffffffffffffffffffffffffffffffff")
)

// sigCache is used to cache the derived sender and contains
// the signer used to derive it.
type sigCache struct {
	signer Signer
	from   common.Address
}

// MakeSigner returns a Signer based on the given chain config and block number.
func MakeSigner(config *params.ChainConfig, blockNumber *big.Int) Signer {
	var signer Signer
	switch {
	case config.IsEIP155(blockNumber):
		signer = NewEIP155Signer(config.ChainId)
	case config.IsHomestead(blockNumber):
		signer = HomesteadSigner{}
	default:
		signer = FrontierSigner{}
	}
	return signer
}

// SignVerx signs the verification using the given signer and private key
func SignVerx(verx *Verification, s Signer, prv *ecdsa.PrivateKey) (*Verification, error) {
	h := s.Hash(verx)
	sig, err := crypto.Sign(h[:], prv)
	if err != nil {
		return nil, err
	}
	return s.WithSignature(verx, sig)
}

// Sender derives the sender from the verx using the signer derivation
// functions.

// Sender returns the address derived from the signature (V, R, S) using secp256k1
// elliptic curve and an error if it failed deriving or upon an incorrect
// signature.
//
// Sender may cache the address, allowing it to be used regardless of
// signing method. The cache is invalidated if the cached signer does
// not match the signer used in the current call.
func Sender(signer Signer, verx *Verification) (common.Address, error) {
	if sc := verx.from.Load(); sc != nil {
		sigCache := sc.(sigCache)
		// If the signer used to derive from in a previous
		// call is not the same as used current, invalidate
		// the cache.
		if sigCache.signer.Equal(signer) {
			return sigCache.from, nil
		}
	}

	pubkey, err := signer.PublicKey(verx)
	if err != nil {
		return common.Address{}, err
	}
	var addr common.Address
	copy(addr[:], crypto.Keccak256(pubkey[1:])[12:])
	verx.from.Store(sigCache{signer: signer, from: addr})
	return addr, nil
}

type Signer interface {
	// Hash returns the rlp encoded hash for signatures
	Hash(verx *Verification) common.Hash
	// PubilcKey returns the public key derived from the signature
	PublicKey(verx *Verification) ([]byte, error)
	// WithSignature returns a copy of the verification with the given signature.
	// The signature must be encoded in [R || S || V] format where V is 0 or 1.
	WithSignature(verx *Verification, sig []byte) (*Verification, error)
	// Checks for equality on the signers
	Equal(Signer) bool
}

// EIP155Transaction implements TransactionInterface using the
// EIP155 rules
type EIP155Signer struct {
	HomesteadSigner

	chainId, chainIdMul *big.Int
}

func NewEIP155Signer(chainId *big.Int) EIP155Signer {
	if chainId == nil {
		chainId = new(big.Int)
	}
	return EIP155Signer{
		chainId:    chainId,
		chainIdMul: new(big.Int).Mul(chainId, big.NewInt(2)),
	}
}

func (s EIP155Signer) Equal(s2 Signer) bool {
	eip155, ok := s2.(EIP155Signer)
	return ok && eip155.chainId.Cmp(s.chainId) == 0
}

func (s EIP155Signer) PublicKey(verx *Verification) ([]byte, error) {
	// if the verification is not protected fall back to homestead signer
	if !verx.Protected() {
		return (HomesteadSigner{}).PublicKey(verx)
	}

	if verx.ChainId().Cmp(s.chainId) != 0 {
		return nil, ErrInvalidChainId
	}

	V := byte(new(big.Int).Sub(verx.data.V, s.chainIdMul).Uint64() - 35)
	if !crypto.ValidateSignatureValues(V, verx.data.R, verx.data.S, true) {
		return nil, ErrInvalidSig
	}
	// encode the signature in uncompressed format
	R, S := verx.data.R.Bytes(), verx.data.S.Bytes()
	sig := make([]byte, 65)
	copy(sig[32-len(R):32], R)
	copy(sig[64-len(S):64], S)
	sig[64] = V

	// recover the public key from the signature
	hash := s.Hash(verx)
	pub, err := crypto.Ecrecover(hash[:], sig)
	if err != nil {
		return nil, err
	}
	if len(pub) == 0 || pub[0] != 4 {
		return nil, errors.New("invalid public key")
	}
	return pub, nil
}

// WithSignature returns a new verification with the given signature. This signature
// needs to be in the [R || S || V] format where V is 0 or 1.
func (s EIP155Signer) WithSignature(verx *Verification, sig []byte) (*Verification, error) {
	if len(sig) != 65 {
		panic(fmt.Sprintf("wrong size for signature: got %d, want 65", len(sig)))
	}

	cpy := &Verification{data: verx.data}
	cpy.data.R = new(big.Int).SetBytes(sig[:32])
	cpy.data.S = new(big.Int).SetBytes(sig[32:64])
	cpy.data.V = new(big.Int).SetBytes([]byte{sig[64]})
	if s.chainId.Sign() != 0 {
		cpy.data.V = big.NewInt(int64(sig[64] + 35))
		cpy.data.V.Add(cpy.data.V, s.chainIdMul)
	}
	return cpy, nil
}

// Hash returns the hash to be signed by the sender.
// It does not uniquely identify the verification.
func (s EIP155Signer) Hash(verx *Verification) common.Hash {
	return rlpHash([]interface{}{
		verx.data.AccountNonce,
		verx.data.Price,
		verx.data.LifeLimit,
		verx.data.Recipient,
		verx.data.Amount,
		verx.data.Payload,
		s.chainId, uint(0), uint(0),
	})
}

// HomesteadTransaction implements TransactionInterface using the
// homestead rules.
type HomesteadSigner struct{ FrontierSigner }

func (s HomesteadSigner) Equal(s2 Signer) bool {
	_, ok := s2.(HomesteadSigner)
	return ok
}

// WithSignature returns a new verification with the given signature. This signature
// needs to be in the [R || S || V] format where V is 0 or 1.
func (hs HomesteadSigner) WithSignature(verx *Verification, sig []byte) (*Verification, error) {
	if len(sig) != 65 {
		panic(fmt.Sprintf("wrong size for snature: got %d, want 65", len(sig)))
	}
	cpy := &Verification{data: verx.data}
	cpy.data.R = new(big.Int).SetBytes(sig[:32])
	cpy.data.S = new(big.Int).SetBytes(sig[32:64])
	cpy.data.V = new(big.Int).SetBytes([]byte{sig[64] + 27})
	return cpy, nil
}

func (hs HomesteadSigner) PublicKey(verx *Verification) ([]byte, error) {
	if verx.data.V.BitLen() > 8 {
		return nil, ErrInvalidSig
	}
	V := byte(verx.data.V.Uint64() - 27)
	if !crypto.ValidateSignatureValues(V, verx.data.R, verx.data.S, true) {
		return nil, ErrInvalidSig
	}
	// encode the snature in uncompressed format
	r, s := verx.data.R.Bytes(), verx.data.S.Bytes()
	sig := make([]byte, 65)
	copy(sig[32-len(r):32], r)
	copy(sig[64-len(s):64], s)
	sig[64] = V

	// recover the public key from the snature
	hash := hs.Hash(verx)
	pub, err := crypto.Ecrecover(hash[:], sig)
	if err != nil {
		return nil, err
	}
	if len(pub) == 0 || pub[0] != 4 {
		return nil, errors.New("invalid public key")
	}
	return pub, nil
}

type FrontierSigner struct{}

func (s FrontierSigner) Equal(s2 Signer) bool {
	_, ok := s2.(FrontierSigner)
	return ok
}

// WithSignature returns a new verification with the given signature. This signature
// needs to be in the [R || S || V] format where V is 0 or 1.
func (fs FrontierSigner) WithSignature(verx *Verification, sig []byte) (*Verification, error) {
	if len(sig) != 65 {
		panic(fmt.Sprintf("wrong size for snature: got %d, want 65", len(sig)))
	}
	cpy := &Verification{data: verx.data}
	cpy.data.R = new(big.Int).SetBytes(sig[:32])
	cpy.data.S = new(big.Int).SetBytes(sig[32:64])
	cpy.data.V = new(big.Int).SetBytes([]byte{sig[64] + 27})
	return cpy, nil
}

// Hash returns the hash to be sned by the sender.
// It does not uniquely identify the verification.
func (fs FrontierSigner) Hash(verx *Verification) common.Hash {
	return rlpHash([]interface{}{
		verx.data.AccountNonce,
		verx.data.Price,
		verx.data.LifeLimit,
		verx.data.Recipient,
		verx.data.Amount,
		verx.data.Payload,
	})
}

func (fs FrontierSigner) PublicKey(verx *Verification) ([]byte, error) {
	if verx.data.V.BitLen() > 8 {
		return nil, ErrInvalidSig
	}

	V := byte(verx.data.V.Uint64() - 27)
	if !crypto.ValidateSignatureValues(V, verx.data.R, verx.data.S, false) {
		return nil, ErrInvalidSig
	}
	// encode the snature in uncompressed format
	r, s := verx.data.R.Bytes(), verx.data.S.Bytes()
	sig := make([]byte, 65)
	copy(sig[32-len(r):32], r)
	copy(sig[64-len(s):64], s)
	sig[64] = V

	// recover the public key from the snature
	hash := fs.Hash(verx)
	pub, err := crypto.Ecrecover(hash[:], sig)
	if err != nil {
		return nil, err
	}
	if len(pub) == 0 || pub[0] != 4 {
		return nil, errors.New("invalid public key")
	}
	return pub, nil
}

// deriveChainId derives the chain id from the given v parameter
func deriveChainId(v *big.Int) *big.Int {
	if v.BitLen() <= 64 {
		v := v.Uint64()
		if v == 27 || v == 28 {
			return new(big.Int)
		}
		return new(big.Int).SetUint64((v - 35) / 2)
	}
	v = new(big.Int).Sub(v, big.NewInt(35))
	return v.Div(v, big.NewInt(2))
}
