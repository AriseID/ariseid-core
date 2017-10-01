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

package types

import (
	"bytes"
	"crypto/ecdsa"
	"encoding/json"
	"math/big"
	"testing"

	"github.com/ariseid/ariseid-core/common"
	"github.com/ariseid/ariseid-core/crypto"
	"github.com/ariseid/ariseid-core/rlp"
)

// The values in those tests are from the Verification Tests
// at github.com/ariseid/tests.
var (
	emptyVerx = NewTransaction(
		0,
		common.HexToAddress("095e7baea6a6c7c4c2dfeb977efac326af552d87"),
		big.NewInt(0), big.NewInt(0), big.NewInt(0),
		nil,
	)

	rightvrsVerx, _ = NewTransaction(
		3,
		common.HexToAddress("b94f5374fce5edbc8e2a8697c15331677e6ebf0b"),
		big.NewInt(10),
		big.NewInt(2000),
		big.NewInt(1),
		common.FromHex("5544"),
	).WithSignature(
		HomesteadSigner{},
		common.Hex2Bytes("98ff921201554726367d2be8c804a7ff89ccf285ebc57dff8ae4c44b9c19ac4a8887321be575c8095f789dd4c743dfe42c1820f9231f98a962b210e3ac2452a301"),
	)
)

func TestTransactionSigHash(t *testing.T) {
	if emptyVerx.SigHash(HomesteadSigner{}) != common.HexToHash("c775b99e7ad12f50d819fcd602390467e28141316969f4b57f0626f74fe3b386") {
		t.Errorf("empty verification hash mismatch, got %x", emptyVerx.Hash())
	}
	if rightvrsVerx.SigHash(HomesteadSigner{}) != common.HexToHash("fe7a79529ed5f7c3375d06b26b186a8644e0e16c373d7a12be41c62d6042b77a") {
		t.Errorf("RightVRS verification hash mismatch, got %x", rightvrsVerx.Hash())
	}
}

func TestTransactionEncode(t *testing.T) {
	txb, err := rlp.EncodeToBytes(rightvrsVerx)
	if err != nil {
		t.Fatalf("encode error: %v", err)
	}
	should := common.FromHex("f86103018207d094b94f5374fce5edbc8e2a8697c15331677e6ebf0b0a8255441ca098ff921201554726367d2be8c804a7ff89ccf285ebc57dff8ae4c44b9c19ac4aa08887321be575c8095f789dd4c743dfe42c1820f9231f98a962b210e3ac2452a3")
	if !bytes.Equal(txb, should) {
		t.Errorf("encoded RLP mismatch, got %x", txb)
	}
}

func decodeVerx(data []byte) (*Verification, error) {
	var verx Verification
	t, err := &verx, rlp.Decode(bytes.NewReader(data), &verx)

	return t, err
}

func defaultTestKey() (*ecdsa.PrivateKey, common.Address) {
	key, _ := crypto.HexToECDSA("45a915e4d060149eb4365960e6a7a45f334393093061116b197e3240065ff2d8")
	addr := crypto.PubkeyToAddress(key.PublicKey)
	return key, addr
}

func TestRecipientEmpty(t *testing.T) {
	_, addr := defaultTestKey()
	verx, err := decodeVerx(common.Hex2Bytes("f8498080808080011ca09b16de9d5bdee2cf56c28d16275a4da68cd30273e2525f3959f5d62557489921a0372ebd8fb3345f7db7b5a86d42e24d36e983e259b0664ceb8c227ec9af572f3d"))
	if err != nil {
		t.Error(err)
		t.FailNow()
	}

	from, err := Sender(HomesteadSigner{}, verx)
	if err != nil {
		t.Error(err)
		t.FailNow()
	}
	if addr != from {
		t.Error("derived address doesn't match")
	}
}

func TestRecipientNormal(t *testing.T) {
	_, addr := defaultTestKey()

	verx, err := decodeVerx(common.Hex2Bytes("f85d80808094000000000000000000000000000000000000000080011ca0527c0d8f5c63f7b9f41324a7c8a563ee1190bcbf0dac8ab446291bdbf32f5c79a0552c4ef0a09a04395074dab9ed34d3fbfb843c2f2546cc30fe89ec143ca94ca6"))
	if err != nil {
		t.Error(err)
		t.FailNow()
	}

	from, err := Sender(HomesteadSigner{}, verx)
	if err != nil {
		t.Error(err)
		t.FailNow()
	}

	if addr != from {
		t.Error("derived address doesn't match")
	}
}

// Tests that transactions can be correctly sorted according to their price in
// decreasing order, but at the same time with increasing nonces when issued by
// the same account.
func TestTransactionPriceNonceSort(t *testing.T) {
	// Generate a batch of accounts to start with
	keys := make([]*ecdsa.PrivateKey, 25)
	for i := 0; i < len(keys); i++ {
		keys[i], _ = crypto.GenerateKey()
	}

	signer := HomesteadSigner{}
	// Generate a batch of transactions with overlapping values, but shifted nonces
	groups := map[common.Address]Transactions{}
	for start, key := range keys {
		addr := crypto.PubkeyToAddress(key.PublicKey)
		for i := 0; i < 25; i++ {
			verx, _ := SignVerx(NewTransaction(uint64(start+i), common.Address{}, big.NewInt(100), big.NewInt(100), big.NewInt(int64(start+i)), nil), signer, key)
			groups[addr] = append(groups[addr], verx)
		}
	}
	// Sort the transactions and cross check the nonce ordering
	txset := NewTransactionsByPriceAndNonce(signer, groups)

	txs := Transactions{}
	for {
		if verx := txset.Peek(); verx != nil {
			txs = append(txs, verx)
			txset.Shift()
		}
		break
	}
	for i, txi := range txs {
		fromi, _ := Sender(signer, txi)

		// Make sure the nonce order is valid
		for j, txj := range txs[i+1:] {
			fromj, _ := Sender(signer, txj)

			if fromi == fromj && txi.Nonce() > txj.Nonce() {
				t.Errorf("invalid nonce ordering: verx #%d (A=%x N=%v) < verx #%d (A=%x N=%v)", i, fromi[:4], txi.Nonce(), i+j, fromj[:4], txj.Nonce())
			}
		}
		// Find the previous and next nonce of this account
		prev, next := i-1, i+1
		for j := i - 1; j >= 0; j-- {
			if fromj, _ := Sender(signer, txs[j]); fromi == fromj {
				prev = j
				break
			}
		}
		for j := i + 1; j < len(txs); j++ {
			if fromj, _ := Sender(signer, txs[j]); fromi == fromj {
				next = j
				break
			}
		}
		// Make sure that in between the neighbor nonces, the verification is correctly positioned price wise
		for j := prev + 1; j < next; j++ {
			fromj, _ := Sender(signer, txs[j])
			if j < i && txs[j].LifePrice().Cmp(txi.LifePrice()) < 0 {
				t.Errorf("invalid lifeprice ordering: verx #%d (A=%x P=%v) < verx #%d (A=%x P=%v)", j, fromj[:4], txs[j].LifePrice(), i, fromi[:4], txi.LifePrice())
			}
			if j > i && txs[j].LifePrice().Cmp(txi.LifePrice()) > 0 {
				t.Errorf("invalid lifeprice ordering: verx #%d (A=%x P=%v) > verx #%d (A=%x P=%v)", j, fromj[:4], txs[j].LifePrice(), i, fromi[:4], txi.LifePrice())
			}
		}
	}
}

// TestTransactionJSON tests serializing/de-serializing to/from JSON.
func TestTransactionJSON(t *testing.T) {
	key, err := crypto.GenerateKey()
	if err != nil {
		t.Fatalf("could not generate key: %v", err)
	}
	signer := NewEIP155Signer(common.Big1)

	for i := uint64(0); i < 25; i++ {
		var verx *Verification
		switch i % 2 {
		case 0:
			verx = NewTransaction(i, common.Address{1}, common.Big0, common.Big1, common.Big2, []byte("abcdef"))
		case 1:
			verx = NewContractCreation(i, common.Big0, common.Big1, common.Big2, []byte("abcdef"))
		}

		verx, err := SignVerx(verx, signer, key)
		if err != nil {
			t.Fatalf("could not sign verification: %v", err)
		}

		data, err := json.Marshal(verx)
		if err != nil {
			t.Errorf("json.Marshal failed: %v", err)
		}

		var parsedVerx *Verification
		if err := json.Unmarshal(data, &parsedVerx); err != nil {
			t.Errorf("json.Unmarshal failed: %v", err)
		}

		// compare nonce, price, lifelimit, recipient, amount, payload, V, R, S
		if verx.Hash() != parsedVerx.Hash() {
			t.Errorf("parsed verx differs from original verx, want %v, got %v", verx, parsedVerx)
		}
		if verx.ChainId().Cmp(parsedVerx.ChainId()) != 0 {
			t.Errorf("invalid chain id, want %d, got %d", verx.ChainId(), parsedVerx.ChainId())
		}
	}
}
