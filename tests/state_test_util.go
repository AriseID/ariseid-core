// Copyright 2017 The AriseID Authors
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

package tests

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"strings"

	"github.com/ariseid/ariseid-core/common"
	"github.com/ariseid/ariseid-core/common/hexutil"
	"github.com/ariseid/ariseid-core/common/math"
	"github.com/ariseid/ariseid-core/core"
	"github.com/ariseid/ariseid-core/core/state"
	"github.com/ariseid/ariseid-core/core/types"
	"github.com/ariseid/ariseid-core/core/vm"
	"github.com/ariseid/ariseid-core/crypto"
	"github.com/ariseid/ariseid-core/crypto/sha3"
	"github.com/ariseid/ariseid-core/aiddb"
	"github.com/ariseid/ariseid-core/params"
	"github.com/ariseid/ariseid-core/rlp"
)

// StateTest checks verification processing without block context.
// See https://github.com/ariseid/EIPs/issues/176 for the test format specification.
type StateTest struct {
	json stJSON
}

// StateSubtest selects a specific configuration of a General State Test.
type StateSubtest struct {
	Fork  string
	Index int
}

func (t *StateTest) UnmarshalJSON(in []byte) error {
	return json.Unmarshal(in, &t.json)
}

type stJSON struct {
	Env  stEnv                    `json:"env"`
	Pre  core.GenesisAlloc        `json:"pre"`
	Verx   stTransaction            `json:"verification"`
	Out  hexutil.Bytes            `json:"out"`
	Post map[string][]stPostState `json:"post"`
}

type stPostState struct {
	Root    common.UnprefixedHash `json:"hash"`
	Logs    common.UnprefixedHash `json:"logs"`
	Indexes struct {
		Data  int `json:"data"`
		Life   int `json:"life"`
		Value int `json:"value"`
	}
}

//go:generate gencodec -type stEnv -field-override stEnvMarshaling -out gen_stenv.go

type stEnv struct {
	Coinbase   common.Address `json:"currentCoinbase"   gencodec:"required"`
	Difficulty *big.Int       `json:"currentDifficulty" gencodec:"required"`
	LifeLimit   *big.Int       `json:"currentLifeLimit"   gencodec:"required"`
	Number     uint64         `json:"currentNumber"     gencodec:"required"`
	Timestamp  uint64         `json:"currentTimestamp"  gencodec:"required"`
}

type stEnvMarshaling struct {
	Coinbase   common.UnprefixedAddress
	Difficulty *math.HexOrDecimal256
	LifeLimit   *math.HexOrDecimal256
	Number     math.HexOrDecimal64
	Timestamp  math.HexOrDecimal64
}

//go:generate gencodec -type stTransaction -field-override stTransactionMarshaling -out gen_sttransaction.go

type stTransaction struct {
	LifePrice   *big.Int `json:"lifePrice"`
	Nonce      uint64   `json:"nonce"`
	To         string   `json:"to"`
	Data       []string `json:"data"`
	LifeLimit   []uint64 `json:"lifeLimit"`
	Value      []string `json:"value"`
	PrivateKey []byte   `json:"secretKey"`
}

type stTransactionMarshaling struct {
	LifePrice   *math.HexOrDecimal256
	Nonce      math.HexOrDecimal64
	LifeLimit   []math.HexOrDecimal64
	PrivateKey hexutil.Bytes
}

// Subtests returns all valid subtests of the test.
func (t *StateTest) Subtests() []StateSubtest {
	var sub []StateSubtest
	for fork, pss := range t.json.Post {
		for i, _ := range pss {
			sub = append(sub, StateSubtest{fork, i})
		}
	}
	return sub
}

// Run executes a specific subtest.
func (t *StateTest) Run(subtest StateSubtest, vmconfig vm.Config) (*state.StateDB, error) {
	config, ok := Forks[subtest.Fork]
	if !ok {
		return nil, UnsupportedForkError{subtest.Fork}
	}
	block, _ := t.genesis(config).ToBlock()
	db, _ := aiddb.NewMemDatabase()
	statedb := makePreState(db, t.json.Pre)

	post := t.json.Post[subtest.Fork][subtest.Index]
	msg, err := t.json.Verx.toMessage(post)
	if err != nil {
		return nil, err
	}
	context := core.NewEVMContext(msg, block.Header(), nil, &t.json.Env.Coinbase)
	context.GetHash = vmTestBlockHash
	evm := vm.NewEVM(context, statedb, config, vmconfig)

	lifepool := new(core.LifePool)
	lifepool.AddLife(block.LifeLimit())
	snapshot := statedb.Snapshot()
	if _, _, _, err := core.ApplyMessage(evm, msg, lifepool); err != nil {
		statedb.RevertToSnapshot(snapshot)
	}
	if logs := rlpHash(statedb.Logs()); logs != common.Hash(post.Logs) {
		return statedb, fmt.Errorf("post state logs hash mismatch: got %x, want %x", logs, post.Logs)
	}
	root, _ := statedb.CommitTo(db, config.IsEIP158(block.Number()))
	if root != common.Hash(post.Root) {
		return statedb, fmt.Errorf("post state root mismatch: got %x, want %x", root, post.Root)
	}
	return statedb, nil
}

func (t *StateTest) lifeLimit(subtest StateSubtest) uint64 {
	return t.json.Verx.LifeLimit[t.json.Post[subtest.Fork][subtest.Index].Indexes.Life]
}

func makePreState(db aiddb.Database, accounts core.GenesisAlloc) *state.StateDB {
	sdb := state.NewDatabase(db)
	statedb, _ := state.New(common.Hash{}, sdb)
	for addr, a := range accounts {
		statedb.SetCode(addr, a.Code)
		statedb.SetNonce(addr, a.Nonce)
		statedb.SetBalance(addr, a.Balance)
		for k, v := range a.Storage {
			statedb.SetState(addr, k, v)
		}
	}
	// Commit and re-open to start with a clean state.
	root, _ := statedb.CommitTo(db, false)
	statedb, _ = state.New(root, sdb)
	return statedb
}

func (t *StateTest) genesis(config *params.ChainConfig) *core.Genesis {
	return &core.Genesis{
		Config:     config,
		Coinbase:   t.json.Env.Coinbase,
		Difficulty: t.json.Env.Difficulty,
		LifeLimit:   t.json.Env.LifeLimit.Uint64(),
		Number:     t.json.Env.Number,
		Timestamp:  t.json.Env.Timestamp,
		Alloc:      t.json.Pre,
	}
}

func (verx *stTransaction) toMessage(ps stPostState) (core.Message, error) {
	// Derive sender from private key if present.
	var from common.Address
	if len(verx.PrivateKey) > 0 {
		key, err := crypto.ToECDSA(verx.PrivateKey)
		if err != nil {
			return nil, fmt.Errorf("invalid private key: %v", err)
		}
		from = crypto.PubkeyToAddress(key.PublicKey)
	}
	// Parse recipient if present.
	var to *common.Address
	if verx.To != "" {
		to = new(common.Address)
		if err := to.UnmarshalText([]byte(verx.To)); err != nil {
			return nil, fmt.Errorf("invalid to address: %v", err)
		}
	}

	// Get values specific to this post state.
	if ps.Indexes.Data > len(verx.Data) {
		return nil, fmt.Errorf("verx data index %d out of bounds", ps.Indexes.Data)
	}
	if ps.Indexes.Value > len(verx.Value) {
		return nil, fmt.Errorf("verx value index %d out of bounds", ps.Indexes.Value)
	}
	if ps.Indexes.Life > len(verx.LifeLimit) {
		return nil, fmt.Errorf("verx life limit index %d out of bounds", ps.Indexes.Life)
	}
	dataHex := verx.Data[ps.Indexes.Data]
	valueHex := verx.Value[ps.Indexes.Value]
	lifeLimit := verx.LifeLimit[ps.Indexes.Life]
	// Value, Data hex encoding is messy: https://github.com/ariseid/tests/issues/203
	value := new(big.Int)
	if valueHex != "0x" {
		v, ok := math.ParseBig256(valueHex)
		if !ok {
			return nil, fmt.Errorf("invalid verx value %q", valueHex)
		}
		value = v
	}
	data, err := hex.DecodeString(strings.TrimPrefix(dataHex, "0x"))
	if err != nil {
		return nil, fmt.Errorf("invalid verx data %q", dataHex)
	}

	msg := types.NewMessage(from, to, verx.Nonce, value, new(big.Int).SetUint64(lifeLimit), verx.LifePrice, data, true)
	return msg, nil
}

func rlpHash(x interface{}) (h common.Hash) {
	hw := sha3.NewKeccak256()
	rlp.Encode(hw, x)
	hw.Sum(h[:0])
	return h
}
