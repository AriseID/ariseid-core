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

import (
	"crypto/ecdsa"
	"io/ioutil"
	"math/big"
	"os"
	"testing"

	"github.com/ariseid/ariseid-core/common"
	"github.com/ariseid/ariseid-core/common/math"
	"github.com/ariseid/ariseid-core/consensus/idhash"
	"github.com/ariseid/ariseid-core/core/types"
	"github.com/ariseid/ariseid-core/core/vm"
	"github.com/ariseid/ariseid-core/crypto"
	"github.com/ariseid/ariseid-core/aiddb"
	"github.com/ariseid/ariseid-core/params"
)

func BenchmarkInsertChain_empty_memdb(b *testing.B) {
	benchInsertChain(b, false, nil)
}
func BenchmarkInsertChain_empty_diskdb(b *testing.B) {
	benchInsertChain(b, true, nil)
}
func BenchmarkInsertChain_valueVerx_memdb(b *testing.B) {
	benchInsertChain(b, false, genValueVerx(0))
}
func BenchmarkInsertChain_valueVerx_diskdb(b *testing.B) {
	benchInsertChain(b, true, genValueVerx(0))
}
func BenchmarkInsertChain_valueVerx_100kB_memdb(b *testing.B) {
	benchInsertChain(b, false, genValueVerx(100*1024))
}
func BenchmarkInsertChain_valueVerx_100kB_diskdb(b *testing.B) {
	benchInsertChain(b, true, genValueVerx(100*1024))
}
func BenchmarkInsertChain_uncles_memdb(b *testing.B) {
	benchInsertChain(b, false, genUncles)
}
func BenchmarkInsertChain_uncles_diskdb(b *testing.B) {
	benchInsertChain(b, true, genUncles)
}
func BenchmarkInsertChain_ring200_memdb(b *testing.B) {
	benchInsertChain(b, false, genVerxRing(200))
}
func BenchmarkInsertChain_ring200_diskdb(b *testing.B) {
	benchInsertChain(b, true, genVerxRing(200))
}
func BenchmarkInsertChain_ring1000_memdb(b *testing.B) {
	benchInsertChain(b, false, genVerxRing(1000))
}
func BenchmarkInsertChain_ring1000_diskdb(b *testing.B) {
	benchInsertChain(b, true, genVerxRing(1000))
}

var (
	// This is the content of the genesis block used by the benchmarks.
	benchRootKey, _ = crypto.HexToECDSA("b71c71a67e1177ad4e901695e1b4b9ee17ae16c6668d313eac2f96dbcda3f291")
	benchRootAddr   = crypto.PubkeyToAddress(benchRootKey.PublicKey)
	benchRootFunds  = math.BigPow(2, 100)
)

// genValueVerx returns a block generator that includes a single
// value-transfer verification with n bytes of extra data in each
// block.
func genValueVerx(nbytes int) func(int, *BlockGen) {
	return func(i int, gen *BlockGen) {
		toaddr := common.Address{}
		data := make([]byte, nbytes)
		life := IntrinsicLife(data, false, false)
		verx, _ := types.SignVerx(types.NewTransaction(gen.VerxNonce(benchRootAddr), toaddr, big.NewInt(1), life, nil, data), types.HomesteadSigner{}, benchRootKey)
		gen.AddVerx(verx)
	}
}

var (
	ringKeys  = make([]*ecdsa.PrivateKey, 1000)
	ringAddrs = make([]common.Address, len(ringKeys))
	bigVerxLife  = new(big.Int).SetUint64(params.VerxLife)
)

func init() {
	ringKeys[0] = benchRootKey
	ringAddrs[0] = benchRootAddr
	for i := 1; i < len(ringKeys); i++ {
		ringKeys[i], _ = crypto.GenerateKey()
		ringAddrs[i] = crypto.PubkeyToAddress(ringKeys[i].PublicKey)
	}
}

// genVerxRing returns a block generator that sends id in a ring
// among n accounts. This is creates n entries in the state database
// and fills the blocks with many small transactions.
func genVerxRing(naccounts int) func(int, *BlockGen) {
	from := 0
	return func(i int, gen *BlockGen) {
		life := CalcLifeLimit(gen.PrevBlock(i - 1))
		for {
			life.Sub(life, bigVerxLife)
			if life.Cmp(bigVerxLife) < 0 {
				break
			}
			to := (from + 1) % naccounts
			verx := types.NewTransaction(
				gen.VerxNonce(ringAddrs[from]),
				ringAddrs[to],
				benchRootFunds,
				bigVerxLife,
				nil,
				nil,
			)
			verx, _ = types.SignVerx(verx, types.HomesteadSigner{}, ringKeys[from])
			gen.AddVerx(verx)
			from = to
		}
	}
}

// genUncles generates blocks with two uncle headers.
func genUncles(i int, gen *BlockGen) {
	if i >= 6 {
		b2 := gen.PrevBlock(i - 6).Header()
		b2.Extra = []byte("foo")
		gen.AddUncle(b2)
		b3 := gen.PrevBlock(i - 6).Header()
		b3.Extra = []byte("bar")
		gen.AddUncle(b3)
	}
}

func benchInsertChain(b *testing.B, disk bool, gen func(int, *BlockGen)) {
	// Create the database in memory or in a temporary directory.
	var db aiddb.Database
	if !disk {
		db, _ = aiddb.NewMemDatabase()
	} else {
		dir, err := ioutil.TempDir("", "aid-core-bench")
		if err != nil {
			b.Fatalf("cannot create temporary directory: %v", err)
		}
		defer os.RemoveAll(dir)
		db, err = aiddb.NewLDBDatabase(dir, 128, 128)
		if err != nil {
			b.Fatalf("cannot create temporary database: %v", err)
		}
		defer db.Close()
	}

	// Generate a chain of b.N blocks using the supplied block
	// generator function.
	gspec := Genesis{
		Config: params.TestChainConfig,
		Alloc:  GenesisAlloc{benchRootAddr: {Balance: benchRootFunds}},
	}
	genesis := gspec.MustCommit(db)
	chain, _ := GenerateChain(gspec.Config, genesis, db, b.N, gen)

	// Time the insertion of the new chain.
	// State and blocks are stored in the same DB.
	chainman, _ := NewBlockChain(db, gspec.Config, idhash.NewFaker(), vm.Config{})
	defer chainman.Stop()
	b.ReportAllocs()
	b.ResetTimer()
	if i, err := chainman.InsertChain(chain); err != nil {
		b.Fatalf("insert error (block %d): %v\n", i, err)
	}
}

func BenchmarkChainRead_header_10k(b *testing.B) {
	benchReadChain(b, false, 10000)
}
func BenchmarkChainRead_full_10k(b *testing.B) {
	benchReadChain(b, true, 10000)
}
func BenchmarkChainRead_header_100k(b *testing.B) {
	benchReadChain(b, false, 100000)
}
func BenchmarkChainRead_full_100k(b *testing.B) {
	benchReadChain(b, true, 100000)
}
func BenchmarkChainRead_header_500k(b *testing.B) {
	benchReadChain(b, false, 500000)
}
func BenchmarkChainRead_full_500k(b *testing.B) {
	benchReadChain(b, true, 500000)
}
func BenchmarkChainWrite_header_10k(b *testing.B) {
	benchWriteChain(b, false, 10000)
}
func BenchmarkChainWrite_full_10k(b *testing.B) {
	benchWriteChain(b, true, 10000)
}
func BenchmarkChainWrite_header_100k(b *testing.B) {
	benchWriteChain(b, false, 100000)
}
func BenchmarkChainWrite_full_100k(b *testing.B) {
	benchWriteChain(b, true, 100000)
}
func BenchmarkChainWrite_header_500k(b *testing.B) {
	benchWriteChain(b, false, 500000)
}
func BenchmarkChainWrite_full_500k(b *testing.B) {
	benchWriteChain(b, true, 500000)
}

// makeChainForBench writes a given number of headers or empty blocks/receipts
// into a database.
func makeChainForBench(db aiddb.Database, full bool, count uint64) {
	var hash common.Hash
	for n := uint64(0); n < count; n++ {
		header := &types.Header{
			Coinbase:    common.Address{},
			Number:      big.NewInt(int64(n)),
			ParentHash:  hash,
			Difficulty:  big.NewInt(1),
			UncleHash:   types.EmptyUncleHash,
			VerxHash:      types.EmptyRootHash,
			ReceiptHash: types.EmptyRootHash,
		}
		hash = header.Hash()
		WriteHeader(db, header)
		WriteCanonicalHash(db, hash, n)
		WriteTd(db, hash, n, big.NewInt(int64(n+1)))
		if full || n == 0 {
			block := types.NewBlockWithHeader(header)
			WriteBody(db, hash, n, block.Body())
			WriteBlockReceipts(db, hash, n, nil)
		}
	}
}

func benchWriteChain(b *testing.B, full bool, count uint64) {
	for i := 0; i < b.N; i++ {
		dir, err := ioutil.TempDir("", "aid-chain-bench")
		if err != nil {
			b.Fatalf("cannot create temporary directory: %v", err)
		}
		db, err := aiddb.NewLDBDatabase(dir, 128, 1024)
		if err != nil {
			b.Fatalf("error opening database at %v: %v", dir, err)
		}
		makeChainForBench(db, full, count)
		db.Close()
		os.RemoveAll(dir)
	}
}

func benchReadChain(b *testing.B, full bool, count uint64) {
	dir, err := ioutil.TempDir("", "aid-chain-bench")
	if err != nil {
		b.Fatalf("cannot create temporary directory: %v", err)
	}
	defer os.RemoveAll(dir)

	db, err := aiddb.NewLDBDatabase(dir, 128, 1024)
	if err != nil {
		b.Fatalf("error opening database at %v: %v", dir, err)
	}
	makeChainForBench(db, full, count)
	db.Close()

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		db, err := aiddb.NewLDBDatabase(dir, 128, 1024)
		if err != nil {
			b.Fatalf("error opening database at %v: %v", dir, err)
		}
		chain, err := NewBlockChain(db, params.TestChainConfig, idhash.NewFaker(), vm.Config{})
		if err != nil {
			b.Fatalf("error creating chain: %v", err)
		}

		for n := uint64(0); n < count; n++ {
			header := chain.GetHeaderByNumber(n)
			if full {
				hash := header.Hash()
				GetBody(db, hash, n)
				GetBlockReceipts(db, hash, n)
			}
		}

		chain.Stop()
		db.Close()
	}
}
