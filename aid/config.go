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

package aid

import (
	"math/big"
	"os"
	"os/user"
	"path/filepath"
	"runtime"

	"github.com/ariseid/ariseid-core/common"
	"github.com/ariseid/ariseid-core/common/hexutil"
	"github.com/ariseid/ariseid-core/core"
	"github.com/ariseid/ariseid-core/aid/downloader"
	"github.com/ariseid/ariseid-core/aid/lifeprice"
	"github.com/ariseid/ariseid-core/params"
)

// DefaultConfig contains default settings for use on the AriseID main net.
var DefaultConfig = Config{
	SyncMode:             downloader.FastSync,
	IdhashCacheDir:       "idhash",
	IdhashCachesInMem:    2,
	IdhashCachesOnDisk:   3,
	IdhashDatasetsInMem:  1,
	IdhashDatasetsOnDisk: 2,
	NetworkId:            1,
	LightPeers:           20,
	DatabaseCache:        128,
	LifePrice:             big.NewInt(18 * params.Shannon),

	VerxPool: core.DefaultVerxPoolConfig,
	GPO: lifeprice.Config{
		Blocks:     10,
		Percentile: 50,
	},
}

func init() {
	home := os.Getenv("HOME")
	if home == "" {
		if user, err := user.Current(); err == nil {
			home = user.HomeDir
		}
	}
	if runtime.GOOS == "windows" {
		DefaultConfig.IdhashDatasetDir = filepath.Join(home, "AppData", "Idhash")
	} else {
		DefaultConfig.IdhashDatasetDir = filepath.Join(home, ".idhash")
	}
}

//go:generate gencodec -type Config -field-override configMarshaling -formats toml -out gen_config.go

type Config struct {
	// The genesis block, which is inserted if the database is empty.
	// If nil, the AriseID main net block is used.
	Genesis *core.Genesis `toml:",omitempty"`

	// Protocol options
	NetworkId uint64 // Network ID to use for selecting peers to connect to
	SyncMode  downloader.SyncMode

	// Light client options
	LightServ  int `toml:",omitempty"` // Maximum percentage of time allowed for serving LES requests
	LightPeers int `toml:",omitempty"` // Maximum number of LES client peers

	// Database options
	SkipBcVersionCheck bool `toml:"-"`
	DatabaseHandles    int  `toml:"-"`
	DatabaseCache      int

	// Verifying-related options
	IDbase    common.Address `toml:",omitempty"`
	VeriferThreads int            `toml:",omitempty"`
	ExtraData    []byte         `toml:",omitempty"`
	LifePrice     *big.Int

	// Idhash options
	IdhashCacheDir       string
	IdhashCachesInMem    int
	IdhashCachesOnDisk   int
	IdhashDatasetDir     string
	IdhashDatasetsInMem  int
	IdhashDatasetsOnDisk int

	// Verification pool options
	VerxPool core.VerxPoolConfig

	// Life Price Oracle options
	GPO lifeprice.Config

	// Enables tracking of SHA3 preimages in the VM
	EnablePreimageRecording bool

	// Miscellaneous options
	DocRoot   string `toml:"-"`
	PowFake   bool   `toml:"-"`
	PowTest   bool   `toml:"-"`
	PowShared bool   `toml:"-"`
}

type configMarshaling struct {
	ExtraData hexutil.Bytes
}
