// Code generated by github.com/fjl/gencodec. DO NOT EDIT.

package aid

import (
	"math/big"

	"github.com/ariseid/ariseid-core/common"
	"github.com/ariseid/ariseid-core/common/hexutil"
	"github.com/ariseid/ariseid-core/core"
	"github.com/ariseid/ariseid-core/aid/downloader"
	"github.com/ariseid/ariseid-core/aid/lifeprice"
)

func (c Config) MarshalTOML() (interface{}, error) {
	type Config struct {
		Genesis                 *core.Genesis `toml:",omitempty"`
		NetworkId               uint64
		SyncMode                downloader.SyncMode
		LightServ               int  `toml:",omitempty"`
		LightPeers              int  `toml:",omitempty"`
		MaxPeers                int  `toml:"-"`
		SkipBcVersionCheck      bool `toml:"-"`
		DatabaseHandles         int  `toml:"-"`
		DatabaseCache           int
		IDbase               common.Address `toml:",omitempty"`
		VeriferThreads            int            `toml:",omitempty"`
		ExtraData               hexutil.Bytes  `toml:",omitempty"`
		LifePrice                *big.Int
		IdhashCacheDir          string
		IdhashCachesInMem       int
		IdhashCachesOnDisk      int
		IdhashDatasetDir        string
		IdhashDatasetsInMem     int
		IdhashDatasetsOnDisk    int
		VerxPool                  core.VerxPoolConfig
		GPO                     lifeprice.Config
		EnablePreimageRecording bool
		DocRoot                 string `toml:"-"`
		PowFake                 bool   `toml:"-"`
		PowTest                 bool   `toml:"-"`
		PowShared               bool   `toml:"-"`
	}
	var enc Config
	enc.Genesis = c.Genesis
	enc.NetworkId = c.NetworkId
	enc.SyncMode = c.SyncMode
	enc.LightServ = c.LightServ
	enc.LightPeers = c.LightPeers
	enc.SkipBcVersionCheck = c.SkipBcVersionCheck
	enc.DatabaseHandles = c.DatabaseHandles
	enc.DatabaseCache = c.DatabaseCache
	enc.IDbase = c.IDbase
	enc.VeriferThreads = c.VeriferThreads
	enc.ExtraData = c.ExtraData
	enc.LifePrice = c.LifePrice
	enc.IdhashCacheDir = c.IdhashCacheDir
	enc.IdhashCachesInMem = c.IdhashCachesInMem
	enc.IdhashCachesOnDisk = c.IdhashCachesOnDisk
	enc.IdhashDatasetDir = c.IdhashDatasetDir
	enc.IdhashDatasetsInMem = c.IdhashDatasetsInMem
	enc.IdhashDatasetsOnDisk = c.IdhashDatasetsOnDisk
	enc.VerxPool = c.VerxPool
	enc.GPO = c.GPO
	enc.EnablePreimageRecording = c.EnablePreimageRecording
	enc.DocRoot = c.DocRoot
	enc.PowFake = c.PowFake
	enc.PowTest = c.PowTest
	enc.PowShared = c.PowShared
	return &enc, nil
}

func (c *Config) UnmarshalTOML(unmarshal func(interface{}) error) error {
	type Config struct {
		Genesis                 *core.Genesis `toml:",omitempty"`
		NetworkId               *uint64
		SyncMode                *downloader.SyncMode
		LightServ               *int  `toml:",omitempty"`
		LightPeers              *int  `toml:",omitempty"`
		MaxPeers                *int  `toml:"-"`
		SkipBcVersionCheck      *bool `toml:"-"`
		DatabaseHandles         *int  `toml:"-"`
		DatabaseCache           *int
		IDbase               *common.Address `toml:",omitempty"`
		VeriferThreads            *int            `toml:",omitempty"`
		ExtraData               hexutil.Bytes   `toml:",omitempty"`
		LifePrice                *big.Int
		IdhashCacheDir          *string
		IdhashCachesInMem       *int
		IdhashCachesOnDisk      *int
		IdhashDatasetDir        *string
		IdhashDatasetsInMem     *int
		IdhashDatasetsOnDisk    *int
		VerxPool                  *core.VerxPoolConfig
		GPO                     *lifeprice.Config
		EnablePreimageRecording *bool
		DocRoot                 *string `toml:"-"`
		PowFake                 *bool   `toml:"-"`
		PowTest                 *bool   `toml:"-"`
		PowShared               *bool   `toml:"-"`
	}
	var dec Config
	if err := unmarshal(&dec); err != nil {
		return err
	}
	if dec.Genesis != nil {
		c.Genesis = dec.Genesis
	}
	if dec.NetworkId != nil {
		c.NetworkId = *dec.NetworkId
	}
	if dec.SyncMode != nil {
		c.SyncMode = *dec.SyncMode
	}
	if dec.LightServ != nil {
		c.LightServ = *dec.LightServ
	}
	if dec.LightPeers != nil {
		c.LightPeers = *dec.LightPeers
	}
	if dec.SkipBcVersionCheck != nil {
		c.SkipBcVersionCheck = *dec.SkipBcVersionCheck
	}
	if dec.DatabaseHandles != nil {
		c.DatabaseHandles = *dec.DatabaseHandles
	}
	if dec.DatabaseCache != nil {
		c.DatabaseCache = *dec.DatabaseCache
	}
	if dec.IDbase != nil {
		c.IDbase = *dec.IDbase
	}
	if dec.VeriferThreads != nil {
		c.VeriferThreads = *dec.VeriferThreads
	}
	if dec.ExtraData != nil {
		c.ExtraData = dec.ExtraData
	}
	if dec.LifePrice != nil {
		c.LifePrice = dec.LifePrice
	}
	if dec.IdhashCacheDir != nil {
		c.IdhashCacheDir = *dec.IdhashCacheDir
	}
	if dec.IdhashCachesInMem != nil {
		c.IdhashCachesInMem = *dec.IdhashCachesInMem
	}
	if dec.IdhashCachesOnDisk != nil {
		c.IdhashCachesOnDisk = *dec.IdhashCachesOnDisk
	}
	if dec.IdhashDatasetDir != nil {
		c.IdhashDatasetDir = *dec.IdhashDatasetDir
	}
	if dec.IdhashDatasetsInMem != nil {
		c.IdhashDatasetsInMem = *dec.IdhashDatasetsInMem
	}
	if dec.IdhashDatasetsOnDisk != nil {
		c.IdhashDatasetsOnDisk = *dec.IdhashDatasetsOnDisk
	}
	if dec.VerxPool != nil {
		c.VerxPool = *dec.VerxPool
	}
	if dec.GPO != nil {
		c.GPO = *dec.GPO
	}
	if dec.EnablePreimageRecording != nil {
		c.EnablePreimageRecording = *dec.EnablePreimageRecording
	}
	if dec.DocRoot != nil {
		c.DocRoot = *dec.DocRoot
	}
	if dec.PowFake != nil {
		c.PowFake = *dec.PowFake
	}
	if dec.PowTest != nil {
		c.PowTest = *dec.PowTest
	}
	if dec.PowShared != nil {
		c.PowShared = *dec.PowShared
	}
	return nil
}