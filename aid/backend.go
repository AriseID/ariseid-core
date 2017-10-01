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

// Package aid implements the AriseID protocol.
package aid

import (
	"errors"
	"fmt"
	"math/big"
	"runtime"
	"sync"
	"sync/atomic"

	"github.com/ariseid/ariseid-core/accounts"
	"github.com/ariseid/ariseid-core/common"
	"github.com/ariseid/ariseid-core/common/hexutil"
	"github.com/ariseid/ariseid-core/consensus"
	"github.com/ariseid/ariseid-core/consensus/clique"
	"github.com/ariseid/ariseid-core/consensus/idhash"
	"github.com/ariseid/ariseid-core/core"
	"github.com/ariseid/ariseid-core/core/bloombits"
	"github.com/ariseid/ariseid-core/core/types"
	"github.com/ariseid/ariseid-core/core/vm"
	"github.com/ariseid/ariseid-core/aid/downloader"
	"github.com/ariseid/ariseid-core/aid/filters"
	"github.com/ariseid/ariseid-core/aid/lifeprice"
	"github.com/ariseid/ariseid-core/aiddb"
	"github.com/ariseid/ariseid-core/event"
	"github.com/ariseid/ariseid-core/internal/aidapi"
	"github.com/ariseid/ariseid-core/log"
	"github.com/ariseid/ariseid-core/verifier"
	"github.com/ariseid/ariseid-core/node"
	"github.com/ariseid/ariseid-core/p2p"
	"github.com/ariseid/ariseid-core/params"
	"github.com/ariseid/ariseid-core/rlp"
	"github.com/ariseid/ariseid-core/rpc"
)

type LesServer interface {
	Start(srvr *p2p.Server)
	Stop()
	Protocols() []p2p.Protocol
}

// AriseID implements the AriseID full node service.
type AriseID struct {
	config      *Config
	chainConfig *params.ChainConfig

	// Channel for shutting down the service
	shutdownChan  chan bool    // Channel for shutting down the ariseid
	stopDbUpgrade func() error // stop chain db sequential key upgrade

	// Handlers
	txPool          *core.VerxPool
	blockchain      *core.BlockChain
	protocolManager *ProtocolManager
	lesServer       LesServer

	// DB interfaces
	chainDb aiddb.Database // Block chain database

	eventMux       *event.TypeMux
	engine         consensus.Engine
	accountManager *accounts.Manager

	bloomRequests chan chan *bloombits.Retrieval // Channel receiving bloom data retrieval requests
	bloomIndexer  *core.ChainIndexer             // Bloom indexer operating during block imports

	ApiBackend *IddApiBackend

	verifier     *verifier.Verifer
	lifePrice  *big.Int
	idbase common.Address

	networkId     uint64
	netRPCService *aidapi.PublicNetAPI

	lock sync.RWMutex // Protects the variadic fields (e.g. life value and idbase)
}

func (s *AriseID) AddLesServer(ls LesServer) {
	s.lesServer = ls
}

// New creates a new AriseID object (including the
// initialisation of the common AriseID object)
func New(ctx *node.ServiceContext, config *Config) (*AriseID, error) {
	if config.SyncMode == downloader.LightSync {
		return nil, errors.New("can't run aid.AriseID in light sync mode, use les.LightAriseID")
	}
	if !config.SyncMode.IsValid() {
		return nil, fmt.Errorf("invalid sync mode %d", config.SyncMode)
	}
	chainDb, err := CreateDB(ctx, config, "chaindata")
	if err != nil {
		return nil, err
	}
	stopDbUpgrade := upgradeDeduplicateData(chainDb)
	chainConfig, genesisHash, genesisErr := core.SetupGenesisBlock(chainDb, config.Genesis)
	if _, ok := genesisErr.(*params.ConfigCompatError); genesisErr != nil && !ok {
		return nil, genesisErr
	}
	log.Info("Initialised chain configuration", "config", chainConfig)

	aid := &AriseID{
		config:         config,
		chainDb:        chainDb,
		chainConfig:    chainConfig,
		eventMux:       ctx.EventMux,
		accountManager: ctx.AccountManager,
		engine:         CreateConsensusEngine(ctx, config, chainConfig, chainDb),
		shutdownChan:   make(chan bool),
		stopDbUpgrade:  stopDbUpgrade,
		networkId:      config.NetworkId,
		lifePrice:       config.LifePrice,
		idbase:      config.IDbase,
		bloomRequests:  make(chan chan *bloombits.Retrieval),
		bloomIndexer:   NewBloomIndexer(chainDb, params.BloomBitsBlocks),
	}

	log.Info("Initialising AriseID protocol", "versions", ProtocolVersions, "network", config.NetworkId)

	if !config.SkipBcVersionCheck {
		bcVersion := core.GetBlockChainVersion(chainDb)
		if bcVersion != core.BlockChainVersion && bcVersion != 0 {
			return nil, fmt.Errorf("Blockchain DB version mismatch (%d / %d). Run idd upgradedb.\n", bcVersion, core.BlockChainVersion)
		}
		core.WriteBlockChainVersion(chainDb, core.BlockChainVersion)
	}

	vmConfig := vm.Config{EnablePreimageRecording: config.EnablePreimageRecording}
	aid.blockchain, err = core.NewBlockChain(chainDb, aid.chainConfig, aid.engine, vmConfig)
	if err != nil {
		return nil, err
	}
	// Rewind the chain in case of an incompatible config upgrade.
	if compat, ok := genesisErr.(*params.ConfigCompatError); ok {
		log.Warn("Rewinding chain to upgrade configuration", "err", compat)
		aid.blockchain.SetHead(compat.RewindTo)
		core.WriteChainConfig(chainDb, genesisHash, chainConfig)
	}
	aid.bloomIndexer.Start(aid.blockchain.CurrentHeader(), aid.blockchain.SubscribeChainEvent)

	if config.VerxPool.Journal != "" {
		config.VerxPool.Journal = ctx.ResolvePath(config.VerxPool.Journal)
	}
	aid.txPool = core.NewVerxPool(config.VerxPool, aid.chainConfig, aid.blockchain)

	if aid.protocolManager, err = NewProtocolManager(aid.chainConfig, config.SyncMode, config.NetworkId, aid.eventMux, aid.txPool, aid.engine, aid.blockchain, chainDb); err != nil {
		return nil, err
	}
	aid.verifier = verifier.New(aid, aid.chainConfig, aid.EventMux(), aid.engine)
	aid.verifier.SetExtra(makeExtraData(config.ExtraData))

	aid.ApiBackend = &IddApiBackend{aid, nil}
	gpoParams := config.GPO
	if gpoParams.Default == nil {
		gpoParams.Default = config.LifePrice
	}
	aid.ApiBackend.gpo = lifeprice.NewOracle(aid.ApiBackend, gpoParams)

	return aid, nil
}

func makeExtraData(extra []byte) []byte {
	if len(extra) == 0 {
		// create default extradata
		extra, _ = rlp.EncodeToBytes([]interface{}{
			uint(params.VersionMajor<<16 | params.VersionMinor<<8 | params.VersionPatch),
			"idd",
			runtime.Version(),
			runtime.GOOS,
		})
	}
	if uint64(len(extra)) > params.MaximumExtraDataSize {
		log.Warn("Verifer extra data exceed limit", "extra", hexutil.Bytes(extra), "limit", params.MaximumExtraDataSize)
		extra = nil
	}
	return extra
}

// CreateDB creates the chain database.
func CreateDB(ctx *node.ServiceContext, config *Config, name string) (aiddb.Database, error) {
	db, err := ctx.OpenDatabase(name, config.DatabaseCache, config.DatabaseHandles)
	if err != nil {
		return nil, err
	}
	if db, ok := db.(*aiddb.LDBDatabase); ok {
		db.Meter("aid/db/chaindata/")
	}
	return db, nil
}

// CreateConsensusEngine creates the required type of consensus engine instance for an AriseID service
func CreateConsensusEngine(ctx *node.ServiceContext, config *Config, chainConfig *params.ChainConfig, db aiddb.Database) consensus.Engine {
	// If proof-of-authority is requested, set it up
	if chainConfig.Clique != nil {
		return clique.New(chainConfig.Clique, db)
	}
	// Otherwise assume proof-of-work
	switch {
	case config.PowFake:
		log.Warn("Idhash used in fake mode")
		return idhash.NewFaker()
	case config.PowTest:
		log.Warn("Idhash used in test mode")
		return idhash.NewTester()
	case config.PowShared:
		log.Warn("Idhash used in shared mode")
		return idhash.NewShared()
	default:
		engine := idhash.New(ctx.ResolvePath(config.IdhashCacheDir), config.IdhashCachesInMem, config.IdhashCachesOnDisk,
			config.IdhashDatasetDir, config.IdhashDatasetsInMem, config.IdhashDatasetsOnDisk)
		engine.SetThreads(-1) // Disable CPU verifying
		return engine
	}
}

// APIs returns the collection of RPC services the ariseid package offers.
// NOTE, some of these services probably need to be moved to somewhere else.
func (s *AriseID) APIs() []rpc.API {
	apis := aidapi.GetAPIs(s.ApiBackend)

	// Append any APIs exposed explicitly by the consensus engine
	apis = append(apis, s.engine.APIs(s.BlockChain())...)

	// Append all the local APIs and return
	return append(apis, []rpc.API{
		{
			Namespace: "aid",
			Version:   "1.0",
			Service:   NewPublicAriseIDAPI(s),
			Public:    true,
		}, {
			Namespace: "aid",
			Version:   "1.0",
			Service:   NewPublicVeriferAPI(s),
			Public:    true,
		}, {
			Namespace: "aid",
			Version:   "1.0",
			Service:   downloader.NewPublicDownloaderAPI(s.protocolManager.downloader, s.eventMux),
			Public:    true,
		}, {
			Namespace: "verifier",
			Version:   "1.0",
			Service:   NewPrivateVeriferAPI(s),
			Public:    false,
		}, {
			Namespace: "aid",
			Version:   "1.0",
			Service:   filters.NewPublicFilterAPI(s.ApiBackend, false),
			Public:    true,
		}, {
			Namespace: "admin",
			Version:   "1.0",
			Service:   NewPrivateAdminAPI(s),
		}, {
			Namespace: "debug",
			Version:   "1.0",
			Service:   NewPublicDebugAPI(s),
			Public:    true,
		}, {
			Namespace: "debug",
			Version:   "1.0",
			Service:   NewPrivateDebugAPI(s.chainConfig, s),
		}, {
			Namespace: "net",
			Version:   "1.0",
			Service:   s.netRPCService,
			Public:    true,
		},
	}...)
}

func (s *AriseID) ResetWithGenesisBlock(gb *types.Block) {
	s.blockchain.ResetWithGenesisBlock(gb)
}

func (s *AriseID) IDbase() (eb common.Address, err error) {
	s.lock.RLock()
	idbase := s.idbase
	s.lock.RUnlock()

	if idbase != (common.Address{}) {
		return idbase, nil
	}
	if wallets := s.AccountManager().Wallets(); len(wallets) > 0 {
		if accounts := wallets[0].Accounts(); len(accounts) > 0 {
			return accounts[0].Address, nil
		}
	}
	return common.Address{}, fmt.Errorf("idbase address must be explicitly specified")
}

// set in js console via admin interface or wrapper from cli flags
func (self *AriseID) SetIDbase(idbase common.Address) {
	self.lock.Lock()
	self.idbase = idbase
	self.lock.Unlock()

	self.verifier.SetIDbase(idbase)
}

func (s *AriseID) StartVerifying(local bool) error {
	eb, err := s.IDbase()
	if err != nil {
		log.Error("Cannot start verifying without idbase", "err", err)
		return fmt.Errorf("idbase missing: %v", err)
	}
	if clique, ok := s.engine.(*clique.Clique); ok {
		wallet, err := s.accountManager.Find(accounts.Account{Address: eb})
		if wallet == nil || err != nil {
			log.Error("IDbase account unavailable locally", "err", err)
			return fmt.Errorf("singer missing: %v", err)
		}
		clique.Authorize(eb, wallet.SignHash)
	}
	if local {
		// If local (CPU) verifying is started, we can disable the verification rejection
		// mechanism introduced to speed sync times. CPU verifying on mainnet is ludicrous
		// so noone will ever hit this path, whereas marking sync done on CPU verifying
		// will ensure that private networks work in single verifier mode too.
		atomic.StoreUint32(&s.protocolManager.acceptVerxs, 1)
	}
	go s.verifier.Start(eb)
	return nil
}

func (s *AriseID) StopVerifying()         { s.verifier.Stop() }
func (s *AriseID) IsVerifying() bool      { return s.verifier.Verifying() }
func (s *AriseID) Verifer() *verifier.Verifer { return s.verifier }

func (s *AriseID) AccountManager() *accounts.Manager  { return s.accountManager }
func (s *AriseID) BlockChain() *core.BlockChain       { return s.blockchain }
func (s *AriseID) VerxPool() *core.VerxPool               { return s.txPool }
func (s *AriseID) EventMux() *event.TypeMux           { return s.eventMux }
func (s *AriseID) Engine() consensus.Engine           { return s.engine }
func (s *AriseID) ChainDb() aiddb.Database            { return s.chainDb }
func (s *AriseID) IsListening() bool                  { return true } // Always listening
func (s *AriseID) AidVersion() int                    { return int(s.protocolManager.SubProtocols[0].Version) }
func (s *AriseID) NetVersion() uint64                 { return s.networkId }
func (s *AriseID) Downloader() *downloader.Downloader { return s.protocolManager.downloader }

// Protocols implements node.Service, returning all the currently configured
// network protocols to start.
func (s *AriseID) Protocols() []p2p.Protocol {
	if s.lesServer == nil {
		return s.protocolManager.SubProtocols
	}
	return append(s.protocolManager.SubProtocols, s.lesServer.Protocols()...)
}

// Start implements node.Service, starting all internal goroutines needed by the
// AriseID protocol implementation.
func (s *AriseID) Start(srvr *p2p.Server) error {
	// Start the bloom bits servicing goroutines
	s.startBloomHandlers()

	// Start the RPC service
	s.netRPCService = aidapi.NewPublicNetAPI(srvr, s.NetVersion())

	// Figure out a max peers count based on the server limits
	maxPeers := srvr.MaxPeers
	if s.config.LightServ > 0 {
		maxPeers -= s.config.LightPeers
		if maxPeers < srvr.MaxPeers/2 {
			maxPeers = srvr.MaxPeers / 2
		}
	}
	// Start the networking layer and the light server if requested
	s.protocolManager.Start(maxPeers)
	if s.lesServer != nil {
		s.lesServer.Start(srvr)
	}
	return nil
}

// Stop implements node.Service, terminating all internal goroutines used by the
// AriseID protocol.
func (s *AriseID) Stop() error {
	if s.stopDbUpgrade != nil {
		s.stopDbUpgrade()
	}
	s.bloomIndexer.Close()
	s.blockchain.Stop()
	s.protocolManager.Stop()
	if s.lesServer != nil {
		s.lesServer.Stop()
	}
	s.txPool.Stop()
	s.verifier.Stop()
	s.eventMux.Stop()

	s.chainDb.Close()
	close(s.shutdownChan)

	return nil
}
