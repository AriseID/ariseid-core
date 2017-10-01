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

// Package les implements the Light AriseID Subprotocol.
package les

import (
	"fmt"
	"sync"
	"time"

	"github.com/ariseid/ariseid-core/accounts"
	"github.com/ariseid/ariseid-core/common"
	"github.com/ariseid/ariseid-core/common/hexutil"
	"github.com/ariseid/ariseid-core/consensus"
	"github.com/ariseid/ariseid-core/core"
	"github.com/ariseid/ariseid-core/core/types"
	"github.com/ariseid/ariseid-core/aid"
	"github.com/ariseid/ariseid-core/aid/downloader"
	"github.com/ariseid/ariseid-core/aid/filters"
	"github.com/ariseid/ariseid-core/aid/lifeprice"
	"github.com/ariseid/ariseid-core/aiddb"
	"github.com/ariseid/ariseid-core/event"
	"github.com/ariseid/ariseid-core/internal/aidapi"
	"github.com/ariseid/ariseid-core/light"
	"github.com/ariseid/ariseid-core/log"
	"github.com/ariseid/ariseid-core/node"
	"github.com/ariseid/ariseid-core/p2p"
	"github.com/ariseid/ariseid-core/p2p/discv5"
	"github.com/ariseid/ariseid-core/params"
	rpc "github.com/ariseid/ariseid-core/rpc"
)

type LightAriseID struct {
	odr         *LesOdr
	relay       *LesVerxRelay
	chainConfig *params.ChainConfig
	// Channel for shutting down the service
	shutdownChan chan bool
	// Handlers
	peers           *peerSet
	txPool          *light.VerxPool
	blockchain      *light.LightChain
	protocolManager *ProtocolManager
	serverPool      *serverPool
	reqDist         *requestDistributor
	retriever       *retrieveManager
	// DB interfaces
	chainDb aiddb.Database // Block chain database

	ApiBackend *LesApiBackend

	eventMux       *event.TypeMux
	engine         consensus.Engine
	accountManager *accounts.Manager

	networkId     uint64
	netRPCService *aidapi.PublicNetAPI

	wg sync.WaitGroup
}

func New(ctx *node.ServiceContext, config *aid.Config) (*LightAriseID, error) {
	chainDb, err := aid.CreateDB(ctx, config, "lightchaindata")
	if err != nil {
		return nil, err
	}
	chainConfig, genesisHash, genesisErr := core.SetupGenesisBlock(chainDb, config.Genesis)
	if _, isCompat := genesisErr.(*params.ConfigCompatError); genesisErr != nil && !isCompat {
		return nil, genesisErr
	}
	log.Info("Initialised chain configuration", "config", chainConfig)

	peers := newPeerSet()
	quitSync := make(chan struct{})

	aid := &LightAriseID{
		chainConfig:    chainConfig,
		chainDb:        chainDb,
		eventMux:       ctx.EventMux,
		peers:          peers,
		reqDist:        newRequestDistributor(peers, quitSync),
		accountManager: ctx.AccountManager,
		engine:         aid.CreateConsensusEngine(ctx, config, chainConfig, chainDb),
		shutdownChan:   make(chan bool),
		networkId:      config.NetworkId,
	}

	aid.relay = NewLesVerxRelay(peers, aid.reqDist)
	aid.serverPool = newServerPool(chainDb, quitSync, &aid.wg)
	aid.retriever = newRetrieveManager(peers, aid.reqDist, aid.serverPool)
	aid.odr = NewLesOdr(chainDb, aid.retriever)
	if aid.blockchain, err = light.NewLightChain(aid.odr, aid.chainConfig, aid.engine); err != nil {
		return nil, err
	}
	// Rewind the chain in case of an incompatible config upgrade.
	if compat, ok := genesisErr.(*params.ConfigCompatError); ok {
		log.Warn("Rewinding chain to upgrade configuration", "err", compat)
		aid.blockchain.SetHead(compat.RewindTo)
		core.WriteChainConfig(chainDb, genesisHash, chainConfig)
	}

	aid.txPool = light.NewVerxPool(aid.chainConfig, aid.blockchain, aid.relay)
	if aid.protocolManager, err = NewProtocolManager(aid.chainConfig, true, config.NetworkId, aid.eventMux, aid.engine, aid.peers, aid.blockchain, nil, chainDb, aid.odr, aid.relay, quitSync, &aid.wg); err != nil {
		return nil, err
	}
	aid.ApiBackend = &LesApiBackend{aid, nil}
	gpoParams := config.GPO
	if gpoParams.Default == nil {
		gpoParams.Default = config.LifePrice
	}
	aid.ApiBackend.gpo = lifeprice.NewOracle(aid.ApiBackend, gpoParams)
	return aid, nil
}

func lesTopic(genesisHash common.Hash) discv5.Topic {
	return discv5.Topic("LES@" + common.Bytes2Hex(genesisHash.Bytes()[0:8]))
}

type LightDummyAPI struct{}

// IDbase is the address that verifying rewards will be send to
func (s *LightDummyAPI) IDbase() (common.Address, error) {
	return common.Address{}, fmt.Errorf("not supported")
}

// Coinbase is the address that verifying rewards will be send to (alias for IDbase)
func (s *LightDummyAPI) Coinbase() (common.Address, error) {
	return common.Address{}, fmt.Errorf("not supported")
}

// Hashrate returns the POW hashrate
func (s *LightDummyAPI) Hashrate() hexutil.Uint {
	return 0
}

// Verifying returns an indication if this node is currently verifying.
func (s *LightDummyAPI) Verifying() bool {
	return false
}

// APIs returns the collection of RPC services the ariseid package offers.
// NOTE, some of these services probably need to be moved to somewhere else.
func (s *LightAriseID) APIs() []rpc.API {
	return append(aidapi.GetAPIs(s.ApiBackend), []rpc.API{
		{
			Namespace: "aid",
			Version:   "1.0",
			Service:   &LightDummyAPI{},
			Public:    true,
		}, {
			Namespace: "aid",
			Version:   "1.0",
			Service:   downloader.NewPublicDownloaderAPI(s.protocolManager.downloader, s.eventMux),
			Public:    true,
		}, {
			Namespace: "aid",
			Version:   "1.0",
			Service:   filters.NewPublicFilterAPI(s.ApiBackend, true),
			Public:    true,
		}, {
			Namespace: "net",
			Version:   "1.0",
			Service:   s.netRPCService,
			Public:    true,
		},
	}...)
}

func (s *LightAriseID) ResetWithGenesisBlock(gb *types.Block) {
	s.blockchain.ResetWithGenesisBlock(gb)
}

func (s *LightAriseID) BlockChain() *light.LightChain      { return s.blockchain }
func (s *LightAriseID) VerxPool() *light.VerxPool              { return s.txPool }
func (s *LightAriseID) Engine() consensus.Engine           { return s.engine }
func (s *LightAriseID) LesVersion() int                    { return int(s.protocolManager.SubProtocols[0].Version) }
func (s *LightAriseID) Downloader() *downloader.Downloader { return s.protocolManager.downloader }
func (s *LightAriseID) EventMux() *event.TypeMux           { return s.eventMux }

// Protocols implements node.Service, returning all the currently configured
// network protocols to start.
func (s *LightAriseID) Protocols() []p2p.Protocol {
	return s.protocolManager.SubProtocols
}

// Start implements node.Service, starting all internal goroutines needed by the
// AriseID protocol implementation.
func (s *LightAriseID) Start(srvr *p2p.Server) error {
	log.Warn("Light client mode is an experimental feature")
	s.netRPCService = aidapi.NewPublicNetAPI(srvr, s.networkId)
	s.serverPool.start(srvr, lesTopic(s.blockchain.Genesis().Hash()))
	s.protocolManager.Start()
	return nil
}

// Stop implements node.Service, terminating all internal goroutines used by the
// AriseID protocol.
func (s *LightAriseID) Stop() error {
	s.odr.Stop()
	s.blockchain.Stop()
	s.protocolManager.Stop()
	s.txPool.Stop()

	s.eventMux.Stop()

	time.Sleep(time.Millisecond * 200)
	s.chainDb.Close()
	close(s.shutdownChan)

	return nil
}
