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

// Contains all the wrappers from the node package to support client side node
// management on mobile platforms.

package idd

import (
	"encoding/json"
	"fmt"
	"path/filepath"

	"github.com/ariseid/ariseid-core/core"
	"github.com/ariseid/ariseid-core/aid"
	"github.com/ariseid/ariseid-core/aid/downloader"
	"github.com/ariseid/ariseid-core/aidclient"
	"github.com/ariseid/ariseid-core/aidstats"
	"github.com/ariseid/ariseid-core/les"
	"github.com/ariseid/ariseid-core/node"
	"github.com/ariseid/ariseid-core/p2p"
	"github.com/ariseid/ariseid-core/p2p/nat"
	"github.com/ariseid/ariseid-core/params"
	whisper "github.com/ariseid/ariseid-core/whisper/whisperv5"
)

// NodeConfig represents the collection of configuration values to fine tune the Idd
// node embedded into a mobile process. The available values are a subset of the
// entire API provided by AriseID to reduce the maintenance surface and dev
// complexity.
type NodeConfig struct {
	// Bootstrap nodes used to establish connectivity with the rest of the network.
	BootstrapNodes *Enodes

	// MaxPeers is the maximum number of peers that can be connected. If this is
	// set to zero, then only the configured static and trusted peers can connect.
	MaxPeers int

	// AriseIDEnabled specifies whid the node should run the AriseID protocol.
	AriseIDEnabled bool

	// AriseIDNetworkID is the network identifier used by the AriseID protocol to
	// decide if remote peers should be accepted or not.
	AriseIDNetworkID int64 // uint64 in truth, but Java can't handle that...

	// AriseIDGenesis is the genesis JSON to use to seed the blockchain with. An
	// empty genesis state is equivalent to using the mainnet's state.
	AriseIDGenesis string

	// AriseIDDatabaseCache is the system memory in MB to allocate for database caching.
	// A minimum of 16MB is always reserved.
	AriseIDDatabaseCache int

	// AriseIDNetStats is a netstats connection string to use to report various
	// chain, verification and node stats to a monitoring server.
	//
	// It has the form "nodename:secret@host:port"
	AriseIDNetStats string

	// WhisperEnabled specifies whid the node should run the Whisper protocol.
	WhisperEnabled bool
}

// defaultNodeConfig contains the default node configuration values to use if all
// or some fields are missing from the user's specified list.
var defaultNodeConfig = &NodeConfig{
	BootstrapNodes:        FoundationBootnodes(),
	MaxPeers:              25,
	AriseIDEnabled:       true,
	AriseIDNetworkID:     1,
	AriseIDDatabaseCache: 16,
}

// NewNodeConfig creates a new node option set, initialized to the default values.
func NewNodeConfig() *NodeConfig {
	config := *defaultNodeConfig
	return &config
}

// Node represents a Idd AriseID node instance.
type Node struct {
	node *node.Node
}

// NewNode creates and configures a new Idd node.
func NewNode(datadir string, config *NodeConfig) (stack *Node, _ error) {
	// If no or partial configurations were specified, use defaults
	if config == nil {
		config = NewNodeConfig()
	}
	if config.MaxPeers == 0 {
		config.MaxPeers = defaultNodeConfig.MaxPeers
	}
	if config.BootstrapNodes == nil || config.BootstrapNodes.Size() == 0 {
		config.BootstrapNodes = defaultNodeConfig.BootstrapNodes
	}
	// Create the empty networking stack
	nodeConf := &node.Config{
		Name:        clientIdentifier,
		Version:     params.Version,
		DataDir:     datadir,
		KeyStoreDir: filepath.Join(datadir, "keystore"), // Mobile should never use internal keystores!
		P2P: p2p.Config{
			NoDiscovery:      true,
			DiscoveryV5:      true,
			DiscoveryV5Addr:  ":0",
			BootstrapNodesV5: config.BootstrapNodes.nodes,
			ListenAddr:       ":0",
			NAT:              nat.Any(),
			MaxPeers:         config.MaxPeers,
		},
	}
	rawStack, err := node.New(nodeConf)
	if err != nil {
		return nil, err
	}

	var genesis *core.Genesis
	if config.AriseIDGenesis != "" {
		// Parse the user supplied genesis spec if not mainnet
		genesis = new(core.Genesis)
		if err := json.Unmarshal([]byte(config.AriseIDGenesis), genesis); err != nil {
			return nil, fmt.Errorf("invalid genesis spec: %v", err)
		}
		// If we have the testnet, hard code the chain configs too
		if config.AriseIDGenesis == TestnetGenesis() {
			genesis.Config = params.TestnetChainConfig
			if config.AriseIDNetworkID == 1 {
				config.AriseIDNetworkID = 3
			}
		}
	}
	// Register the AriseID protocol if requested
	if config.AriseIDEnabled {
		ethConf := aid.DefaultConfig
		ethConf.Genesis = genesis
		ethConf.SyncMode = downloader.LightSync
		ethConf.NetworkId = uint64(config.AriseIDNetworkID)
		ethConf.DatabaseCache = config.AriseIDDatabaseCache
		if err := rawStack.Register(func(ctx *node.ServiceContext) (node.Service, error) {
			return les.New(ctx, &ethConf)
		}); err != nil {
			return nil, fmt.Errorf("ariseid init: %v", err)
		}
		// If netstats reporting is requested, do it
		if config.AriseIDNetStats != "" {
			if err := rawStack.Register(func(ctx *node.ServiceContext) (node.Service, error) {
				var lesServ *les.LightAriseID
				ctx.Service(&lesServ)

				return aidstats.New(config.AriseIDNetStats, nil, lesServ)
			}); err != nil {
				return nil, fmt.Errorf("netstats init: %v", err)
			}
		}
	}
	// Register the Whisper protocol if requested
	if config.WhisperEnabled {
		if err := rawStack.Register(func(*node.ServiceContext) (node.Service, error) {
			return whisper.New(&whisper.DefaultConfig), nil
		}); err != nil {
			return nil, fmt.Errorf("whisper init: %v", err)
		}
	}
	return &Node{rawStack}, nil
}

// Start creates a live P2P node and starts running it.
func (n *Node) Start() error {
	return n.node.Start()
}

// Stop terminates a running node along with all it's services. In the node was
// not started, an error is returned.
func (n *Node) Stop() error {
	return n.node.Stop()
}

// GetAriseIDClient retrieves a client to access the AriseID subsystem.
func (n *Node) GetAriseIDClient() (client *AriseIDClient, _ error) {
	rpc, err := n.node.Attach()
	if err != nil {
		return nil, err
	}
	return &AriseIDClient{aidclient.NewClient(rpc)}, nil
}

// GetNodeInfo gathers and returns a collection of metadata known about the host.
func (n *Node) GetNodeInfo() *NodeInfo {
	return &NodeInfo{n.node.Server().NodeInfo()}
}

// GetPeersInfo returns an array of metadata objects describing connected peers.
func (n *Node) GetPeersInfo() *PeerInfos {
	return &PeerInfos{n.node.Server().PeersInfo()}
}
