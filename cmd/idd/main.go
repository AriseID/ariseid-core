// Copyright 2014 The AriseID Authors
// This file is part AriseID.
//
// AriseID free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// AriseID distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with AriseID. If not, see <http://www.gnu.org/licenses/>.

// idd is the official command-line client for AriseID.
package main

import (
	"fmt"
	"os"
	"runtime"
	"sort"
	"strings"
	"time"

	"github.com/ariseid/ariseid-core/accounts"
	"github.com/ariseid/ariseid-core/accounts/keystore"
	"github.com/ariseid/ariseid-core/cmd/utils"
	"github.com/ariseid/ariseid-core/common"
	"github.com/ariseid/ariseid-core/console"
	"github.com/ariseid/ariseid-core/aid"
	"github.com/ariseid/ariseid-core/aidclient"
	"github.com/ariseid/ariseid-core/internal/debug"
	"github.com/ariseid/ariseid-core/log"
	"github.com/ariseid/ariseid-core/metrics"
	"github.com/ariseid/ariseid-core/node"
	"gopkg.in/urfave/cli.v1"
)

const (
	clientIdentifier = "idd" // Client identifier to advertise over the network
)

var (
	// Git SHA1 commit hash of the release (set via linker flags)
	gitCommit = ""
	// AriseID address of the Idd release oracle.
	relOracle = common.HexToAddress("0xfa7b9770ca4cb04296cac84f37736d4041251cdf")
	// The app that holds all commands and flags.
	app = utils.NewApp(gitCommit, "the AriseID command line interface")
	// flags that configure the node
	nodeFlags = []cli.Flag{
		utils.IdentityFlag,
		utils.UnlockedAccountFlag,
		utils.PasswordFileFlag,
		utils.BootnodesFlag,
		utils.BootnodesV4Flag,
		utils.BootnodesV5Flag,
		utils.DataDirFlag,
		utils.KeyStoreDirFlag,
		utils.NoUSBFlag,
		utils.IdhashCacheDirFlag,
		utils.IdhashCachesInMemoryFlag,
		utils.IdhashCachesOnDiskFlag,
		utils.IdhashDatasetDirFlag,
		utils.IdhashDatasetsInMemoryFlag,
		utils.IdhashDatasetsOnDiskFlag,
		utils.VerxPoolNoLocalsFlag,
		utils.VerxPoolJournalFlag,
		utils.VerxPoolRejournalFlag,
		utils.VerxPoolPriceLimitFlag,
		utils.VerxPoolPriceBumpFlag,
		utils.VerxPoolAccountSlotsFlag,
		utils.VerxPoolGlobalSlotsFlag,
		utils.VerxPoolAccountQueueFlag,
		utils.VerxPoolGlobalQueueFlag,
		utils.VerxPoolLifetimeFlag,
		utils.FastSyncFlag,
		utils.LightModeFlag,
		utils.SyncModeFlag,
		utils.LightServFlag,
		utils.LightPeersFlag,
		utils.LightKDFFlag,
		utils.CacheFlag,
		utils.TrieCacheGenFlag,
		utils.ListenPortFlag,
		utils.MaxPeersFlag,
		utils.MaxPendingPeersFlag,
		utils.IDbaseFlag,
		utils.LifePriceFlag,
		utils.VeriferThreadsFlag,
		utils.VerifyingEnabledFlag,
		utils.TargetLifeLimitFlag,
		utils.NATFlag,
		utils.NoDiscoverFlag,
		utils.DiscoveryV5Flag,
		utils.NetrestrictFlag,
		utils.NodeKeyFileFlag,
		utils.NodeKeyHexFlag,
		utils.DevModeFlag,
		utils.TestnetFlag,
		utils.RinkebyFlag,
		utils.VMEnableDebugFlag,
		utils.NetworkIdFlag,
		utils.RPCCORSDomainFlag,
		utils.EthStatsURLFlag,
		utils.MetricsEnabledFlag,
		utils.FakePoWFlag,
		utils.NoCompactionFlag,
		utils.GpoBlocksFlag,
		utils.GpoPercentileFlag,
		utils.ExtraDataFlag,
		configFileFlag,
	}

	rpcFlags = []cli.Flag{
		utils.RPCEnabledFlag,
		utils.RPCListenAddrFlag,
		utils.RPCPortFlag,
		utils.RPCApiFlag,
		utils.WSEnabledFlag,
		utils.WSListenAddrFlag,
		utils.WSPortFlag,
		utils.WSApiFlag,
		utils.WSAllowedOriginsFlag,
		utils.IPCDisabledFlag,
		utils.IPCPathFlag,
	}

	whisperFlags = []cli.Flag{
		utils.WhisperEnabledFlag,
		utils.WhisperMaxMessageSizeFlag,
		utils.WhisperMinPOWFlag,
	}
)

func init() {
	// Initialize the CLI app and start Idd
	app.Action = idd
	app.HideVersion = true // we have a command to print the version
	app.Copyright = "Copyright 2013-2017 The AriseID Authors"
	app.Commands = []cli.Command{
		// See chaincmd.go:
		initCommand,
		importCommand,
		exportCommand,
		removedbCommand,
		dumpCommand,
		// See monitorcmd.go:
		monitorCommand,
		// See accountcmd.go:
		accountCommand,
		walletCommand,
		// See consolecmd.go:
		consoleCommand,
		attachCommand,
		javascriptCommand,
		// See misccmd.go:
		makecacheCommand,
		makedagCommand,
		versionCommand,
		bugCommand,
		licenseCommand,
		// See config.go
		dumpConfigCommand,
	}
	sort.Sort(cli.CommandsByName(app.Commands))

	app.Flags = append(app.Flags, nodeFlags...)
	app.Flags = append(app.Flags, rpcFlags...)
	app.Flags = append(app.Flags, consoleFlags...)
	app.Flags = append(app.Flags, debug.Flags...)
	app.Flags = append(app.Flags, whisperFlags...)

	app.Before = func(ctx *cli.Context) error {
		runtime.GOMAXPROCS(runtime.NumCPU())
		if err := debug.Setup(ctx); err != nil {
			return err
		}
		// Start system runtime metrics collection
		go metrics.CollectProcessMetrics(3 * time.Second)

		utils.SetupNetwork(ctx)
		return nil
	}

	app.After = func(ctx *cli.Context) error {
		debug.Exit()
		console.Stdin.Close() // Resets terminal mode.
		return nil
	}
}

func main() {
	if err := app.Run(os.Args); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

// idd is the main entry point into the system if no special subcommand is ran.
// It creates a default node based on the command line arguments and runs it in
// blocking mode, waiting for it to be shut down.
func idd(ctx *cli.Context) error {
	node := makeFullNode(ctx)
	startNode(ctx, node)
	node.Wait()
	return nil
}

// startNode boots up the system node and all registered protocols, after which
// it unlocks any requested accounts, and starts the RPC/IPC interfaces and the
// verifier.
func startNode(ctx *cli.Context, stack *node.Node) {
	// Start up the node itself
	utils.StartNode(stack)

	// Unlock any account specifically requested
	ks := stack.AccountManager().Backends(keystore.KeyStoreType)[0].(*keystore.KeyStore)

	passwords := utils.MakePasswordList(ctx)
	unlocks := strings.Split(ctx.GlobalString(utils.UnlockedAccountFlag.Name), ",")
	for i, account := range unlocks {
		if trimmed := strings.TrimSpace(account); trimmed != "" {
			unlockAccount(ctx, ks, trimmed, i, passwords)
		}
	}
	// Register wallet event handlers to open and auto-derive wallets
	events := make(chan accounts.WalletEvent, 16)
	stack.AccountManager().Subscribe(events)

	go func() {
		// Create an chain state reader for self-derivation
		rpcClient, err := stack.Attach()
		if err != nil {
			utils.Fatalf("Failed to attach to self: %v", err)
		}
		stateReader := aidclient.NewClient(rpcClient)

		// Open any wallets already attached
		for _, wallet := range stack.AccountManager().Wallets() {
			if err := wallet.Open(""); err != nil {
				log.Warn("Failed to open wallet", "url", wallet.URL(), "err", err)
			}
		}
		// Listen for wallet event till termination
		for event := range events {
			switch event.Kind {
			case accounts.WalletArrived:
				if err := event.Wallet.Open(""); err != nil {
					log.Warn("New wallet appeared, failed to open", "url", event.Wallet.URL(), "err", err)
				}
			case accounts.WalletOpened:
				status, _ := event.Wallet.Status()
				log.Info("New wallet appeared", "url", event.Wallet.URL(), "status", status)

				if event.Wallet.URL().Scheme == "ledger" {
					event.Wallet.SelfDerive(accounts.DefaultLedgerBaseDerivationPath, stateReader)
				} else {
					event.Wallet.SelfDerive(accounts.DefaultBaseDerivationPath, stateReader)
				}

			case accounts.WalletDropped:
				log.Info("Old wallet dropped", "url", event.Wallet.URL())
				event.Wallet.Close()
			}
		}
	}()
	// Start auxiliary services if enabled
	if ctx.GlobalBool(utils.VerifyingEnabledFlag.Name) {
		// Verifying only makes sense if a full AriseID node is running
		var ariseid *aid.AriseID
		if err := stack.Service(&ariseid); err != nil {
			utils.Fatalf("ariseid service not running: %v", err)
		}
		// Use a reduced number of threads if requested
		if threads := ctx.GlobalInt(utils.VeriferThreadsFlag.Name); threads > 0 {
			type threaded interface {
				SetThreads(threads int)
			}
			if th, ok := ariseid.Engine().(threaded); ok {
				th.SetThreads(threads)
			}
		}
		// Set the life value to the limits from the CLI and start verifying
		ariseid.VerxPool().SetLifePrice(utils.GlobalBig(ctx, utils.LifePriceFlag.Name))
		if err := ariseid.StartVerifying(true); err != nil {
			utils.Fatalf("Failed to start verifying: %v", err)
		}
	}
}
