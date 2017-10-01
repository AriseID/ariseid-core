// Copyright 2017 The AriseID Authors
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

package main

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/ariseid/ariseid-core/accounts/keystore"
	"github.com/ariseid/ariseid-core/common"
	"github.com/ariseid/ariseid-core/log"
)

// deployNode creates a new node configuration based on some user input.
func (w *wizard) deployNode(boot bool) {
	// Do some sanity check before the user wastes time on input
	if w.conf.genesis == nil {
		log.Error("No genesis block configured")
		return
	}
	if w.conf.aidstats == "" {
		log.Error("No aidstats server configured")
		return
	}
	// Select the server to interact with
	server := w.selectServer()
	if server == "" {
		return
	}
	client := w.servers[server]

	// Retrieve any active aidstats configurations from the server
	infos, err := checkNode(client, w.network, boot)
	if err != nil {
		if boot {
			infos = &nodeInfos{portFull: 30303, peersTotal: 512, peersLight: 256}
		} else {
			infos = &nodeInfos{portFull: 30303, peersTotal: 50, peersLight: 0, lifeTarget: 4.7, lifePrice: 18}
		}
	}
	infos.genesis, _ = json.MarshalIndent(w.conf.genesis, "", "  ")
	infos.network = w.conf.genesis.Config.ChainId.Int64()

	// Figure out where the user wants to store the persistent data
	fmt.Println()
	if infos.datadir == "" {
		fmt.Printf("Where should data be stored on the remote machine?\n")
		infos.datadir = w.readString()
	} else {
		fmt.Printf("Where should data be stored on the remote machine? (default = %s)\n", infos.datadir)
		infos.datadir = w.readDefaultString(infos.datadir)
	}
	// Figure out which port to listen on
	fmt.Println()
	fmt.Printf("Which TCP/UDP port to listen on? (default = %d)\n", infos.portFull)
	infos.portFull = w.readDefaultInt(infos.portFull)

	// Figure out how many peers to allow (different based on node type)
	fmt.Println()
	fmt.Printf("How many peers to allow connecting? (default = %d)\n", infos.peersTotal)
	infos.peersTotal = w.readDefaultInt(infos.peersTotal)

	// Figure out how many light peers to allow (different based on node type)
	fmt.Println()
	fmt.Printf("How many light peers to allow connecting? (default = %d)\n", infos.peersLight)
	infos.peersLight = w.readDefaultInt(infos.peersLight)

	// Set a proper name to report on the stats page
	fmt.Println()
	if infos.aidstats == "" {
		fmt.Printf("What should the node be called on the stats page?\n")
		infos.aidstats = w.readString() + ":" + w.conf.aidstats
	} else {
		fmt.Printf("What should the node be called on the stats page? (default = %s)\n", infos.aidstats)
		infos.aidstats = w.readDefaultString(infos.aidstats) + ":" + w.conf.aidstats
	}
	// If the node is a verifier/signer, load up needed credentials
	if !boot {
		if w.conf.genesis.Config.Idhash != nil {
			// Idhash based verifiers only need an idbase to verify against
			fmt.Println()
			if infos.idbase == "" {
				fmt.Printf("What address should the verifier user?\n")
				for {
					if address := w.readAddress(); address != nil {
						infos.idbase = address.Hex()
						break
					}
				}
			} else {
				fmt.Printf("What address should the verifier user? (default = %s)\n", infos.idbase)
				infos.idbase = w.readDefaultAddress(common.HexToAddress(infos.idbase)).Hex()
			}
		} else if w.conf.genesis.Config.Clique != nil {
			// If a previous signer was already set, offer to reuse it
			if infos.keyJSON != "" {
				if key, err := keystore.DecryptKey([]byte(infos.keyJSON), infos.keyPass); err != nil {
					infos.keyJSON, infos.keyPass = "", ""
				} else {
					fmt.Println()
					fmt.Printf("Reuse previous (%s) signing account (y/n)? (default = yes)\n", key.Address.Hex())
					if w.readDefaultString("y") != "y" {
						infos.keyJSON, infos.keyPass = "", ""
					}
				}
			}
			// Clique based signers need a keyfile and unlock password, ask if unavailable
			if infos.keyJSON == "" {
				fmt.Println()
				fmt.Println("Please paste the signer's key JSON:")
				infos.keyJSON = w.readJSON()

				fmt.Println()
				fmt.Println("What's the unlock password for the account? (won't be echoed)")
				infos.keyPass = w.readPassword()

				if _, err := keystore.DecryptKey([]byte(infos.keyJSON), infos.keyPass); err != nil {
					log.Error("Failed to decrypt key with given passphrase")
					return
				}
			}
		}
		// Establish the life dynamics to be enforced by the signer
		fmt.Println()
		fmt.Printf("What life limit should empty blocks target (MLife)? (default = %0.3f)\n", infos.lifeTarget)
		infos.lifeTarget = w.readDefaultFloat(infos.lifeTarget)

		fmt.Println()
		fmt.Printf("What life value should the signer require (GWei)? (default = %0.3f)\n", infos.lifePrice)
		infos.lifePrice = w.readDefaultFloat(infos.lifePrice)
	}
	// Try to deploy the full node on the host
	if out, err := deployNode(client, w.network, w.conf.bootFull, w.conf.bootLight, infos); err != nil {
		log.Error("Failed to deploy AriseID node container", "err", err)
		if len(out) > 0 {
			fmt.Printf("%s\n", out)
		}
		return
	}
	// All ok, run a network scan to pick any changes up
	log.Info("Waiting for node to finish booting")
	time.Sleep(3 * time.Second)

	w.networkStats(false)
}
