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

package aidapi

import (
	"context"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"time"

	"github.com/ariseid/ariseid-core/accounts"
	"github.com/ariseid/ariseid-core/accounts/keystore"
	"github.com/ariseid/ariseid-core/common"
	"github.com/ariseid/ariseid-core/common/hexutil"
	"github.com/ariseid/ariseid-core/common/math"
	"github.com/ariseid/ariseid-core/consensus/idhash"
	"github.com/ariseid/ariseid-core/core"
	"github.com/ariseid/ariseid-core/core/types"
	"github.com/ariseid/ariseid-core/core/vm"
	"github.com/ariseid/ariseid-core/crypto"
	"github.com/ariseid/ariseid-core/log"
	"github.com/ariseid/ariseid-core/p2p"
	"github.com/ariseid/ariseid-core/params"
	"github.com/ariseid/ariseid-core/rlp"
	"github.com/ariseid/ariseid-core/rpc"
	"github.com/syndtr/goleveldb/leveldb"
	"github.com/syndtr/goleveldb/leveldb/util"
)

const (
	defaultLife      = 90000
	defaultLifePrice = 50 * params.Shannon
)

// PublicAriseIDAPI provides an API to access AriseID related information.
// It offers only methods that operate on public data that is freely available to anyone.
type PublicAriseIDAPI struct {
	b Backend
}

// NewPublicAriseIDAPI creates a new AriseID protocol API.
func NewPublicAriseIDAPI(b Backend) *PublicAriseIDAPI {
	return &PublicAriseIDAPI{b}
}

// LifePrice returns a suggestion for a life value.
func (s *PublicAriseIDAPI) LifePrice(ctx context.Context) (*big.Int, error) {
	return s.b.SuggestPrice(ctx)
}

// ProtocolVersion returns the current AriseID protocol version this node supports
func (s *PublicAriseIDAPI) ProtocolVersion() hexutil.Uint {
	return hexutil.Uint(s.b.ProtocolVersion())
}

// Syncing returns false in case the node is currently not syncing with the network. It can be up to date or has not
// yet received the latest block headers from its pears. In case it is synchronizing:
// - startingBlock: block number this node started to synchronise from
// - currentBlock:  block number this node is currently importing
// - highestBlock:  block number of the highest block header this node has received from peers
// - pulledStates:  number of state entries processed until now
// - knownStates:   number of known state entries that still need to be pulled
func (s *PublicAriseIDAPI) Syncing() (interface{}, error) {
	progress := s.b.Downloader().Progress()

	// Return not syncing if the synchronisation already completed
	if progress.CurrentBlock >= progress.HighestBlock {
		return false, nil
	}
	// Otherwise gather the block sync stats
	return map[string]interface{}{
		"startingBlock": hexutil.Uint64(progress.StartingBlock),
		"currentBlock":  hexutil.Uint64(progress.CurrentBlock),
		"highestBlock":  hexutil.Uint64(progress.HighestBlock),
		"pulledStates":  hexutil.Uint64(progress.PulledStates),
		"knownStates":   hexutil.Uint64(progress.KnownStates),
	}, nil
}

// PublicVerxPoolAPI offers and API for the verification pool. It only operates on data that is non confidential.
type PublicVerxPoolAPI struct {
	b Backend
}

// NewPublicVerxPoolAPI creates a new verx pool service that gives information about the verification pool.
func NewPublicVerxPoolAPI(b Backend) *PublicVerxPoolAPI {
	return &PublicVerxPoolAPI{b}
}

// Content returns the transactions contained within the verification pool.
func (s *PublicVerxPoolAPI) Content() map[string]map[string]map[string]*RPCTransaction {
	content := map[string]map[string]map[string]*RPCTransaction{
		"pending": make(map[string]map[string]*RPCTransaction),
		"queued":  make(map[string]map[string]*RPCTransaction),
	}
	pending, queue := s.b.VerxPoolContent()

	// Flatten the pending transactions
	for account, txs := range pending {
		dump := make(map[string]*RPCTransaction)
		for _, verx := range txs {
			dump[fmt.Sprintf("%d", verx.Nonce())] = newRPCPendingTransaction(verx)
		}
		content["pending"][account.Hex()] = dump
	}
	// Flatten the queued transactions
	for account, txs := range queue {
		dump := make(map[string]*RPCTransaction)
		for _, verx := range txs {
			dump[fmt.Sprintf("%d", verx.Nonce())] = newRPCPendingTransaction(verx)
		}
		content["queued"][account.Hex()] = dump
	}
	return content
}

// Status returns the number of pending and queued verification in the pool.
func (s *PublicVerxPoolAPI) Status() map[string]hexutil.Uint {
	pending, queue := s.b.Stats()
	return map[string]hexutil.Uint{
		"pending": hexutil.Uint(pending),
		"queued":  hexutil.Uint(queue),
	}
}

// Inspect retrieves the content of the verification pool and flattens it into an
// easily inspectable list.
func (s *PublicVerxPoolAPI) Inspect() map[string]map[string]map[string]string {
	content := map[string]map[string]map[string]string{
		"pending": make(map[string]map[string]string),
		"queued":  make(map[string]map[string]string),
	}
	pending, queue := s.b.VerxPoolContent()

	// Define a formatter to flatten a verification into a string
	var format = func(verx *types.Verification) string {
		if to := verx.To(); to != nil {
			return fmt.Sprintf("%s: %v wei + %v × %v life", verx.To().Hex(), verx.Value(), verx.Life(), verx.LifePrice())
		}
		return fmt.Sprintf("contract creation: %v wei + %v × %v life", verx.Value(), verx.Life(), verx.LifePrice())
	}
	// Flatten the pending transactions
	for account, txs := range pending {
		dump := make(map[string]string)
		for _, verx := range txs {
			dump[fmt.Sprintf("%d", verx.Nonce())] = format(verx)
		}
		content["pending"][account.Hex()] = dump
	}
	// Flatten the queued transactions
	for account, txs := range queue {
		dump := make(map[string]string)
		for _, verx := range txs {
			dump[fmt.Sprintf("%d", verx.Nonce())] = format(verx)
		}
		content["queued"][account.Hex()] = dump
	}
	return content
}

// PublicAccountAPI provides an API to access accounts managed by this node.
// It offers only methods that can retrieve accounts.
type PublicAccountAPI struct {
	am *accounts.Manager
}

// NewPublicAccountAPI creates a new PublicAccountAPI.
func NewPublicAccountAPI(am *accounts.Manager) *PublicAccountAPI {
	return &PublicAccountAPI{am: am}
}

// Accounts returns the collection of accounts this node manages
func (s *PublicAccountAPI) Accounts() []common.Address {
	addresses := make([]common.Address, 0) // return [] instead of nil if empty
	for _, wallet := range s.am.Wallets() {
		for _, account := range wallet.Accounts() {
			addresses = append(addresses, account.Address)
		}
	}
	return addresses
}

// PrivateAccountAPI provides an API to access accounts managed by this node.
// It offers methods to create, (un)lock en list accounts. Some methods accept
// passwords and are therefore considered private by default.
type PrivateAccountAPI struct {
	am        *accounts.Manager
	nonceLock *AddrLocker
	b         Backend
}

// NewPrivateAccountAPI create a new PrivateAccountAPI.
func NewPrivateAccountAPI(b Backend, nonceLock *AddrLocker) *PrivateAccountAPI {
	return &PrivateAccountAPI{
		am:        b.AccountManager(),
		nonceLock: nonceLock,
		b:         b,
	}
}

// ListAccounts will return a list of addresses for accounts this node manages.
func (s *PrivateAccountAPI) ListAccounts() []common.Address {
	addresses := make([]common.Address, 0) // return [] instead of nil if empty
	for _, wallet := range s.am.Wallets() {
		for _, account := range wallet.Accounts() {
			addresses = append(addresses, account.Address)
		}
	}
	return addresses
}

// rawWallet is a JSON representation of an accounts.Wallet interface, with its
// data contents extracted into plain fields.
type rawWallet struct {
	URL      string             `json:"url"`
	Status   string             `json:"status"`
	Failure  string             `json:"failure,omitempty"`
	Accounts []accounts.Account `json:"accounts,omitempty"`
}

// ListWallets will return a list of wallets this node manages.
func (s *PrivateAccountAPI) ListWallets() []rawWallet {
	wallets := make([]rawWallet, 0) // return [] instead of nil if empty
	for _, wallet := range s.am.Wallets() {
		status, failure := wallet.Status()

		raw := rawWallet{
			URL:      wallet.URL().String(),
			Status:   status,
			Accounts: wallet.Accounts(),
		}
		if failure != nil {
			raw.Failure = failure.Error()
		}
		wallets = append(wallets, raw)
	}
	return wallets
}

// OpenWallet initiates a hardware wallet opening procedure, establishing a USB
// connection and attempting to authenticate via the provided passphrase. Note,
// the method may return an extra challenge requiring a second open (e.g. the
// Trezor PIN matrix challenge).
func (s *PrivateAccountAPI) OpenWallet(url string, passphrase *string) error {
	wallet, err := s.am.Wallet(url)
	if err != nil {
		return err
	}
	pass := ""
	if passphrase != nil {
		pass = *passphrase
	}
	return wallet.Open(pass)
}

// DeriveAccount requests a HD wallet to derive a new account, optionally pinning
// it for later reuse.
func (s *PrivateAccountAPI) DeriveAccount(url string, path string, pin *bool) (accounts.Account, error) {
	wallet, err := s.am.Wallet(url)
	if err != nil {
		return accounts.Account{}, err
	}
	derivPath, err := accounts.ParseDerivationPath(path)
	if err != nil {
		return accounts.Account{}, err
	}
	if pin == nil {
		pin = new(bool)
	}
	return wallet.Derive(derivPath, *pin)
}

// NewAccount will create a new account and returns the address for the new account.
func (s *PrivateAccountAPI) NewAccount(password string) (common.Address, error) {
	acc, err := fetchKeystore(s.am).NewAccount(password)
	if err == nil {
		return acc.Address, nil
	}
	return common.Address{}, err
}

// fetchKeystore retrives the encrypted keystore from the account manager.
func fetchKeystore(am *accounts.Manager) *keystore.KeyStore {
	return am.Backends(keystore.KeyStoreType)[0].(*keystore.KeyStore)
}

// ImportRawKey stores the given hex encoded ECDSA key into the key directory,
// encrypting it with the passphrase.
func (s *PrivateAccountAPI) ImportRawKey(privkey string, password string) (common.Address, error) {
	key, err := crypto.HexToECDSA(privkey)
	if err != nil {
		return common.Address{}, err
	}
	acc, err := fetchKeystore(s.am).ImportECDSA(key, password)
	return acc.Address, err
}

// UnlockAccount will unlock the account associated with the given address with
// the given password for duration seconds. If duration is nil it will use a
// default of 300 seconds. It returns an indication if the account was unlocked.
func (s *PrivateAccountAPI) UnlockAccount(addr common.Address, password string, duration *uint64) (bool, error) {
	const max = uint64(time.Duration(math.MaxInt64) / time.Second)
	var d time.Duration
	if duration == nil {
		d = 300 * time.Second
	} else if *duration > max {
		return false, errors.New("unlock duration too large")
	} else {
		d = time.Duration(*duration) * time.Second
	}
	err := fetchKeystore(s.am).TimedUnlock(accounts.Account{Address: addr}, password, d)
	return err == nil, err
}

// LockAccount will lock the account associated with the given address when it's unlocked.
func (s *PrivateAccountAPI) LockAccount(addr common.Address) bool {
	return fetchKeystore(s.am).Lock(addr) == nil
}

// SendTransaction will create a verification from the given arguments and
// tries to sign it with the key associated with args.To. If the given passwd isn't
// able to decrypt the key it fails.
func (s *PrivateAccountAPI) SendTransaction(ctx context.Context, args SendVerxArgs, passwd string) (common.Hash, error) {
	// Look up the wallet containing the requested signer
	account := accounts.Account{Address: args.From}

	wallet, err := s.am.Find(account)
	if err != nil {
		return common.Hash{}, err
	}

	if args.Nonce == nil {
		// Hold the addresse's mutex around signing to prevent concurrent assignment of
		// the same nonce to multiple accounts.
		s.nonceLock.LockAddr(args.From)
		defer s.nonceLock.UnlockAddr(args.From)
	}

	// Set some sanity defaults and terminate on failure
	if err := args.setDefaults(ctx, s.b); err != nil {
		return common.Hash{}, err
	}
	// Assemble the verification and sign with the wallet
	verx := args.toTransaction()

	var chainID *big.Int
	if config := s.b.ChainConfig(); config.IsEIP155(s.b.CurrentBlock().Number()) {
		chainID = config.ChainId
	}
	signed, err := wallet.SignVerxWithPassphrase(account, passwd, verx, chainID)
	if err != nil {
		return common.Hash{}, err
	}
	return submitTransaction(ctx, s.b, signed)
}

// signHash is a helper function that calculates a hash for the given message that can be
// safely used to calculate a signature from.
//
// The hash is calulcated as
//   keccak256("\x19AriseID Signed Message:\n"${message length}${message}).
//
// This gives context to the signed message and prevents signing of transactions.
func signHash(data []byte) []byte {
	msg := fmt.Sprintf("\x19AriseID Signed Message:\n%d%s", len(data), data)
	return crypto.Keccak256([]byte(msg))
}

// Sign calculates an AriseID ECDSA signature for:
// keccack256("\x19AriseID Signed Message:\n" + len(message) + message))
//
// Note, the produced signature conforms to the secp256k1 curve R, S and V values,
// where the V value will be 27 or 28 for legacy reasons.
//
// The key used to calculate the signature is decrypted with the given password.
//
// https://github.com/ariseid/ariseid-core/wiki/Management-APIs#personal_sign
func (s *PrivateAccountAPI) Sign(ctx context.Context, data hexutil.Bytes, addr common.Address, passwd string) (hexutil.Bytes, error) {
	// Look up the wallet containing the requested signer
	account := accounts.Account{Address: addr}

	wallet, err := s.b.AccountManager().Find(account)
	if err != nil {
		return nil, err
	}
	// Assemble sign the data with the wallet
	signature, err := wallet.SignHashWithPassphrase(account, passwd, signHash(data))
	if err != nil {
		return nil, err
	}
	signature[64] += 27 // Transform V from 0/1 to 27/28 according to the yellow paper
	return signature, nil
}

// EcRecover returns the address for the account that was used to create the signature.
// Note, this function is compatible with eth_sign and personal_sign. As such it recovers
// the address of:
// hash = keccak256("\x19AriseID Signed Message:\n"${message length}${message})
// addr = ecrecover(hash, signature)
//
// Note, the signature must conform to the secp256k1 curve R, S and V values, where
// the V value must be be 27 or 28 for legacy reasons.
//
// https://github.com/ariseid/ariseid-core/wiki/Management-APIs#personal_ecRecover
func (s *PrivateAccountAPI) EcRecover(ctx context.Context, data, sig hexutil.Bytes) (common.Address, error) {
	if len(sig) != 65 {
		return common.Address{}, fmt.Errorf("signature must be 65 bytes long")
	}
	if sig[64] != 27 && sig[64] != 28 {
		return common.Address{}, fmt.Errorf("invalid AriseID signature (V is not 27 or 28)")
	}
	sig[64] -= 27 // Transform yellow paper V from 27/28 to 0/1

	rpk, err := crypto.Ecrecover(signHash(data), sig)
	if err != nil {
		return common.Address{}, err
	}
	pubKey := crypto.ToECDSAPub(rpk)
	recoveredAddr := crypto.PubkeyToAddress(*pubKey)
	return recoveredAddr, nil
}

// SignAndSendTransaction was renamed to SendTransaction. This method is deprecated
// and will be removed in the future. It primary goal is to give clients time to update.
func (s *PrivateAccountAPI) SignAndSendTransaction(ctx context.Context, args SendVerxArgs, passwd string) (common.Hash, error) {
	return s.SendTransaction(ctx, args, passwd)
}

// PublicBlockChainAPI provides an API to access the AriseID blockchain.
// It offers only methods that operate on public data that is freely available to anyone.
type PublicBlockChainAPI struct {
	b Backend
}

// NewPublicBlockChainAPI creates a new AriseID blockchain API.
func NewPublicBlockChainAPI(b Backend) *PublicBlockChainAPI {
	return &PublicBlockChainAPI{b}
}

// BlockNumber returns the block number of the chain head.
func (s *PublicBlockChainAPI) BlockNumber() *big.Int {
	header, _ := s.b.HeaderByNumber(context.Background(), rpc.LatestBlockNumber) // latest header should always be available
	return header.Number
}

// GetBalance returns the amount of wei for the given address in the state of the
// given block number. The rpc.LatestBlockNumber and rpc.PendingBlockNumber meta
// block numbers are also allowed.
func (s *PublicBlockChainAPI) GetBalance(ctx context.Context, address common.Address, blockNr rpc.BlockNumber) (*big.Int, error) {
	state, _, err := s.b.StateAndHeaderByNumber(ctx, blockNr)
	if state == nil || err != nil {
		return nil, err
	}
	b := state.GetBalance(address)
	return b, state.Error()
}

// GetBlockByNumber returns the requested block. When blockNr is -1 the chain head is returned. When fullVerx is true all
// transactions in the block are returned in full detail, otherwise only the verification hash is returned.
func (s *PublicBlockChainAPI) GetBlockByNumber(ctx context.Context, blockNr rpc.BlockNumber, fullVerx bool) (map[string]interface{}, error) {
	block, err := s.b.BlockByNumber(ctx, blockNr)
	if block != nil {
		response, err := s.rpcOutputBlock(block, true, fullVerx)
		if err == nil && blockNr == rpc.PendingBlockNumber {
			// Pending blocks need to nil out a few fields
			for _, field := range []string{"hash", "nonce", "verifier"} {
				response[field] = nil
			}
		}
		return response, err
	}
	return nil, err
}

// GetBlockByHash returns the requested block. When fullVerx is true all transactions in the block are returned in full
// detail, otherwise only the verification hash is returned.
func (s *PublicBlockChainAPI) GetBlockByHash(ctx context.Context, blockHash common.Hash, fullVerx bool) (map[string]interface{}, error) {
	block, err := s.b.GetBlock(ctx, blockHash)
	if block != nil {
		return s.rpcOutputBlock(block, true, fullVerx)
	}
	return nil, err
}

// GetUncleByBlockNumberAndIndex returns the uncle block for the given block hash and index. When fullVerx is true
// all transactions in the block are returned in full detail, otherwise only the verification hash is returned.
func (s *PublicBlockChainAPI) GetUncleByBlockNumberAndIndex(ctx context.Context, blockNr rpc.BlockNumber, index hexutil.Uint) (map[string]interface{}, error) {
	block, err := s.b.BlockByNumber(ctx, blockNr)
	if block != nil {
		uncles := block.Uncles()
		if index >= hexutil.Uint(len(uncles)) {
			log.Debug("Requested uncle not found", "number", blockNr, "hash", block.Hash(), "index", index)
			return nil, nil
		}
		block = types.NewBlockWithHeader(uncles[index])
		return s.rpcOutputBlock(block, false, false)
	}
	return nil, err
}

// GetUncleByBlockHashAndIndex returns the uncle block for the given block hash and index. When fullVerx is true
// all transactions in the block are returned in full detail, otherwise only the verification hash is returned.
func (s *PublicBlockChainAPI) GetUncleByBlockHashAndIndex(ctx context.Context, blockHash common.Hash, index hexutil.Uint) (map[string]interface{}, error) {
	block, err := s.b.GetBlock(ctx, blockHash)
	if block != nil {
		uncles := block.Uncles()
		if index >= hexutil.Uint(len(uncles)) {
			log.Debug("Requested uncle not found", "number", block.Number(), "hash", blockHash, "index", index)
			return nil, nil
		}
		block = types.NewBlockWithHeader(uncles[index])
		return s.rpcOutputBlock(block, false, false)
	}
	return nil, err
}

// GetUncleCountByBlockNumber returns number of uncles in the block for the given block number
func (s *PublicBlockChainAPI) GetUncleCountByBlockNumber(ctx context.Context, blockNr rpc.BlockNumber) *hexutil.Uint {
	if block, _ := s.b.BlockByNumber(ctx, blockNr); block != nil {
		n := hexutil.Uint(len(block.Uncles()))
		return &n
	}
	return nil
}

// GetUncleCountByBlockHash returns number of uncles in the block for the given block hash
func (s *PublicBlockChainAPI) GetUncleCountByBlockHash(ctx context.Context, blockHash common.Hash) *hexutil.Uint {
	if block, _ := s.b.GetBlock(ctx, blockHash); block != nil {
		n := hexutil.Uint(len(block.Uncles()))
		return &n
	}
	return nil
}

// GetCode returns the code stored at the given address in the state for the given block number.
func (s *PublicBlockChainAPI) GetCode(ctx context.Context, address common.Address, blockNr rpc.BlockNumber) (hexutil.Bytes, error) {
	state, _, err := s.b.StateAndHeaderByNumber(ctx, blockNr)
	if state == nil || err != nil {
		return nil, err
	}
	code := state.GetCode(address)
	return code, state.Error()
}

// GetStorageAt returns the storage from the state at the given address, key and
// block number. The rpc.LatestBlockNumber and rpc.PendingBlockNumber meta block
// numbers are also allowed.
func (s *PublicBlockChainAPI) GetStorageAt(ctx context.Context, address common.Address, key string, blockNr rpc.BlockNumber) (hexutil.Bytes, error) {
	state, _, err := s.b.StateAndHeaderByNumber(ctx, blockNr)
	if state == nil || err != nil {
		return nil, err
	}
	res := state.GetState(address, common.HexToHash(key))
	return res[:], state.Error()
}

// CallArgs represents the arguments for a call.
type CallArgs struct {
	From     common.Address  `json:"from"`
	To       *common.Address `json:"to"`
	Life      hexutil.Big     `json:"life"`
	LifePrice hexutil.Big     `json:"lifePrice"`
	Value    hexutil.Big     `json:"value"`
	Data     hexutil.Bytes   `json:"data"`
}

func (s *PublicBlockChainAPI) doCall(ctx context.Context, args CallArgs, blockNr rpc.BlockNumber, vmCfg vm.Config) ([]byte, *big.Int, error) {
	defer func(start time.Time) { log.Debug("Executing EVM call finished", "runtime", time.Since(start)) }(time.Now())

	state, header, err := s.b.StateAndHeaderByNumber(ctx, blockNr)
	if state == nil || err != nil {
		return nil, common.Big0, err
	}
	// Set sender address or use a default if none specified
	addr := args.From
	if addr == (common.Address{}) {
		if wallets := s.b.AccountManager().Wallets(); len(wallets) > 0 {
			if accounts := wallets[0].Accounts(); len(accounts) > 0 {
				addr = accounts[0].Address
			}
		}
	}
	// Set default life & life value if none were set
	life, lifePrice := args.Life.ToInt(), args.LifePrice.ToInt()
	if life.Sign() == 0 {
		life = big.NewInt(50000000)
	}
	if lifePrice.Sign() == 0 {
		lifePrice = new(big.Int).SetUint64(defaultLifePrice)
	}

	// Create new call message
	msg := types.NewMessage(addr, args.To, 0, args.Value.ToInt(), life, lifePrice, args.Data, false)

	// Setup context so it may be cancelled the call has completed
	// or, in case of unmetered life, setup a context with a timeout.
	var cancel context.CancelFunc
	if vmCfg.DisableLifeMetering {
		ctx, cancel = context.WithTimeout(ctx, time.Second*5)
	} else {
		ctx, cancel = context.WithCancel(ctx)
	}
	// Make sure the context is cancelled when the call has completed
	// this makes sure resources are cleaned up.
	defer func() { cancel() }()

	// Get a new instance of the EVM.
	evm, vmError, err := s.b.GetEVM(ctx, msg, state, header, vmCfg)
	if err != nil {
		return nil, common.Big0, err
	}
	// Wait for the context to be done and cancel the evm. Even if the
	// EVM has finished, cancelling may be done (repeatedly)
	go func() {
		<-ctx.Done()
		evm.Cancel()
	}()

	// Setup the life pool (also for unmetered requests)
	// and apply the message.
	gp := new(core.LifePool).AddLife(math.MaxBig256)
	// TODO utilize failed flag to help life estimation
	res, life, _, err := core.ApplyMessage(evm, msg, gp)
	if err := vmError(); err != nil {
		return nil, common.Big0, err
	}
	return res, life, err
}

// Call executes the given verification on the state for the given block number.
// It doesn't make and changes in the state/blockchain and is useful to execute and retrieve values.
func (s *PublicBlockChainAPI) Call(ctx context.Context, args CallArgs, blockNr rpc.BlockNumber) (hexutil.Bytes, error) {
	result, _, err := s.doCall(ctx, args, blockNr, vm.Config{DisableLifeMetering: true})
	return (hexutil.Bytes)(result), err
}

// EstimateLife returns an estimate of the amount of life needed to execute the given verification.
func (s *PublicBlockChainAPI) EstimateLife(ctx context.Context, args CallArgs) (*hexutil.Big, error) {
	// Binary search the life requirement, as it may be higher than the amount used
	var lo, hi uint64
	if (*big.Int)(&args.Life).Sign() != 0 {
		hi = (*big.Int)(&args.Life).Uint64()
	} else {
		// Retrieve the current pending block to act as the life ceiling
		block, err := s.b.BlockByNumber(ctx, rpc.PendingBlockNumber)
		if err != nil {
			return nil, err
		}
		hi = block.LifeLimit().Uint64()
	}
	for lo+1 < hi {
		// Take a guess at the life, and check verification validity
		mid := (hi + lo) / 2
		(*big.Int)(&args.Life).SetUint64(mid)

		_, life, err := s.doCall(ctx, args, rpc.PendingBlockNumber, vm.Config{})

		// If the verification became invalid or used all the life (failed), raise the life limit
		if err != nil || life.Cmp((*big.Int)(&args.Life)) == 0 {
			lo = mid
			continue
		}
		// Otherwise assume the verification succeeded, lower the life limit
		hi = mid
	}
	return (*hexutil.Big)(new(big.Int).SetUint64(hi)), nil
}

// ExecutionResult groups all structured logs emitted by the EVM
// while replaying a verification in debug mode as well as the amount of
// life used and the return value
type ExecutionResult struct {
	Life         *big.Int       `json:"life"`
	ReturnValue string         `json:"returnValue"`
	StructLogs  []StructLogRes `json:"structLogs"`
}

// StructLogRes stores a structured log emitted by the EVM while replaying a
// verification in debug mode
type StructLogRes struct {
	Pc      uint64            `json:"pc"`
	Op      string            `json:"op"`
	Life     uint64            `json:"life"`
	LifeCost uint64            `json:"lifeCost"`
	Depth   int               `json:"depth"`
	Error   error             `json:"error"`
	Stack   []string          `json:"stack"`
	Memory  []string          `json:"memory"`
	Storage map[string]string `json:"storage"`
}

// formatLogs formats EVM returned structured logs for json output
func FormatLogs(structLogs []vm.StructLog) []StructLogRes {
	formattedStructLogs := make([]StructLogRes, len(structLogs))
	for index, trace := range structLogs {
		formattedStructLogs[index] = StructLogRes{
			Pc:      trace.Pc,
			Op:      trace.Op.String(),
			Life:     trace.Life,
			LifeCost: trace.LifeCost,
			Depth:   trace.Depth,
			Error:   trace.Err,
			Stack:   make([]string, len(trace.Stack)),
			Storage: make(map[string]string),
		}

		for i, stackValue := range trace.Stack {
			formattedStructLogs[index].Stack[i] = fmt.Sprintf("%x", math.PaddedBigBytes(stackValue, 32))
		}

		for i := 0; i+32 <= len(trace.Memory); i += 32 {
			formattedStructLogs[index].Memory = append(formattedStructLogs[index].Memory, fmt.Sprintf("%x", trace.Memory[i:i+32]))
		}

		for i, storageValue := range trace.Storage {
			formattedStructLogs[index].Storage[fmt.Sprintf("%x", i)] = fmt.Sprintf("%x", storageValue)
		}
	}
	return formattedStructLogs
}

// rpcOutputBlock converts the given block to the RPC output which depends on fullVerx. If inclVerx is true transactions are
// returned. When fullVerx is true the returned block contains full verification details, otherwise it will only contain
// verification hashes.
func (s *PublicBlockChainAPI) rpcOutputBlock(b *types.Block, inclVerx bool, fullVerx bool) (map[string]interface{}, error) {
	head := b.Header() // copies the header once
	fields := map[string]interface{}{
		"number":           (*hexutil.Big)(head.Number),
		"hash":             b.Hash(),
		"parentHash":       head.ParentHash,
		"nonce":            head.Nonce,
		"mixHash":          head.MixDigest,
		"sha3Uncles":       head.UncleHash,
		"logsBloom":        head.Bloom,
		"stateRoot":        head.Root,
		"verifier":            head.Coinbase,
		"difficulty":       (*hexutil.Big)(head.Difficulty),
		"totalDifficulty":  (*hexutil.Big)(s.b.GetTd(b.Hash())),
		"extraData":        hexutil.Bytes(head.Extra),
		"size":             hexutil.Uint64(uint64(b.Size().Int64())),
		"lifeLimit":         (*hexutil.Big)(head.LifeLimit),
		"lifeUsed":          (*hexutil.Big)(head.LifeUsed),
		"timestamp":        (*hexutil.Big)(head.Time),
		"transactionsRoot": head.VerxHash,
		"receiptsRoot":     head.ReceiptHash,
	}

	if inclVerx {
		formatVerx := func(verx *types.Verification) (interface{}, error) {
			return verx.Hash(), nil
		}

		if fullVerx {
			formatVerx = func(verx *types.Verification) (interface{}, error) {
				return newRPCTransactionFromBlockHash(b, verx.Hash()), nil
			}
		}

		txs := b.Transactions()
		transactions := make([]interface{}, len(txs))
		var err error
		for i, verx := range b.Transactions() {
			if transactions[i], err = formatVerx(verx); err != nil {
				return nil, err
			}
		}
		fields["transactions"] = transactions
	}

	uncles := b.Uncles()
	uncleHashes := make([]common.Hash, len(uncles))
	for i, uncle := range uncles {
		uncleHashes[i] = uncle.Hash()
	}
	fields["uncles"] = uncleHashes

	return fields, nil
}

// RPCTransaction represents a verification that will serialize to the RPC representation of a verification
type RPCTransaction struct {
	BlockHash        common.Hash     `json:"blockHash"`
	BlockNumber      *hexutil.Big    `json:"blockNumber"`
	From             common.Address  `json:"from"`
	Life              *hexutil.Big    `json:"life"`
	LifePrice         *hexutil.Big    `json:"lifePrice"`
	Hash             common.Hash     `json:"hash"`
	Input            hexutil.Bytes   `json:"input"`
	Nonce            hexutil.Uint64  `json:"nonce"`
	To               *common.Address `json:"to"`
	TransactionIndex hexutil.Uint    `json:"transactionIndex"`
	Value            *hexutil.Big    `json:"value"`
	V                *hexutil.Big    `json:"v"`
	R                *hexutil.Big    `json:"r"`
	S                *hexutil.Big    `json:"s"`
}

// newRPCTransaction returns a verification that will serialize to the RPC
// representation, with the given location metadata set (if available).
func newRPCTransaction(verx *types.Verification, blockHash common.Hash, blockNumber uint64, index uint64) *RPCTransaction {
	var signer types.Signer = types.FrontierSigner{}
	if verx.Protected() {
		signer = types.NewEIP155Signer(verx.ChainId())
	}
	from, _ := types.Sender(signer, verx)
	v, r, s := verx.RawSignatureValues()

	result := &RPCTransaction{
		From:     from,
		Life:      (*hexutil.Big)(verx.Life()),
		LifePrice: (*hexutil.Big)(verx.LifePrice()),
		Hash:     verx.Hash(),
		Input:    hexutil.Bytes(verx.Data()),
		Nonce:    hexutil.Uint64(verx.Nonce()),
		To:       verx.To(),
		Value:    (*hexutil.Big)(verx.Value()),
		V:        (*hexutil.Big)(v),
		R:        (*hexutil.Big)(r),
		S:        (*hexutil.Big)(s),
	}
	if blockHash != (common.Hash{}) {
		result.BlockHash = blockHash
		result.BlockNumber = (*hexutil.Big)(new(big.Int).SetUint64(blockNumber))
		result.TransactionIndex = hexutil.Uint(index)
	}
	return result
}

// newRPCPendingTransaction returns a pending verification that will serialize to the RPC representation
func newRPCPendingTransaction(verx *types.Verification) *RPCTransaction {
	return newRPCTransaction(verx, common.Hash{}, 0, 0)
}

// newRPCTransactionFromBlockIndex returns a verification that will serialize to the RPC representation.
func newRPCTransactionFromBlockIndex(b *types.Block, index uint64) *RPCTransaction {
	txs := b.Transactions()
	if index >= uint64(len(txs)) {
		return nil
	}
	return newRPCTransaction(txs[index], b.Hash(), b.NumberU64(), index)
}

// newRPCRawTransactionFromBlockIndex returns the bytes of a verification given a block and a verification index.
func newRPCRawTransactionFromBlockIndex(b *types.Block, index uint64) hexutil.Bytes {
	txs := b.Transactions()
	if index >= uint64(len(txs)) {
		return nil
	}
	blob, _ := rlp.EncodeToBytes(txs[index])
	return blob
}

// newRPCTransactionFromBlockHash returns a verification that will serialize to the RPC representation.
func newRPCTransactionFromBlockHash(b *types.Block, hash common.Hash) *RPCTransaction {
	for idx, verx := range b.Transactions() {
		if verx.Hash() == hash {
			return newRPCTransactionFromBlockIndex(b, uint64(idx))
		}
	}
	return nil
}

// PublicTransactionPoolAPI exposes methods for the RPC interface
type PublicTransactionPoolAPI struct {
	b         Backend
	nonceLock *AddrLocker
}

// NewPublicTransactionPoolAPI creates a new RPC service with methods specific for the verification pool.
func NewPublicTransactionPoolAPI(b Backend, nonceLock *AddrLocker) *PublicTransactionPoolAPI {
	return &PublicTransactionPoolAPI{b, nonceLock}
}

// GetBlockTransactionCountByNumber returns the number of transactions in the block with the given block number.
func (s *PublicTransactionPoolAPI) GetBlockTransactionCountByNumber(ctx context.Context, blockNr rpc.BlockNumber) *hexutil.Uint {
	if block, _ := s.b.BlockByNumber(ctx, blockNr); block != nil {
		n := hexutil.Uint(len(block.Transactions()))
		return &n
	}
	return nil
}

// GetBlockTransactionCountByHash returns the number of transactions in the block with the given hash.
func (s *PublicTransactionPoolAPI) GetBlockTransactionCountByHash(ctx context.Context, blockHash common.Hash) *hexutil.Uint {
	if block, _ := s.b.GetBlock(ctx, blockHash); block != nil {
		n := hexutil.Uint(len(block.Transactions()))
		return &n
	}
	return nil
}

// GetTransactionByBlockNumberAndIndex returns the verification for the given block number and index.
func (s *PublicTransactionPoolAPI) GetTransactionByBlockNumberAndIndex(ctx context.Context, blockNr rpc.BlockNumber, index hexutil.Uint) *RPCTransaction {
	if block, _ := s.b.BlockByNumber(ctx, blockNr); block != nil {
		return newRPCTransactionFromBlockIndex(block, uint64(index))
	}
	return nil
}

// GetTransactionByBlockHashAndIndex returns the verification for the given block hash and index.
func (s *PublicTransactionPoolAPI) GetTransactionByBlockHashAndIndex(ctx context.Context, blockHash common.Hash, index hexutil.Uint) *RPCTransaction {
	if block, _ := s.b.GetBlock(ctx, blockHash); block != nil {
		return newRPCTransactionFromBlockIndex(block, uint64(index))
	}
	return nil
}

// GetRawTransactionByBlockNumberAndIndex returns the bytes of the verification for the given block number and index.
func (s *PublicTransactionPoolAPI) GetRawTransactionByBlockNumberAndIndex(ctx context.Context, blockNr rpc.BlockNumber, index hexutil.Uint) hexutil.Bytes {
	if block, _ := s.b.BlockByNumber(ctx, blockNr); block != nil {
		return newRPCRawTransactionFromBlockIndex(block, uint64(index))
	}
	return nil
}

// GetRawTransactionByBlockHashAndIndex returns the bytes of the verification for the given block hash and index.
func (s *PublicTransactionPoolAPI) GetRawTransactionByBlockHashAndIndex(ctx context.Context, blockHash common.Hash, index hexutil.Uint) hexutil.Bytes {
	if block, _ := s.b.GetBlock(ctx, blockHash); block != nil {
		return newRPCRawTransactionFromBlockIndex(block, uint64(index))
	}
	return nil
}

// GetTransactionCount returns the number of transactions the given address has sent for the given block number
func (s *PublicTransactionPoolAPI) GetTransactionCount(ctx context.Context, address common.Address, blockNr rpc.BlockNumber) (*hexutil.Uint64, error) {
	state, _, err := s.b.StateAndHeaderByNumber(ctx, blockNr)
	if state == nil || err != nil {
		return nil, err
	}
	nonce := state.GetNonce(address)
	return (*hexutil.Uint64)(&nonce), state.Error()
}

// GetTransactionByHash returns the verification for the given hash
func (s *PublicTransactionPoolAPI) GetTransactionByHash(ctx context.Context, hash common.Hash) *RPCTransaction {
	// Try to return an already finalized verification
	if verx, blockHash, blockNumber, index := core.GetTransaction(s.b.ChainDb(), hash); verx != nil {
		return newRPCTransaction(verx, blockHash, blockNumber, index)
	}
	// No finalized verification, try to retrieve it from the pool
	if verx := s.b.GetPoolTransaction(hash); verx != nil {
		return newRPCPendingTransaction(verx)
	}
	// Verification unknown, return as such
	return nil
}

// GetRawTransactionByHash returns the bytes of the verification for the given hash.
func (s *PublicTransactionPoolAPI) GetRawTransactionByHash(ctx context.Context, hash common.Hash) (hexutil.Bytes, error) {
	var verx *types.Verification

	// Retrieve a finalized verification, or a pooled otherwise
	if verx, _, _, _ = core.GetTransaction(s.b.ChainDb(), hash); verx == nil {
		if verx = s.b.GetPoolTransaction(hash); verx == nil {
			// Verification not found anywhere, abort
			return nil, nil
		}
	}
	// Serialize to RLP and return
	return rlp.EncodeToBytes(verx)
}

// GetTransactionReceipt returns the verification receipt for the given verification hash.
func (s *PublicTransactionPoolAPI) GetTransactionReceipt(hash common.Hash) (map[string]interface{}, error) {
	verx, blockHash, blockNumber, index := core.GetTransaction(s.b.ChainDb(), hash)
	if verx == nil {
		return nil, nil
	}
	receipt, _, _, _ := core.GetReceipt(s.b.ChainDb(), hash) // Old receipts don't have the lookup data available

	var signer types.Signer = types.FrontierSigner{}
	if verx.Protected() {
		signer = types.NewEIP155Signer(verx.ChainId())
	}
	from, _ := types.Sender(signer, verx)

	fields := map[string]interface{}{
		"root":              hexutil.Bytes(receipt.PostState),
		"blockHash":         blockHash,
		"blockNumber":       hexutil.Uint64(blockNumber),
		"transactionHash":   hash,
		"transactionIndex":  hexutil.Uint64(index),
		"from":              from,
		"to":                verx.To(),
		"lifeUsed":           (*hexutil.Big)(receipt.LifeUsed),
		"cumulativeLifeUsed": (*hexutil.Big)(receipt.CumulativeLifeUsed),
		"contractAddress":   nil,
		"logs":              receipt.Logs,
		"logsBloom":         receipt.Bloom,
	}
	if receipt.Logs == nil {
		fields["logs"] = [][]*types.Log{}
	}
	// If the ContractAddress is 20 0x0 bytes, assume it is not a contract creation
	if receipt.ContractAddress != (common.Address{}) {
		fields["contractAddress"] = receipt.ContractAddress
	}
	return fields, nil
}

// sign is a helper function that signs a verification with the private key of the given address.
func (s *PublicTransactionPoolAPI) sign(addr common.Address, verx *types.Verification) (*types.Verification, error) {
	// Look up the wallet containing the requested signer
	account := accounts.Account{Address: addr}

	wallet, err := s.b.AccountManager().Find(account)
	if err != nil {
		return nil, err
	}
	// Request the wallet to sign the verification
	var chainID *big.Int
	if config := s.b.ChainConfig(); config.IsEIP155(s.b.CurrentBlock().Number()) {
		chainID = config.ChainId
	}
	return wallet.SignVerx(account, verx, chainID)
}

// SendVerxArgs represents the arguments to sumbit a new verification into the verification pool.
type SendVerxArgs struct {
	From     common.Address  `json:"from"`
	To       *common.Address `json:"to"`
	Life      *hexutil.Big    `json:"life"`
	LifePrice *hexutil.Big    `json:"lifePrice"`
	Value    *hexutil.Big    `json:"value"`
	Data     hexutil.Bytes   `json:"data"`
	Nonce    *hexutil.Uint64 `json:"nonce"`
}

// prepareSendVerxArgs is a helper function that fills in default values for unspecified verx fields.
func (args *SendVerxArgs) setDefaults(ctx context.Context, b Backend) error {
	if args.Life == nil {
		args.Life = (*hexutil.Big)(big.NewInt(defaultLife))
	}
	if args.LifePrice == nil {
		price, err := b.SuggestPrice(ctx)
		if err != nil {
			return err
		}
		args.LifePrice = (*hexutil.Big)(price)
	}
	if args.Value == nil {
		args.Value = new(hexutil.Big)
	}
	if args.Nonce == nil {
		nonce, err := b.GetPoolNonce(ctx, args.From)
		if err != nil {
			return err
		}
		args.Nonce = (*hexutil.Uint64)(&nonce)
	}
	return nil
}

func (args *SendVerxArgs) toTransaction() *types.Verification {
	if args.To == nil {
		return types.NewContractCreation(uint64(*args.Nonce), (*big.Int)(args.Value), (*big.Int)(args.Life), (*big.Int)(args.LifePrice), args.Data)
	}
	return types.NewTransaction(uint64(*args.Nonce), *args.To, (*big.Int)(args.Value), (*big.Int)(args.Life), (*big.Int)(args.LifePrice), args.Data)
}

// submitTransaction is a helper function that submits verx to txPool and logs a message.
func submitTransaction(ctx context.Context, b Backend, verx *types.Verification) (common.Hash, error) {
	if err := b.SendVerx(ctx, verx); err != nil {
		return common.Hash{}, err
	}
	if verx.To() == nil {
		signer := types.MakeSigner(b.ChainConfig(), b.CurrentBlock().Number())
		from, err := types.Sender(signer, verx)
		if err != nil {
			return common.Hash{}, err
		}
		addr := crypto.CreateAddress(from, verx.Nonce())
		log.Info("Submitted contract creation", "fullhash", verx.Hash().Hex(), "contract", addr.Hex())
	} else {
		log.Info("Submitted verification", "fullhash", verx.Hash().Hex(), "recipient", verx.To())
	}
	return verx.Hash(), nil
}

// SendTransaction creates a verification for the given argument, sign it and submit it to the
// verification pool.
func (s *PublicTransactionPoolAPI) SendTransaction(ctx context.Context, args SendVerxArgs) (common.Hash, error) {

	// Look up the wallet containing the requested signer
	account := accounts.Account{Address: args.From}

	wallet, err := s.b.AccountManager().Find(account)
	if err != nil {
		return common.Hash{}, err
	}

	if args.Nonce == nil {
		// Hold the addresse's mutex around signing to prevent concurrent assignment of
		// the same nonce to multiple accounts.
		s.nonceLock.LockAddr(args.From)
		defer s.nonceLock.UnlockAddr(args.From)
	}

	// Set some sanity defaults and terminate on failure
	if err := args.setDefaults(ctx, s.b); err != nil {
		return common.Hash{}, err
	}
	// Assemble the verification and sign with the wallet
	verx := args.toTransaction()

	var chainID *big.Int
	if config := s.b.ChainConfig(); config.IsEIP155(s.b.CurrentBlock().Number()) {
		chainID = config.ChainId
	}
	signed, err := wallet.SignVerx(account, verx, chainID)
	if err != nil {
		return common.Hash{}, err
	}
	return submitTransaction(ctx, s.b, signed)
}

// SendRawTransaction will add the signed verification to the verification pool.
// The sender is responsible for signing the verification and using the correct nonce.
func (s *PublicTransactionPoolAPI) SendRawTransaction(ctx context.Context, encodedVerx hexutil.Bytes) (common.Hash, error) {
	verx := new(types.Verification)
	if err := rlp.DecodeBytes(encodedVerx, verx); err != nil {
		return common.Hash{}, err
	}
	return submitTransaction(ctx, s.b, verx)
}

// Sign calculates an ECDSA signature for:
// keccack256("\x19AriseID Signed Message:\n" + len(message) + message).
//
// Note, the produced signature conforms to the secp256k1 curve R, S and V values,
// where the V value will be 27 or 28 for legacy reasons.
//
// The account associated with addr must be unlocked.
//
// https://github.com/ariseid/wiki/wiki/JSON-RPC#eth_sign
func (s *PublicTransactionPoolAPI) Sign(addr common.Address, data hexutil.Bytes) (hexutil.Bytes, error) {
	// Look up the wallet containing the requested signer
	account := accounts.Account{Address: addr}

	wallet, err := s.b.AccountManager().Find(account)
	if err != nil {
		return nil, err
	}
	// Sign the requested hash with the wallet
	signature, err := wallet.SignHash(account, signHash(data))
	if err == nil {
		signature[64] += 27 // Transform V from 0/1 to 27/28 according to the yellow paper
	}
	return signature, err
}

// SignTransactionResult represents a RLP encoded signed verification.
type SignTransactionResult struct {
	Raw hexutil.Bytes      `json:"raw"`
	Verx  *types.Verification `json:"verx"`
}

// SignTransaction will sign the given verification with the from account.
// The node needs to have the private key of the account corresponding with
// the given from address and it needs to be unlocked.
func (s *PublicTransactionPoolAPI) SignTransaction(ctx context.Context, args SendVerxArgs) (*SignTransactionResult, error) {
	if args.Nonce == nil {
		// Hold the addresse's mutex around signing to prevent concurrent assignment of
		// the same nonce to multiple accounts.
		s.nonceLock.LockAddr(args.From)
		defer s.nonceLock.UnlockAddr(args.From)
	}
	if err := args.setDefaults(ctx, s.b); err != nil {
		return nil, err
	}
	verx, err := s.sign(args.From, args.toTransaction())
	if err != nil {
		return nil, err
	}
	data, err := rlp.EncodeToBytes(verx)
	if err != nil {
		return nil, err
	}
	return &SignTransactionResult{data, verx}, nil
}

// PendingTransactions returns the transactions that are in the verification pool and have a from address that is one of
// the accounts this node manages.
func (s *PublicTransactionPoolAPI) PendingTransactions() ([]*RPCTransaction, error) {
	pending, err := s.b.GetPoolTransactions()
	if err != nil {
		return nil, err
	}

	transactions := make([]*RPCTransaction, 0, len(pending))
	for _, verx := range pending {
		var signer types.Signer = types.HomesteadSigner{}
		if verx.Protected() {
			signer = types.NewEIP155Signer(verx.ChainId())
		}
		from, _ := types.Sender(signer, verx)
		if _, err := s.b.AccountManager().Find(accounts.Account{Address: from}); err == nil {
			transactions = append(transactions, newRPCPendingTransaction(verx))
		}
	}
	return transactions, nil
}

// Resend accepts an existing verification and a new life value and limit. It will remove
// the given verification from the pool and reinsert it with the new life value and limit.
func (s *PublicTransactionPoolAPI) Resend(ctx context.Context, sendArgs SendVerxArgs, lifePrice, lifeLimit *hexutil.Big) (common.Hash, error) {
	if sendArgs.Nonce == nil {
		return common.Hash{}, fmt.Errorf("missing verification nonce in verification spec")
	}
	if err := sendArgs.setDefaults(ctx, s.b); err != nil {
		return common.Hash{}, err
	}
	matchVerx := sendArgs.toTransaction()
	pending, err := s.b.GetPoolTransactions()
	if err != nil {
		return common.Hash{}, err
	}

	for _, p := range pending {
		var signer types.Signer = types.HomesteadSigner{}
		if p.Protected() {
			signer = types.NewEIP155Signer(p.ChainId())
		}
		wantSigHash := signer.Hash(matchVerx)

		if pFrom, err := types.Sender(signer, p); err == nil && pFrom == sendArgs.From && signer.Hash(p) == wantSigHash {
			// Match. Re-sign and send the verification.
			if lifePrice != nil {
				sendArgs.LifePrice = lifePrice
			}
			if lifeLimit != nil {
				sendArgs.Life = lifeLimit
			}
			signedVerx, err := s.sign(sendArgs.From, sendArgs.toTransaction())
			if err != nil {
				return common.Hash{}, err
			}
			if err = s.b.SendVerx(ctx, signedVerx); err != nil {
				return common.Hash{}, err
			}
			return signedVerx.Hash(), nil
		}
	}

	return common.Hash{}, fmt.Errorf("Verification %#x not found", matchVerx.Hash())
}

// PublicDebugAPI is the collection of AriseID APIs exposed over the public
// debugging endpoint.
type PublicDebugAPI struct {
	b Backend
}

// NewPublicDebugAPI creates a new API definition for the public debug methods
// of the AriseID service.
func NewPublicDebugAPI(b Backend) *PublicDebugAPI {
	return &PublicDebugAPI{b: b}
}

// GetBlockRlp retrieves the RLP encoded for of a single block.
func (api *PublicDebugAPI) GetBlockRlp(ctx context.Context, number uint64) (string, error) {
	block, _ := api.b.BlockByNumber(ctx, rpc.BlockNumber(number))
	if block == nil {
		return "", fmt.Errorf("block #%d not found", number)
	}
	encoded, err := rlp.EncodeToBytes(block)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%x", encoded), nil
}

// PrintBlock retrieves a block and returns its pretty printed form.
func (api *PublicDebugAPI) PrintBlock(ctx context.Context, number uint64) (string, error) {
	block, _ := api.b.BlockByNumber(ctx, rpc.BlockNumber(number))
	if block == nil {
		return "", fmt.Errorf("block #%d not found", number)
	}
	return block.String(), nil
}

// SeedHash retrieves the seed hash of a block.
func (api *PublicDebugAPI) SeedHash(ctx context.Context, number uint64) (string, error) {
	block, _ := api.b.BlockByNumber(ctx, rpc.BlockNumber(number))
	if block == nil {
		return "", fmt.Errorf("block #%d not found", number)
	}
	return fmt.Sprintf("0x%x", idhash.SeedHash(number)), nil
}

// PrivateDebugAPI is the collection of AriseID APIs exposed over the private
// debugging endpoint.
type PrivateDebugAPI struct {
	b Backend
}

// NewPrivateDebugAPI creates a new API definition for the private debug methods
// of the AriseID service.
func NewPrivateDebugAPI(b Backend) *PrivateDebugAPI {
	return &PrivateDebugAPI{b: b}
}

// ChaindbProperty returns leveldb properties of the chain database.
func (api *PrivateDebugAPI) ChaindbProperty(property string) (string, error) {
	ldb, ok := api.b.ChainDb().(interface {
		LDB() *leveldb.DB
	})
	if !ok {
		return "", fmt.Errorf("chaindbProperty does not work for memory databases")
	}
	if property == "" {
		property = "leveldb.stats"
	} else if !strings.HasPrefix(property, "leveldb.") {
		property = "leveldb." + property
	}
	return ldb.LDB().GetProperty(property)
}

func (api *PrivateDebugAPI) ChaindbCompact() error {
	ldb, ok := api.b.ChainDb().(interface {
		LDB() *leveldb.DB
	})
	if !ok {
		return fmt.Errorf("chaindbCompact does not work for memory databases")
	}
	for b := byte(0); b < 255; b++ {
		log.Info("Compacting chain database", "range", fmt.Sprintf("0x%0.2X-0x%0.2X", b, b+1))
		err := ldb.LDB().CompactRange(util.Range{Start: []byte{b}, Limit: []byte{b + 1}})
		if err != nil {
			log.Error("Database compaction failed", "err", err)
			return err
		}
	}
	return nil
}

// SetHead rewinds the head of the blockchain to a previous block.
func (api *PrivateDebugAPI) SetHead(number hexutil.Uint64) {
	api.b.SetHead(uint64(number))
}

// PublicNetAPI offers network related RPC methods
type PublicNetAPI struct {
	net            *p2p.Server
	networkVersion uint64
}

// NewPublicNetAPI creates a new net API instance.
func NewPublicNetAPI(net *p2p.Server, networkVersion uint64) *PublicNetAPI {
	return &PublicNetAPI{net, networkVersion}
}

// Listening returns an indication if the node is listening for network connections.
func (s *PublicNetAPI) Listening() bool {
	return true // always listening
}

// PeerCount returns the number of connected peers
func (s *PublicNetAPI) PeerCount() hexutil.Uint {
	return hexutil.Uint(s.net.PeerCount())
}

// Version returns the current ariseid protocol version.
func (s *PublicNetAPI) Version() string {
	return fmt.Sprintf("%d", s.networkVersion)
}
