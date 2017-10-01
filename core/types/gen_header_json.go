// Code generated by github.com/fjl/gencodec. DO NOT EDIT.

package types

import (
	"encoding/json"
	"errors"
	"math/big"

	"github.com/ariseid/ariseid-core/common"
	"github.com/ariseid/ariseid-core/common/hexutil"
)

func (h Header) MarshalJSON() ([]byte, error) {
	type Header struct {
		ParentHash  common.Hash    `json:"parentHash"       gencodec:"required"`
		UncleHash   common.Hash    `json:"sha3Uncles"       gencodec:"required"`
		Coinbase    common.Address `json:"verifier"            gencodec:"required"`
		Root        common.Hash    `json:"stateRoot"        gencodec:"required"`
		VerxHash      common.Hash    `json:"transactionsRoot" gencodec:"required"`
		ReceiptHash common.Hash    `json:"receiptsRoot"     gencodec:"required"`
		Bloom       Bloom          `json:"logsBloom"        gencodec:"required"`
		Difficulty  *hexutil.Big   `json:"difficulty"       gencodec:"required"`
		Number      *hexutil.Big   `json:"number"           gencodec:"required"`
		LifeLimit    *hexutil.Big   `json:"lifeLimit"         gencodec:"required"`
		LifeUsed     *hexutil.Big   `json:"lifeUsed"          gencodec:"required"`
		Time        *hexutil.Big   `json:"timestamp"        gencodec:"required"`
		Extra       hexutil.Bytes  `json:"extraData"        gencodec:"required"`
		MixDigest   common.Hash    `json:"mixHash"          gencodec:"required"`
		Nonce       BlockNonce     `json:"nonce"            gencodec:"required"`
		Hash        common.Hash    `json:"hash"`
	}
	var enc Header
	enc.ParentHash = h.ParentHash
	enc.UncleHash = h.UncleHash
	enc.Coinbase = h.Coinbase
	enc.Root = h.Root
	enc.VerxHash = h.VerxHash
	enc.ReceiptHash = h.ReceiptHash
	enc.Bloom = h.Bloom
	enc.Difficulty = (*hexutil.Big)(h.Difficulty)
	enc.Number = (*hexutil.Big)(h.Number)
	enc.LifeLimit = (*hexutil.Big)(h.LifeLimit)
	enc.LifeUsed = (*hexutil.Big)(h.LifeUsed)
	enc.Time = (*hexutil.Big)(h.Time)
	enc.Extra = h.Extra
	enc.MixDigest = h.MixDigest
	enc.Nonce = h.Nonce
	enc.Hash = h.Hash()
	return json.Marshal(&enc)
}

func (h *Header) UnmarshalJSON(input []byte) error {
	type Header struct {
		ParentHash  *common.Hash    `json:"parentHash"       gencodec:"required"`
		UncleHash   *common.Hash    `json:"sha3Uncles"       gencodec:"required"`
		Coinbase    *common.Address `json:"verifier"            gencodec:"required"`
		Root        *common.Hash    `json:"stateRoot"        gencodec:"required"`
		VerxHash      *common.Hash    `json:"transactionsRoot" gencodec:"required"`
		ReceiptHash *common.Hash    `json:"receiptsRoot"     gencodec:"required"`
		Bloom       *Bloom          `json:"logsBloom"        gencodec:"required"`
		Difficulty  *hexutil.Big    `json:"difficulty"       gencodec:"required"`
		Number      *hexutil.Big    `json:"number"           gencodec:"required"`
		LifeLimit    *hexutil.Big    `json:"lifeLimit"         gencodec:"required"`
		LifeUsed     *hexutil.Big    `json:"lifeUsed"          gencodec:"required"`
		Time        *hexutil.Big    `json:"timestamp"        gencodec:"required"`
		Extra       hexutil.Bytes   `json:"extraData"        gencodec:"required"`
		MixDigest   *common.Hash    `json:"mixHash"          gencodec:"required"`
		Nonce       *BlockNonce     `json:"nonce"            gencodec:"required"`
	}
	var dec Header
	if err := json.Unmarshal(input, &dec); err != nil {
		return err
	}
	if dec.ParentHash == nil {
		return errors.New("missing required field 'parentHash' for Header")
	}
	h.ParentHash = *dec.ParentHash
	if dec.UncleHash == nil {
		return errors.New("missing required field 'sha3Uncles' for Header")
	}
	h.UncleHash = *dec.UncleHash
	if dec.Coinbase == nil {
		return errors.New("missing required field 'verifier' for Header")
	}
	h.Coinbase = *dec.Coinbase
	if dec.Root == nil {
		return errors.New("missing required field 'stateRoot' for Header")
	}
	h.Root = *dec.Root
	if dec.VerxHash == nil {
		return errors.New("missing required field 'transactionsRoot' for Header")
	}
	h.VerxHash = *dec.VerxHash
	if dec.ReceiptHash == nil {
		return errors.New("missing required field 'receiptsRoot' for Header")
	}
	h.ReceiptHash = *dec.ReceiptHash
	if dec.Bloom == nil {
		return errors.New("missing required field 'logsBloom' for Header")
	}
	h.Bloom = *dec.Bloom
	if dec.Difficulty == nil {
		return errors.New("missing required field 'difficulty' for Header")
	}
	h.Difficulty = (*big.Int)(dec.Difficulty)
	if dec.Number == nil {
		return errors.New("missing required field 'number' for Header")
	}
	h.Number = (*big.Int)(dec.Number)
	if dec.LifeLimit == nil {
		return errors.New("missing required field 'lifeLimit' for Header")
	}
	h.LifeLimit = (*big.Int)(dec.LifeLimit)
	if dec.LifeUsed == nil {
		return errors.New("missing required field 'lifeUsed' for Header")
	}
	h.LifeUsed = (*big.Int)(dec.LifeUsed)
	if dec.Time == nil {
		return errors.New("missing required field 'timestamp' for Header")
	}
	h.Time = (*big.Int)(dec.Time)
	if dec.Extra == nil {
		return errors.New("missing required field 'extraData' for Header")
	}
	h.Extra = dec.Extra
	if dec.MixDigest == nil {
		return errors.New("missing required field 'mixHash' for Header")
	}
	h.MixDigest = *dec.MixDigest
	if dec.Nonce == nil {
		return errors.New("missing required field 'nonce' for Header")
	}
	h.Nonce = *dec.Nonce
	return nil
}
