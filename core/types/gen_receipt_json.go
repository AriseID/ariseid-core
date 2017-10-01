// Code generated by github.com/fjl/gencodec. DO NOT EDIT.

package types

import (
	"encoding/json"
	"errors"
	"math/big"

	"github.com/ariseid/ariseid-core/common"
	"github.com/ariseid/ariseid-core/common/hexutil"
)

func (r Receipt) MarshalJSON() ([]byte, error) {
	type Receipt struct {
		PostState         hexutil.Bytes  `json:"root"`
		Failed            bool           `json:"failed"`
		CumulativeLifeUsed *hexutil.Big   `json:"cumulativeLifeUsed" gencodec:"required"`
		Bloom             Bloom          `json:"logsBloom"         gencodec:"required"`
		Logs              []*Log         `json:"logs"              gencodec:"required"`
		VerxHash            common.Hash    `json:"transactionHash" gencodec:"required"`
		ContractAddress   common.Address `json:"contractAddress"`
		LifeUsed           *hexutil.Big   `json:"lifeUsed" gencodec:"required"`
	}
	var enc Receipt
	enc.PostState = r.PostState
	enc.Failed = r.Failed
	enc.CumulativeLifeUsed = (*hexutil.Big)(r.CumulativeLifeUsed)
	enc.Bloom = r.Bloom
	enc.Logs = r.Logs
	enc.VerxHash = r.VerxHash
	enc.ContractAddress = r.ContractAddress
	enc.LifeUsed = (*hexutil.Big)(r.LifeUsed)
	return json.Marshal(&enc)
}

func (r *Receipt) UnmarshalJSON(input []byte) error {
	type Receipt struct {
		PostState         hexutil.Bytes   `json:"root"`
		Failed            *bool           `json:"failed"`
		CumulativeLifeUsed *hexutil.Big    `json:"cumulativeLifeUsed" gencodec:"required"`
		Bloom             *Bloom          `json:"logsBloom"         gencodec:"required"`
		Logs              []*Log          `json:"logs"              gencodec:"required"`
		VerxHash            *common.Hash    `json:"transactionHash" gencodec:"required"`
		ContractAddress   *common.Address `json:"contractAddress"`
		LifeUsed           *hexutil.Big    `json:"lifeUsed" gencodec:"required"`
	}
	var dec Receipt
	if err := json.Unmarshal(input, &dec); err != nil {
		return err
	}
	if dec.PostState != nil {
		r.PostState = dec.PostState
	}
	if dec.Failed != nil {
		r.Failed = *dec.Failed
	}
	if dec.CumulativeLifeUsed == nil {
		return errors.New("missing required field 'cumulativeLifeUsed' for Receipt")
	}
	r.CumulativeLifeUsed = (*big.Int)(dec.CumulativeLifeUsed)
	if dec.Bloom == nil {
		return errors.New("missing required field 'logsBloom' for Receipt")
	}
	r.Bloom = *dec.Bloom
	if dec.Logs == nil {
		return errors.New("missing required field 'logs' for Receipt")
	}
	r.Logs = dec.Logs
	if dec.VerxHash == nil {
		return errors.New("missing required field 'transactionHash' for Receipt")
	}
	r.VerxHash = *dec.VerxHash
	if dec.ContractAddress != nil {
		r.ContractAddress = *dec.ContractAddress
	}
	if dec.LifeUsed == nil {
		return errors.New("missing required field 'lifeUsed' for Receipt")
	}
	r.LifeUsed = (*big.Int)(dec.LifeUsed)
	return nil
}