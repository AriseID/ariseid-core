// Code generated by github.com/fjl/gencodec. DO NOT EDIT.

package tests

import (
	"encoding/json"
	"math/big"

	"github.com/ariseid/ariseid-core/common/hexutil"
	"github.com/ariseid/ariseid-core/common/math"
)

var _ = (*stTransactionMarshaling)(nil)

func (s stTransaction) MarshalJSON() ([]byte, error) {
	type stTransaction struct {
		LifePrice   *math.HexOrDecimal256 `json:"lifePrice"`
		Nonce      math.HexOrDecimal64   `json:"nonce"`
		To         string                `json:"to"`
		Data       []string              `json:"data"`
		LifeLimit   []math.HexOrDecimal64 `json:"lifeLimit"`
		Value      []string              `json:"value"`
		PrivateKey hexutil.Bytes         `json:"secretKey"`
	}
	var enc stTransaction
	enc.LifePrice = (*math.HexOrDecimal256)(s.LifePrice)
	enc.Nonce = math.HexOrDecimal64(s.Nonce)
	enc.To = s.To
	enc.Data = s.Data
	if s.LifeLimit != nil {
		enc.LifeLimit = make([]math.HexOrDecimal64, len(s.LifeLimit))
		for k, v := range s.LifeLimit {
			enc.LifeLimit[k] = math.HexOrDecimal64(v)
		}
	}
	enc.Value = s.Value
	enc.PrivateKey = s.PrivateKey
	return json.Marshal(&enc)
}

func (s *stTransaction) UnmarshalJSON(input []byte) error {
	type stTransaction struct {
		LifePrice   *math.HexOrDecimal256 `json:"lifePrice"`
		Nonce      *math.HexOrDecimal64  `json:"nonce"`
		To         *string               `json:"to"`
		Data       []string              `json:"data"`
		LifeLimit   []math.HexOrDecimal64 `json:"lifeLimit"`
		Value      []string              `json:"value"`
		PrivateKey hexutil.Bytes         `json:"secretKey"`
	}
	var dec stTransaction
	if err := json.Unmarshal(input, &dec); err != nil {
		return err
	}
	if dec.LifePrice != nil {
		s.LifePrice = (*big.Int)(dec.LifePrice)
	}
	if dec.Nonce != nil {
		s.Nonce = uint64(*dec.Nonce)
	}
	if dec.To != nil {
		s.To = *dec.To
	}
	if dec.Data != nil {
		s.Data = dec.Data
	}
	if dec.LifeLimit != nil {
		s.LifeLimit = make([]uint64, len(dec.LifeLimit))
		for k, v := range dec.LifeLimit {
			s.LifeLimit[k] = uint64(v)
		}
	}
	if dec.Value != nil {
		s.Value = dec.Value
	}
	if dec.PrivateKey != nil {
		s.PrivateKey = dec.PrivateKey
	}
	return nil
}
