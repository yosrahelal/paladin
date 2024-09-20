/*
 * Copyright © 2024 Kaleido, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with
 * the License. You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on
 * an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations under the License.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package publictxmgr

import (
	"context"
	"encoding/json"
	"fmt"
	"math/big"

	baseTypes "github.com/kaleido-io/paladin/core/internal/engine/enginespi"

	"github.com/hyperledger/firefly-common/pkg/fftypes"
	"github.com/hyperledger/firefly-common/pkg/i18n"
	"github.com/hyperledger/firefly-signer/pkg/ethsigner"
	"github.com/hyperledger/firefly-signer/pkg/ethtypes"
	"github.com/kaleido-io/paladin/core/internal/cache"
	"github.com/kaleido-io/paladin/core/internal/msgs"
	"github.com/kaleido-io/paladin/core/pkg/ethclient"
	"github.com/kaleido-io/paladin/toolkit/pkg/confutil"
	"github.com/kaleido-io/paladin/toolkit/pkg/log"
)

type GasPriceConfig struct {
	IncreaseMax        *string      `yaml:"increaseMax"`
	IncreasePercentage *int         `yaml:"increasePercentage"`
	FixedGasPrice      any          `yaml:"fixedGasPrice"` // number or object
	Cache              cache.Config `yaml:"cache"`
}

var DefaultGasPriceConfig = &GasPriceConfig{
	IncreaseMax:        nil,
	IncreasePercentage: confutil.P(0),
	FixedGasPrice:      nil,
	Cache: cache.Config{
		Capacity: confutil.P(100),
		// TODO: Enable a KB based cache with TTL in Paladin
		// Enabled: confutil.P(true),
		// Size:    confutil.P("1kb"),
		// TTL:     confutil.P("1s"),
	},
}

type GasPriceClient interface {
	DeleteCache(ctx context.Context) bool
	HasZeroGasPrice(ctx context.Context) bool
	SetFixedGasPriceIfConfigured(ctx context.Context, ethTx *ethsigner.Transaction)
	GetFixedGasPriceJSON(ctx context.Context) (gasPrice *fftypes.JSONAny)
	ParseGasPriceJSON(ctx context.Context, input *fftypes.JSONAny) (gpo *baseTypes.GasPriceObject, err error)
	GetGasPriceObject(ctx context.Context) (gasPrice *baseTypes.GasPriceObject, err error)
	Init(ctx context.Context, cAPI ethclient.EthClient)
}

// The hybrid gas price client retrieves gas price using the following methods in order and will return as soon as the method succeeded unless there is an override
//   - Fixed gas price
//   - Cached gas price
//   - Gas Oracle
//   - Node gas_Price
type HybridGasPriceClient struct {
	hasZeroGasPrice bool
	fixedGasPrice   *fftypes.JSONAny
	cAPI            ethclient.EthClient
	gasPriceCache   cache.CInterface
}

func (hGpc *HybridGasPriceClient) HasZeroGasPrice(ctx context.Context) bool {
	return hGpc.hasZeroGasPrice
}

func (hGpc *HybridGasPriceClient) GetFixedGasPriceJSON(ctx context.Context) (gasPrice *fftypes.JSONAny) {
	return hGpc.fixedGasPrice
}

func (hGpc *HybridGasPriceClient) SetFixedGasPriceIfConfigured(ctx context.Context, ethTx *ethsigner.Transaction) {
	if hGpc.fixedGasPrice != nil {
		gpo, _ := hGpc.ParseGasPriceJSON(ctx, hGpc.fixedGasPrice)
		if gpo.GasPrice != nil {
			ethTx.GasPrice = (*ethtypes.HexInteger)(gpo.GasPrice)
		}
		if gpo.MaxFeePerGas != nil {
			ethTx.MaxFeePerGas = (*ethtypes.HexInteger)(gpo.MaxFeePerGas)
		}

		if gpo.MaxPriorityFeePerGas != nil {
			ethTx.MaxPriorityFeePerGas = (*ethtypes.HexInteger)(gpo.MaxPriorityFeePerGas)
		}
	}
}

func (hGpc *HybridGasPriceClient) GetGasPriceObject(ctx context.Context) (gasPrice *baseTypes.GasPriceObject, err error) {

	gasPriceJSON, err := hGpc.getGasPriceJSON(ctx)
	if err != nil {
		return nil, err
	}

	return hGpc.ParseGasPriceJSON(ctx, gasPriceJSON)
}

func (hGpc *HybridGasPriceClient) getGasPriceJSON(ctx context.Context) (gasPriceJSON *fftypes.JSONAny, err error) {

	//  fixed price overrides everything
	if !hGpc.fixedGasPrice.IsNil() {
		log.L(ctx).Debugf("Retrieving gas price from fixed gas price")
		gasPriceJSON = hGpc.fixedGasPrice
		return
	}

	// use the cache gas price first
	cachedGasPrice := hGpc.gasPriceCache.Get("gasPrice")
	if cachedGasPrice != nil {
		return cachedGasPrice.(*fftypes.JSONAny), nil
	}

	// then try to use the node eth call
	log.L(ctx).Debugf("Retrieving gas price from node eth call")
	gasPriceHexInt, err := hGpc.cAPI.GasPrice(ctx)
	if err != nil {
		// no fallback is available, return the error
		log.L(ctx).Errorf("Failed to retrieve gas price from the node")
		return nil, err
	} else {
		gasPriceJSON = fftypes.JSONAnyPtr(fmt.Sprintf(`"%s"`, gasPriceHexInt.BigInt().String()))
	}

	hGpc.gasPriceCache.Set("gasPrice", gasPriceJSON)

	return gasPriceJSON, nil

}
func (hGpc *HybridGasPriceClient) Init(ctx context.Context, cAPI ethclient.EthClient) {
	hGpc.cAPI = cAPI
	// check whether it's a gasless chain
	gasPriceJson := hGpc.GetFixedGasPriceJSON(ctx)
	gpo, err := hGpc.ParseGasPriceJSON(ctx, gasPriceJson)
	if err != nil {
		log.L(ctx).Warnf("Cannot get gas price due to %+v", err)
	}

	if gpo != nil && ((gpo.GasPrice != nil && gpo.GasPrice.Sign() == 0) ||
		(gpo.MaxFeePerGas != nil && gpo.MaxFeePerGas.Sign() == 0 &&
			gpo.MaxPriorityFeePerGas != nil && gpo.MaxPriorityFeePerGas.Sign() == 0)) {
		hGpc.hasZeroGasPrice = true
		hGpc.fixedGasPrice = gasPriceJson
	}
}

func (hGpc *HybridGasPriceClient) DeleteCache(ctx context.Context) bool {
	return hGpc.gasPriceCache.Delete("gasPrice")
}

func NewGasPriceClient(ctx context.Context, conf *Config) GasPriceClient {
	gasPriceCache := cache.NewCache[string, *big.Int](&conf.GasPrice.Cache, &DefaultConfig.GasPrice.Cache)
	log.L(ctx).Debugf("Gas price cache size: %d", gasPriceCache.Capacity())
	gasPriceClient := &HybridGasPriceClient{}
	// initialize gas oracle
	// set fixed gas price
	gasPriceClient.fixedGasPrice = fftypes.JSONAnyPtr(conf.GetString(GasPriceFixedJSONString))
	gasPriceClient.gasPriceCache = gasPriceCache

	return gasPriceClient
}

func (hGpc *HybridGasPriceClient) ParseGasPriceJSON(ctx context.Context, input *fftypes.JSONAny) (gpo *baseTypes.GasPriceObject, err error) {
	gpo = &baseTypes.GasPriceObject{}
	if input == nil {
		gpo.GasPrice = big.NewInt(0)
		log.L(ctx).Tracef("Gas price object generated using empty input, gasPrice=%+v", gpo)
		return gpo, nil
	}
	gasPriceObject := input.JSONObjectNowarn()

	maxPriorityFeePerGas := gasPriceObject.GetInteger("maxPriorityFeePerGas")
	maxFeePerGas := gasPriceObject.GetInteger("maxFeePerGas")
	if maxPriorityFeePerGas.Sign() > 0 || maxFeePerGas.Sign() > 0 {
		gpo = &baseTypes.GasPriceObject{
			MaxPriorityFeePerGas: maxPriorityFeePerGas,
			MaxFeePerGas:         maxFeePerGas,
		}
		log.L(ctx).Tracef("Gas price object generated using EIP1559 fields, gasPrice=%+v", gpo)
		return gpo, nil
	}
	gpo.GasPrice = gasPriceObject.GetInteger("gasPrice")
	if gpo.GasPrice.Sign() == 0 {
		tempHexInt := ethtypes.NewHexInteger(big.NewInt(0))
		err := json.Unmarshal(input.Bytes(), tempHexInt)
		if err != nil {
			return nil, i18n.NewError(ctx, msgs.MsgGasPriceError, input.String(), err.Error())
		}
		gpo.GasPrice = tempHexInt.BigInt()
		log.L(ctx).Tracef("Gas price object generated using gasPrice number, gasPrice=%+v", gpo)
		return gpo, nil
	}
	log.L(ctx).Tracef("Gas price object generated using gasPrice field, gasPrice=%+v", gpo)
	return gpo, nil
}
