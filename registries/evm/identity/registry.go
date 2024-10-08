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

package identity

import (
	"context"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/hyperledger/firefly-signer/pkg/abi"
	"github.com/hyperledger/firefly-signer/pkg/ethtypes"
	"github.com/kaleido-io/paladin/kata/pkg/blockindexer"
	"github.com/kaleido-io/paladin/kata/pkg/ethclient"
	"github.com/kaleido-io/paladin/kata/pkg/persistence"
	"github.com/kaleido-io/paladin/kata/pkg/types"
	"github.com/kaleido-io/paladin/registry/config"
)

//go:embed abis/IdentityRegistry.json
var identityRegistryBuildJSON []byte

type solBuild struct {
	ABI      abi.ABI                   `json:"abi"`
	Bytecode ethtypes.HexBytes0xPrefix `json:"bytecode"`
}

type IdentityRegistry struct {
	contract     solBuild
	indexer      blockindexer.BlockIndexer
	ethClient    ethclient.EthClient
	abiClient    ethclient.ABIClient
	keyMgr       ethclient.KeyManager
	contractAddr ethtypes.Address0xHex

	IdentityCache map[string]*Identity
	PropertyCache map[string]*map[string]string

	LastSync              int64
	LastIncrementalUpdate int64
}

var Registry IdentityRegistry

func (registry *IdentityRegistry) Initialize(conf config.Config) error {
	ctx := context.Background()

	registry.IdentityCache = make(map[string]*Identity)
	registry.PropertyCache = make(map[string]*map[string]string)

	persistence, err := persistence.NewPersistence(ctx, &conf.Persistence)
	if err != nil {
		return fmt.Errorf("Failed initialize persistence: %s", err)
	}

	registry.indexer, err = blockindexer.NewBlockIndexer(ctx, &blockindexer.Config{}, &conf.Eth.WS, persistence)
	if err != nil {
		return fmt.Errorf("Failed to initialize indexer: %s", err)
	}

	registry.keyMgr, err = ethclient.NewSimpleTestKeyManager(ctx, &conf.Keys)
	if err != nil {
		return fmt.Errorf("Failed to initialize key manager: %s", err)
	}

	ecf, err := ethclient.NewEthClientFactory(ctx, registry.keyMgr, &conf.Eth)
	if err != nil {
		return fmt.Errorf("Failed to initialize ethClient factory: %s", err)
	}

	err = ecf.Start()
	if err != nil {
		return fmt.Errorf("Failed to start ethClient factory: %s", err)
	}

	registry.ethClient = ecf.HTTPClient()

	err = registry.indexer.Start()
	if err != nil {
		return fmt.Errorf("Failed to initialize indexer: %s", err)
	}

	if len(conf.Contract.Address) > 0 {
		address, err := ethtypes.NewAddress(conf.Contract.Address)
		if err != nil {
			return fmt.Errorf("Invalid smart contract address: %s", err)
		}
		registry.contractAddr = *address
		err = registry.SyncCache()
		if err != nil {
			return err
		}
		err = registry.StartListening()
		if err != nil {
			return fmt.Errorf("Failed to initialize listener: %s", err)
		}
	}

	return nil
}

func (registry *IdentityRegistry) DeploySmartContract(signer string) (address ethtypes.Address0xHex, err error) {
	ctx := context.Background()

	err = json.Unmarshal(identityRegistryBuildJSON, &registry.contract)
	if err != nil {
		return
	}

	registry.abiClient, err = registry.ethClient.ABI(ctx, registry.contract.ABI)
	if err != nil {
		return
	}

	txHash, err := registry.abiClient.MustConstructor(types.HexBytes(registry.contract.Bytecode)).R(ctx).
		Signer(signer).SignAndSend()
	if err != nil {
		return
	}

	deployTX, err := registry.indexer.WaitForTransaction(ctx, *txHash)
	if err != nil {
		return
	}

	registry.contractAddr = *deployTX.ContractAddress.Address0xHex()

	err = registry.SyncCache()
	if err != nil {
		return
	}

	err = registry.StartListening()
	if err != nil {
		return
	}
	address = registry.contractAddr
	return
}

func (registry *IdentityRegistry) GetSmartContractAddress() (address ethtypes.Address0xHex, err error) {
	if !registry.IsSmartContractSet() {
		err = errors.New("Smart contract not set")
	}
	address = registry.contractAddr
	return
}

func (registry *IdentityRegistry) SetSmartContractAddress(address ethtypes.Address0xHex) (err error) {

	startListener := registry.contractAddr == ethtypes.Address0xHex{}

	registry.contractAddr = address

	err = registry.SyncCache()
	if err != nil {
		return err
	}

	if startListener {
		err = registry.StartListening()
		if err != nil {
			return
		}
	}

	return
}

func (registry *IdentityRegistry) IsSmartContractSet() bool {
	return registry.contractAddr != ethtypes.Address0xHex{}
}
