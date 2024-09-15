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

package helpers

import (
	"context"
	"testing"

	"github.com/hyperledger/firefly-signer/pkg/abi"
	"github.com/hyperledger/firefly-signer/pkg/ethtypes"
	"github.com/hyperledger/firefly-signer/pkg/rpcbackend"
	"github.com/kaleido-io/paladin/core/pkg/ethclient"
	"github.com/kaleido-io/paladin/core/pkg/testbed"
	"github.com/stretchr/testify/assert"
)

type AtomFactoryHelper struct {
	t           *testing.T
	tb          testbed.Testbed
	rpc         rpcbackend.Backend
	eth         ethclient.EthClient
	Address     ethtypes.Address0xHex
	FactoryABI  abi.ABI
	InstanceABI abi.ABI
}

type AtomHelper struct {
	t           *testing.T
	tb          testbed.Testbed
	eth         ethclient.EthClient
	Address     ethtypes.Address0xHex
	InstanceABI abi.ABI
}

type AtomOperation struct {
	ContractAddress ethtypes.Address0xHex     `json:"contractAddress"`
	CallData        ethtypes.HexBytes0xPrefix `json:"callData"`
}

type AtomDeployed struct {
	Address ethtypes.Address0xHex `json:"addr"`
}

func InitAtom(
	t *testing.T,
	tb testbed.Testbed,
	rpc rpcbackend.Backend,
	address string,
	factoryABI abi.ABI,
	instanceABI abi.ABI,
) *AtomFactoryHelper {
	return &AtomFactoryHelper{
		t:           t,
		tb:          tb,
		rpc:         rpc,
		eth:         tb.Components().EthClientFactory().HTTPClient(),
		Address:     *ethtypes.MustNewAddress(address),
		FactoryABI:  factoryABI,
		InstanceABI: instanceABI,
	}
}

func (a *AtomFactoryHelper) Create(ctx context.Context, signer string, operations []*AtomOperation) *AtomHelper {
	txHash, err := functionBuilder(ctx, a.t, a.eth, a.FactoryABI, "create").
		Signer(signer).
		To(&a.Address).
		Input(toJSON(a.t, map[string]any{"operations": operations})).
		SignAndSend()
	waitFor(ctx, a.t, a.tb, txHash, err)

	var atomDeployed AtomDeployed
	findEvent(ctx, a.t, a.tb, *txHash, a.FactoryABI, "AtomDeployed", &atomDeployed)
	assert.NotEmpty(a.t, atomDeployed.Address)
	return &AtomHelper{
		t:           a.t,
		tb:          a.tb,
		eth:         a.eth,
		Address:     atomDeployed.Address,
		InstanceABI: a.InstanceABI,
	}
}

func (a *AtomHelper) Execute(ctx context.Context) *TransactionHelper {
	builder := functionBuilder(ctx, a.t, a.eth, a.InstanceABI, "execute").To(&a.Address)
	return NewTransactionHelper(a.t, a.tb, builder)
}
