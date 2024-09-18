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

package txmgr

import (
	"context"

	"github.com/google/uuid"
	"github.com/hyperledger/firefly-signer/pkg/abi"
	"github.com/kaleido-io/paladin/core/internal/cache"
	"github.com/kaleido-io/paladin/core/internal/components"
	"github.com/kaleido-io/paladin/core/internal/rpcserver"
	"github.com/kaleido-io/paladin/core/pkg/persistence"
	"github.com/kaleido-io/paladin/toolkit/pkg/confutil"
	"github.com/kaleido-io/paladin/toolkit/pkg/tktypes"
)

func NewTXManager(ctx context.Context, conf *Config) components.TXManager {
	return &txManager{
		txCache:              cache.NewCache[uuid.UUID, *txStatusRecord](&conf.TransactionActivity.Cache, &DefaultConfig.TransactionActivity.Cache),
		abiCache:             cache.NewCache[tktypes.Bytes32, abi.ABI](&conf.ABI.Cache, &DefaultConfig.ABI.Cache),
		activityRecordsPerTX: confutil.IntMin(conf.TransactionActivity.RecordsPerTransaction, 0, *DefaultConfig.TransactionActivity.RecordsPerTransaction),
	}
}

type txManager struct {
	p                    persistence.Persistence
	txCache              cache.Cache[uuid.UUID, *txStatusRecord]
	abiCache             cache.Cache[tktypes.Bytes32, abi.ABI]
	activityRecordsPerTX int
	rpcModule            *rpcserver.RPCModule
}

func (tm *txManager) PostInit(c components.AllComponents) error {
	tm.p = c.Persistence()
	return nil
}

func (tm *txManager) PreInit(c components.PreInitComponents) (*components.ManagerInitResult, error) {
	tm.buildRPCModule()
	return &components.ManagerInitResult{
		RPCModules: []*rpcserver.RPCModule{tm.rpcModule},
	}, nil
}

func (tm *txManager) Start() error { return nil }

func (tm *txManager) Stop() {}
