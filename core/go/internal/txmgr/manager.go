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

	"github.com/kaleido-io/paladin/core/internal/components"
	"github.com/kaleido-io/paladin/core/pkg/config"
	"github.com/kaleido-io/paladin/core/pkg/persistence"
	"github.com/kaleido-io/paladin/toolkit/pkg/cache"
	"github.com/kaleido-io/paladin/toolkit/pkg/ptxapi"
	"github.com/kaleido-io/paladin/toolkit/pkg/rpcserver"
	"github.com/kaleido-io/paladin/toolkit/pkg/tktypes"
)

func NewTXManager(ctx context.Context, conf *config.TxManagerConfig) components.TXManager {
	return &txManager{
		abiCache: cache.NewCache[tktypes.Bytes32, *ptxapi.StoredABI](&conf.ABI.Cache, &config.TxManagerDefaults.ABI.Cache),
	}
}

type txManager struct {
	p            persistence.Persistence
	publicTxMgr  components.PublicTxManager
	privateTxMgr components.PrivateTxManager
	abiCache     cache.Cache[tktypes.Bytes32, *ptxapi.StoredABI]
	rpcModule    *rpcserver.RPCModule
}

func (tm *txManager) PostInit(c components.AllComponents) error {
	tm.p = c.Persistence()
	tm.publicTxMgr = c.PublicTxManager()
	tm.privateTxMgr = c.PrivateTxManager()
	return nil
}

func (tm *txManager) PreInit(c components.PreInitComponents) (*components.ManagerInitResult, error) {
	tm.buildRPCModule()
	return &components.ManagerInitResult{
		RPCModules:       []*rpcserver.RPCModule{tm.rpcModule},
		PreCommitHandler: tm.blockIndexerPreCommit,
	}, nil
}

func (tm *txManager) Start() error { return nil }

func (tm *txManager) Stop() {}
