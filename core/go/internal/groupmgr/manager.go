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

package groupmgr

import (
	"context"

	"github.com/kaleido-io/paladin/config/pkg/pldconf"
	"github.com/kaleido-io/paladin/core/internal/components"
	"github.com/kaleido-io/paladin/core/pkg/persistence"

	"github.com/kaleido-io/paladin/toolkit/pkg/pldapi"
	"github.com/kaleido-io/paladin/toolkit/pkg/query"
	"github.com/kaleido-io/paladin/toolkit/pkg/rpcserver"
	"github.com/kaleido-io/paladin/toolkit/pkg/tktypes"
)

type groupManager struct {
	bgCtx     context.Context
	cancelCtx context.CancelFunc

	rpcModule *rpcserver.RPCModule
	conf      *pldconf.GroupManagerConfig

	stateManager  components.StateManager
	domainManager components.DomainManager
	persistence   persistence.Persistence
}

func NewGroupManager(bgCtx context.Context, conf *pldconf.GroupManagerConfig) components.GroupManager {
	gm := &groupManager{
		conf: conf,
	}
	gm.bgCtx, gm.cancelCtx = context.WithCancel(bgCtx)
	return gm
}

func (gm *groupManager) PreInit(pic components.PreInitComponents) (*components.ManagerInitResult, error) {
	gm.initRPC()
	return &components.ManagerInitResult{
		RPCModules: []*rpcserver.RPCModule{gm.rpcModule},
	}, nil
}

func (gm *groupManager) PostInit(c components.AllComponents) error {
	gm.stateManager = c.StateManager()
	gm.domainManager = c.DomainManager()
	gm.persistence = c.Persistence()
	return nil
}

func (gm *groupManager) Start() error {
	return nil
}

func (gm *groupManager) Stop() {
	gm.cancelCtx()
}

func (gm *groupManager) CreateGroup(ctx context.Context, dbTX persistence.DBTX, spec *pldapi.PrivacyGroupInput) (id tktypes.HexBytes, err error) {

	domain, err := gm.domainManager.GetDomainByName(ctx, spec.Domain)
	if err != nil {
		return nil, err
	}

	pGroup, err := domain.InitPrivacyGroup(ctx, dbTX, domain, spec)
	if err != nil {
		return nil, err
	}

	return nil, nil
}

func (gm *groupManager) QueryGroups(ctx context.Context, dbTX persistence.DBTX, jq *query.QueryJSON) ([]*pldapi.PrivacyGroup, error) {
	// TODO: implement
	return nil, nil
}
