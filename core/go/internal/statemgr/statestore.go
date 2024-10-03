// Copyright © 2024 Kaleido, Inc.
//
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package statemgr

import (
	"context"
	"sync"

	"github.com/kaleido-io/paladin/config/pkg/confutil"
	"github.com/kaleido-io/paladin/config/pkg/pldconf"
	"github.com/kaleido-io/paladin/core/internal/components"
	"github.com/kaleido-io/paladin/core/pkg/persistence"
	"github.com/kaleido-io/paladin/toolkit/pkg/cache"
	"github.com/kaleido-io/paladin/toolkit/pkg/rpcserver"
)

type stateStore struct {
	p              persistence.Persistence
	bgCtx          context.Context
	cancelCtx      context.CancelFunc
	conf           *pldconf.StateStoreConfig
	writer         *stateWriter
	abiSchemaCache cache.Cache[string, components.Schema]
	rpcModule      *rpcserver.RPCModule
	domainLock     sync.Mutex
	domainContexts map[string]*domainContext
}

var SchemaCacheDefaults = &pldconf.CacheConfig{
	Capacity: confutil.P(1000),
}

func NewStateManager(ctx context.Context, conf *pldconf.StateStoreConfig, p persistence.Persistence) components.StateManager {
	ss := &stateStore{
		p:              p,
		conf:           conf,
		abiSchemaCache: cache.NewCache[string, components.Schema](&conf.SchemaCache, SchemaCacheDefaults),
		domainContexts: make(map[string]*domainContext),
	}
	ss.bgCtx, ss.cancelCtx = context.WithCancel(ctx)
	return ss
}

func (ss *stateStore) PreInit(c components.PreInitComponents) (*components.ManagerInitResult, error) {
	ss.initRPC()
	return &components.ManagerInitResult{
		RPCModules: []*rpcserver.RPCModule{ss.rpcModule},
	}, nil
}

func (ss *stateStore) PostInit(c components.AllComponents) error {
	ss.writer = newStateWriter(ss.bgCtx, ss, &ss.conf.StateWriter)
	return nil
}

func (ss *stateStore) Start() error {
	return nil
}

func (ss *stateStore) Stop() {
	ss.writer.stop()
	ss.cancelCtx()
}
