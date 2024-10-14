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

package keymanager

import (
	"context"

	"github.com/kaleido-io/paladin/config/pkg/pldconf"
	"github.com/kaleido-io/paladin/core/internal/components"
	"github.com/kaleido-io/paladin/core/pkg/persistence"

	"github.com/kaleido-io/paladin/toolkit/pkg/rpcserver"
	"github.com/kaleido-io/paladin/toolkit/pkg/signerapi"
)

type keyManager struct {
	bgCtx context.Context

	conf      *pldconf.KeyManagerConfig
	rpcModule *rpcserver.RPCModule

	p persistence.Persistence
}

func NewKeyManager(bgCtx context.Context, conf *pldconf.KeyManagerConfig) components.KeyManager {
	return &keyManager{
		bgCtx: bgCtx,
		conf:  conf,
	}
}

func (km *keyManager) PreInit(pic components.PreInitComponents) (*components.ManagerInitResult, error) {
	return &components.ManagerInitResult{
		RPCModules: []*rpcserver.RPCModule{km.rpcModule},
	}, nil
}

func (tm *keyManager) PostInit(c components.AllComponents) error {
	tm.p = c.Persistence()
	return nil
}

func (tm *keyManager) Start() error {
	return nil
}

func (tm *keyManager) Stop() {
}

func (km *keyManager) ResolveKey(ctx context.Context, identifier string, algorithm string, verifierType string) (keyHandle string, verifier string, err error) {
	panic("unimplemented")
}

func (km *keyManager) Sign(ctx context.Context, req *signerapi.SignRequest) (*signerapi.SignResponse, error) {
	panic("unimplemented")
}
