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

package privatetxnmgr

import (
	"github.com/kaleido-io/paladin/core/internal/components"
	"github.com/kaleido-io/paladin/core/internal/privatetxnmgr/ptmgrtypes"
	"github.com/kaleido-io/paladin/core/internal/statestore"
	"github.com/kaleido-io/paladin/core/pkg/ethclient"
)

type PaladinStageFoundationService struct {
	stateStore statestore.StateStore
	domainAPI  components.DomainSmartContract
	transport  components.TransportManager
	keyManager ethclient.KeyManager
}

type TransactionDispatched struct {
}

func (psfs *PaladinStageFoundationService) StateStore() statestore.StateStore {
	return psfs.stateStore
}

func (psfs *PaladinStageFoundationService) TransportManager() components.TransportManager {
	return psfs.transport
}

func (psfs *PaladinStageFoundationService) DomainAPI() components.DomainSmartContract {
	return psfs.domainAPI
}

func (psfs *PaladinStageFoundationService) KeyManager() ethclient.KeyManager {
	return psfs.keyManager
}

func NewPaladinStageFoundationService(
	stateStore statestore.StateStore,
	transport components.TransportManager,
	domainAPI components.DomainSmartContract,
	keyManager ethclient.KeyManager,
) ptmgrtypes.StageFoundationService {
	return &PaladinStageFoundationService{
		stateStore: stateStore,
		transport:  transport,
		domainAPI:  domainAPI,
		keyManager: keyManager,
	}
}
