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

	"github.com/hyperledger/firefly-common/pkg/config"
	"github.com/hyperledger/firefly-common/pkg/i18n"
	"github.com/kaleido-io/paladin/core/internal/components"
	"github.com/kaleido-io/paladin/core/internal/msgs"
	"github.com/kaleido-io/paladin/toolkit/pkg/log"
)

type publicTxMgr struct {
	publicTxEngine components.PublicTxEngine
	rootCtx        context.Context
	rootCtxCancel  context.CancelFunc
	stopChan       <-chan struct{}
}

func NewPublicTransactionMgr(ctx context.Context) components.PublicTxManager {
	ptmCtx, ptmCtxCancel := context.WithCancel(log.WithLogField(ctx, "role", "public_tx_mgr"))
	return &publicTxMgr{
		rootCtx:       ptmCtx,
		rootCtxCancel: ptmCtxCancel,
	}
}

// Init only depends on the configuration and components - no other managers
func (ptm *publicTxMgr) PreInit(pic components.PreInitComponents) (result *components.ManagerInitResult, err error) {
	if ptm.publicTxEngine == nil {
		tmpConfigSection := config.RootSection("tmp")
		ptm.publicTxEngine, err = NewTransactionEngine(ptm.rootCtx, tmpConfigSection)
		if err != nil {
			return nil, err
		}
		ptm.publicTxEngine.Init(ptm.rootCtx, pic.EthClientFactory().HTTPClient(), pic.KeyManager(), nil /*TODO: transaction storage**/, nil, pic.BlockIndexer())
		return nil, nil
	} else {
		return nil, i18n.NewError(ptm.rootCtx, msgs.MsgPublicTxMgrAlreadyInit)
	}
}

// Post-init allows the manager to cross-bind to other components, or the Engine
func (ptm *publicTxMgr) PostInit(components.AllComponents) error {
	return nil
}

func (ptm *publicTxMgr) Start() (err error) {
	ptm.stopChan, err = ptm.publicTxEngine.Start(ptm.rootCtx)
	return
}
func (ptm *publicTxMgr) Stop() {
	ptm.rootCtxCancel()
	<-ptm.stopChan
}

func (ptm *publicTxMgr) GetEngine() components.PublicTxEngine {
	return ptm.publicTxEngine
}
