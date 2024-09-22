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
	"time"

	"github.com/hyperledger/firefly-common/pkg/i18n"
	"github.com/kaleido-io/paladin/core/internal/msgs"
	"github.com/kaleido-io/paladin/toolkit/pkg/log"
)

type APIRequestType int

const (
	ActionSuspend APIRequestType = iota
	ActionResume
)

func (pte *pubTxManager) persistSuspendedFlag(ctx context.Context, ptx *persistedPubTx, suspended bool) error {
	log.L(ctx).Infof("Setting suspend status to '%t' for transaction %s:%d", suspended, ptx.Transaction, ptx.ResubmitIndex)
	return pte.p.DB().
		WithContext(ctx).
		UpdateColumn("suspended", suspended).
		Where("transaction = ?", ptx.Transaction).
		Where("resubmit_idx = ?", ptx.ResubmitIndex).
		Error
}

func (pte *pubTxManager) dispatchAction(ctx context.Context, ptx *persistedPubTx, action APIRequestType) error {
	response := make(chan error, 1)
	startTime := time.Now()
	go func() {
		pte.InFlightOrchestratorMux.Lock()
		defer pte.InFlightOrchestratorMux.Unlock()
		switch action {
		case ActionSuspend, ActionResume:
			suspended := false
			if action == ActionSuspend {
				suspended = true
			}
			// Just update the DB directly, as we're not inflight right now.
			inFlightOrchestrator, orchestratorInFlight := pte.InFlightOrchestrators[ptx.From]
			if !orchestratorInFlight {
				// no in-flight orchestrator for the signing address, it's OK to update the DB directly
				response <- pte.persistSuspendedFlag(ctx, ptx, suspended)
			} else {
				// has to be done in the context of the orchestrator
				inFlightOrchestrator.dispatchAction(ctx, ptx, action, response)
			}
		}
	}()

	select {
	case err := <-response:
		return err
	case <-ctx.Done():
		return i18n.NewError(ctx, msgs.MsgTransactionEngineRequestTimeout, time.Since(startTime).Seconds())
	}
}

func (oc *orchestrator) dispatchAction(ctx context.Context, ptx *persistedPubTx, action APIRequestType, response chan<- error) {
	switch action {
	case ActionSuspend, ActionResume:
		oc.InFlightTxsMux.Lock()
		defer oc.InFlightTxsMux.Unlock()
		var pending *InFlightTransactionStageController
		for _, inflight := range oc.InFlightTxs {
			if inflight.stateManager.GetTxID() == ptx.getIDString() {
				pending = inflight
				break
			}
		}
		if pending != nil {
			switch action {
			case ActionSuspend, ActionResume:
				pending.pauseRequested = false
				if action == ActionSuspend {
					pending.pauseRequested = false
				}
				// Ok we've now got the lock that means we can write to the DB
				response <- oc.persistSuspendedFlag(ctx, ptx, pending.pauseRequested)
			}
		}
	}
}
