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
	"net/http"
	"time"

	"github.com/hyperledger/firefly-common/pkg/i18n"
	"github.com/kaleido-io/paladin/core/internal/msgs"
	"github.com/kaleido-io/paladin/toolkit/pkg/log"
	"github.com/kaleido-io/paladin/toolkit/pkg/ptxapi"
)

type APIRequestType int

const (
	ActionSuspend APIRequestType = iota
	ActionResume
)

func (pte *pubTxManager) persistSuspendedFlag(ctx context.Context, txID *ptxapi.PublicTxID, suspended bool) error {
	log.L(ctx).Infof("Setting suspend status to '%t' for transaction %s:%d", suspended, txID.Transaction, txID.ResubmitIndex)
	return pte.p.DB().
		WithContext(ctx).
		UpdateColumn("suspended", suspended).
		Where("transaction = ?", txID.Transaction).
		Where("resubmit_idx = ?", txID.ResubmitIndex).
		Error
}

func (pte *pubTxManager) dispatchAction(ctx context.Context, tx *ptxapi.PublicTx, action APIRequestType) error {
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
			inFlightOrchestrator, orchestratorInFlight := pte.InFlightOrchestrators[tx.From]
			if !orchestratorInFlight {
				// no in-flight orchestrator for the signing address, it's OK to update the DB directly
				response <- pte.persistSuspendedFlag(ctx, &tx.PublicTxID, suspended)
			} else {
				inFlightOrchestrator.dispatchAction(ctx, tx, action, response)
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

func (oc *orchestrator) dispatchAction(ctx context.Context, mtx *ptxapi.PublicTx, action APIRequestType, response chan<- error) {
	switch action {
	case ActionSuspend, ActionResume:
		oc.InFlightTxsMux.Lock()
		defer oc.InFlightTxsMux.Unlock()
		var pending *InFlightTransactionStageController
		for _, inflight := range oc.InFlightTxs {
			if inflight.stateManager.GetTxID() == mtx.ID {
				pending = inflight
				break
			}
		}
		newStatus := PubTxStatusPending
		if action == ActionSuspend {
			newStatus = PubTxStatusSuspended
		}
		if pending == nil {
			// transaction not in flight yet, update the DB directly and tell the engine to not pick up the transaction until we completed
			oc.transactionIDsInStatusUpdate = append(oc.transactionIDsInStatusUpdate, mtx.ID.String())
			go func() {
				defer func() {
					oc.InFlightTxsMux.Lock()
					defer oc.InFlightTxsMux.Unlock()
					newTransactionIDsInStatusUpdate := make([]string, 0, len(oc.transactionIDsInStatusUpdate)-1)
					for _, txID := range oc.transactionIDsInStatusUpdate {
						if txID != mtx.ID.String() {
							newTransactionIDsInStatusUpdate = append(newTransactionIDsInStatusUpdate, txID)
						}
					}
					oc.transactionIDsInStatusUpdate = newTransactionIDsInStatusUpdate
				}()
				log.L(ctx).Debugf("Setting status to '%s' for transaction %s", newStatus, mtx.ID)
				err := oc.txStore.UpdateTransaction(ctx, mtx.ID.String(), &BaseTXUpdates{
					Status: &newStatus,
				})
				if err != nil {
					response <- APIResponse{err: err}
					return
				}
				mtx.Status = newStatus
				response <- APIResponse{tx: mtx, status: http.StatusOK}
			}()
		} else {
			asyncUpdateRequired, err := pending.NotifyStatusUpdate(ctx, &newStatus)
			if err != nil {
				response <- APIResponse{err: err}
				return
			}
			if asyncUpdateRequired {
				response <- APIResponse{tx: mtx, status: http.StatusAccepted}
				return
			}
			response <- APIResponse{tx: mtx, status: http.StatusOK}
		}

	}

}
