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

	"github.com/kaleido-io/paladin/core/internal/msgs"
	"github.com/kaleido-io/paladin/toolkit/pkg/i18n"
	"github.com/kaleido-io/paladin/toolkit/pkg/log"
	"github.com/kaleido-io/paladin/toolkit/pkg/pldapi"
	"github.com/kaleido-io/paladin/toolkit/pkg/tktypes"
)

type AsyncRequestType int

const (
	ActionSuspend AsyncRequestType = iota
	ActionResume
	ActionCompleted
)

func (pte *pubTxManager) persistSuspendedFlag(ctx context.Context, from tktypes.EthAddress, nonce uint64, suspended bool) error {
	log.L(ctx).Infof("Setting suspend status to '%t' for transaction %s:%d", suspended, from, nonce)
	return pte.p.DB().
		WithContext(ctx).
		Table("public_txns").
		Where(`"from" = ?`, from).
		Where("nonce = ?", nonce).
		UpdateColumn("suspended", suspended).
		Error
}

func (pte *pubTxManager) dispatchAction(ctx context.Context, from tktypes.EthAddress, nonce uint64, action AsyncRequestType) error {
	response := make(chan error, 1)
	startTime := time.Now()
	go func() {
		pte.inFlightOrchestratorMux.Lock()
		defer pte.inFlightOrchestratorMux.Unlock()
		inFlightOrchestrator, orchestratorInFlight := pte.inFlightOrchestrators[from]
		switch action {
		case ActionCompleted:
			// Only need to pass this on if there's an orchestrator in flight for this signing address
			if orchestratorInFlight {
				inFlightOrchestrator.dispatchAction(ctx, nonce, action, response)
			}
		case ActionSuspend, ActionResume:
			suspended := false
			if action == ActionSuspend {
				suspended = true
			}
			if !orchestratorInFlight {
				// no in-flight orchestrator for the signing address, it's OK to update the DB directly
				response <- pte.persistSuspendedFlag(ctx, from, nonce, suspended)
			} else {
				// has to be done in the context of the orchestrator
				inFlightOrchestrator.dispatchAction(ctx, nonce, action, response)
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

func (oc *orchestrator) dispatchAction(ctx context.Context, nonce uint64, action AsyncRequestType, response chan<- error) {
	oc.inFlightTxsMux.Lock()
	defer oc.inFlightTxsMux.Unlock()
	var pending *inFlightTransactionStageController
	for _, inflight := range oc.inFlightTxs {
		if inflight.stateManager.GetNonce() == nonce {
			pending = inflight
			break
		}
	}
	if pending != nil {
		switch action {
		case ActionCompleted:
			_, err := pending.NotifyStatusUpdate(ctx, InFlightStatusConfirmReceived)
			response <- err
		case ActionSuspend, ActionResume:
			var suspendedFlag bool
			if action == ActionSuspend {
				suspendedFlag = true
				_, _ = pending.NotifyStatusUpdate(ctx, InFlightStatusSuspending)
			} else {
				suspendedFlag = false
				_, _ = pending.NotifyStatusUpdate(ctx, InFlightStatusPending)
			}
			// Ok we've now got the lock that means we can write to the DB
			// No optimization of this write, as it's a user action from the side of normal processing
			response <- oc.persistSuspendedFlag(ctx, oc.signingAddress, nonce, suspendedFlag)
		}
		oc.MarkInFlightTxStale()
	}
}

// TODO AM: an update has to change both the transaction and the public transaction - persistedTransaction also has from, data, function
// TODO AM: can the update be made in here or does a function to call need to be passed through
// TODO AM: can the inflight controller modify the DB or is that another function that needs to be passed through?

func (pte *pubTxManager) dispatchUpdate(ctx context.Context, pubTXID uint64, from string, txu *pldapi.TransactionUpdate) error {
	response := make(chan error, 1)
	startTime := time.Now()
	go func() {
		pte.inFlightOrchestratorMux.Lock()
		defer pte.inFlightOrchestratorMux.Unlock()
		from := tktypes.MustEthAddress(from)
		inFlightOrchestrator, orchestratorInFlight := pte.inFlightOrchestrators[*from]
		if !orchestratorInFlight {
			// no in-flight orchestrator for the signing address, it's OK to update the DB directly
			// TODO AM: for an update though we need to ensure that the orchestrator does get scheduled asap after this
			// response <- pte.persistSuspendedFlag(ctx, from, nonce, suspended)
		} else {
			// has to be done in the context of the orchestrator
			inFlightOrchestrator.dispatchUpdate(ctx, pubTXID, txu, response)
		}
	}()

	select {
	case err := <-response:
		return err
	case <-ctx.Done():
		return i18n.NewError(ctx, msgs.MsgTransactionEngineRequestTimeout, time.Since(startTime).Seconds())
	}
}

func (oc *orchestrator) dispatchUpdate(ctx context.Context, pubTXID uint64, txu *pldapi.TransactionUpdate, response chan<- error) {
	oc.inFlightTxsMux.Lock()
	defer oc.inFlightTxsMux.Unlock()
	var pending *inFlightTransactionStageController
	for _, inflight := range oc.inFlightTxs {
		if inflight.stateManager.GetPubTxnID() == pubTXID {
			pending = inflight
			break
		}
	}
	if pending != nil {
		// TODO AM: implement the actual update here
		// get a lock on the inflight transaction - could this potentially block and cause a timeout?
		// update the DB
		// make any updates to the inflight transaction

		// needs to return on the response channel
		oc.MarkInFlightTxStale()
	} else {
		// make the update straight to the db
	}

}
