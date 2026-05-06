/*
 * Copyright © 2025 Kaleido, Inc.
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

package originator

import (
	"context"
	"fmt"

	"github.com/LFDT-Paladin/paladin/common/go/pkg/i18n"
	"github.com/LFDT-Paladin/paladin/common/go/pkg/log"
	"github.com/LFDT-Paladin/paladin/core/internal/msgs"
	"github.com/LFDT-Paladin/paladin/core/internal/sequencer/common"
	"github.com/LFDT-Paladin/paladin/core/internal/sequencer/originator/transaction"
)

func action_HeartbeatReceived(ctx context.Context, o *originator, event common.Event) error {
	e := event.(*common.HeartbeatReceivedEvent)
	return o.applyHeartbeatReceived(ctx, e)
}

func (o *originator) applyHeartbeatReceived(ctx context.Context, event *common.HeartbeatReceivedEvent) error {
	// Reset at the start of each heartbeat: this function is the only place that sets needsRedelegate,
	// and sendDelegationRequest is the only place that clears it after acting on it.
	o.needsRedelegate = false

	// Process confirmed transactions (success or revert) from ALL coordinator heartbeats (any node).
	// We may hear of confirmations from a flushing or closing coordinator, and updating our state machine
	// to reflect as soon as possible will minimise duplicate submissions to the base ledger.
	// We should have been notified by a fire and forget message that a transaction has been confirmed, before
	// it is included in a heartbeat, so most the time this code should be redundant.
	for _, confirmedTransaction := range event.CoordinatorSnapshot.ConfirmedTransactions {
		if confirmedTransaction.Originator != o.nodeName {
			continue
		}
		txn := o.transactionsByID[confirmedTransaction.ID]
		if txn == nil {
			log.L(ctx).Debugf("received confirmed transaction %s in heartbeat from %s but no transaction found in memory", confirmedTransaction.ID, event.From)
			continue
		}
		if len(confirmedTransaction.RevertReason) > 0 {
			err := txn.HandleEvent(ctx, &transaction.ConfirmedRevertedEvent{
				BaseEvent:    transaction.BaseEvent{TransactionID: confirmedTransaction.ID},
				RevertReason: confirmedTransaction.RevertReason,
				WillRetry:    false,
			})
			if err != nil {
				msg := fmt.Errorf("error handling confirmed reverted event for transaction %s: %v", txn.GetID(), err)
				return i18n.NewError(ctx, msgs.MsgSequencerInternalError, msg)
			}
		} else {
			err := txn.HandleEvent(ctx, &transaction.ConfirmedSuccessEvent{
				BaseEvent: transaction.BaseEvent{TransactionID: confirmedTransaction.ID},
			})
			if err != nil {
				msg := fmt.Errorf("error handling confirmed success event for transaction %s: %v", txn.GetID(), err)
				return i18n.NewError(ctx, msgs.MsgSequencerInternalError, msg)
			}
		}
	}

	// Handle heartbeats from the previous coordinator while we are watching for its flush to complete.
	if event.From == o.previousActiveCoordinatorNode && o.watchingPreviousCoordinatorFlush {
		// Reset the liveness counter for as long as the previous coordinator keeps heartbeating (including
		// its first closing heartbeat, at which point we stop watching).
		o.heartbeatIntervalsSinceLastReceive = 0

		if event.CoordinatorSnapshot.IsCoordinatorClosing() {
			// First closing heartbeat from the previous coordinator: trigger a full redelegate to the new
			// active coordinator so it can include any transactions the previous coordinator dropped.
			log.L(ctx).Debugf("previous coordinator %s has entered closing state; triggering redelegate to %s", event.From, o.activeCoordinatorNode)
			o.watchingPreviousCoordinatorFlush = false
			o.needsRedelegate = true
		}
		// Whether closing or not, we are not interested in the previous coordinator's dispatch snapshot.
		return nil
	}

	// Only process dispatch state updates and dropped-transaction detection from the active coordinator.
	if event.From != o.activeCoordinatorNode {
		log.L(ctx).Debugf("ignoring non-active coordinator heartbeat from %s (active: %s)", event.From, o.activeCoordinatorNode)
		return nil
	}

	// Active coordinator heartbeat: reset the liveness counter.
	o.heartbeatIntervalsSinceLastReceive = 0

	// If we were still watching the previous coordinator flush but the new active
	// coordinator has already started heartbeating, we no longer need to wait.
	if o.watchingPreviousCoordinatorFlush {
		log.L(ctx).Debugf("active coordinator %s is heartbeating while watching previous coordinator flush; exiting watching phase", event.From)
		o.watchingPreviousCoordinatorFlush = false
		o.needsRedelegate = true
	}

	// Check for transactions that the active coordinator appears to have dropped (absent from its snapshot).
	// If any are found we redelegate everything so the coordinator can reassemble them.
	if o.hasDroppedTransactions(ctx, event.CoordinatorSnapshot) {
		o.needsRedelegate = true
	}

	for _, dispatchedTransaction := range event.CoordinatorSnapshot.DispatchedTransactions {
		// If any of the dispatched transactions were sent by this originator, ensure we have an up-to-date view.
		if dispatchedTransaction.Originator != o.nodeName {
			continue
		}
		txn := o.transactionsByID[dispatchedTransaction.ID]
		if txn == nil {
			// Unexpected: we trust our memory over the coordinator's snapshot; ignore this entry.
			log.L(ctx).Warnf("received heartbeat from %s with dispatched transaction %s but no transaction found in memory", o.activeCoordinatorNode, dispatchedTransaction.ID)
			continue
		}
		if dispatchedTransaction.LatestSubmissionHash != nil {
			txnSubmittedEvent := &transaction.SubmittedEvent{}
			txnSubmittedEvent.TransactionID = dispatchedTransaction.ID
			txnSubmittedEvent.SignerAddress = dispatchedTransaction.Signer
			txnSubmittedEvent.LatestSubmissionHash = *dispatchedTransaction.LatestSubmissionHash
			txnSubmittedEvent.Coordinator = event.From
			if dispatchedTransaction.Nonce != nil {
				txnSubmittedEvent.Nonce = *dispatchedTransaction.Nonce
			}
			err := txn.HandleEvent(ctx, txnSubmittedEvent)
			if err != nil {
				msg := fmt.Errorf("error handling transaction submitted event for transaction %s: %v", txn.GetID(), err)
				return i18n.NewError(ctx, msgs.MsgSequencerInternalError, msg)
			}
		} else if dispatchedTransaction.Nonce != nil {
			err := txn.HandleEvent(ctx, &transaction.NonceAssignedEvent{
				BaseEvent: transaction.BaseEvent{
					TransactionID: dispatchedTransaction.ID,
				},
				Nonce:       *dispatchedTransaction.Nonce,
				Coordinator: event.From,
			})
			if err != nil {
				msg := fmt.Errorf("error handling nonce assigned event for transaction %s: %v", txn.GetID(), err)
				return i18n.NewError(ctx, msgs.MsgSequencerInternalError, msg)
			}
		}
	}

	// Note: sending redelegate requests is handled by the state machine guard guard_NeedsRedelegate.
	return nil
}

// hasDroppedTransactions returns true if any non-final transaction is absent from the coordinator's snapshot,
// implying the coordinator has dropped it and we need to redelegate everything.
func (o *originator) hasDroppedTransactions(ctx context.Context, snapshot *common.CoordinatorSnapshot) bool {
	for _, txn := range o.getTransactionsNotInStates([]transaction.State{transaction.State_Final, transaction.State_Confirmed, transaction.State_Reverted}) {
		if !transactionFoundInSnapshot(snapshot, txn) {
			log.L(ctx).Debugf("transaction %s not found in latest coordinator snapshot, assuming dropped", txn.GetID())
			return true
		}
	}
	return false
}

func transactionFoundInSnapshot(snapshot *common.CoordinatorSnapshot, txn transaction.OriginatorTransaction) bool {
	for _, t := range snapshot.DispatchedTransactions {
		if t.ID == txn.GetID() {
			return true
		}
	}
	for _, t := range snapshot.PooledTransactions {
		if t.ID == txn.GetID() {
			return true
		}
	}
	for _, t := range snapshot.ConfirmedTransactions {
		if t.ID == txn.GetID() {
			return true
		}
	}
	return false
}


func action_IncrementHeartbeatIntervalCounts(_ context.Context, o *originator, _ common.Event) error {
	o.heartbeatIntervalsSinceLastReceive++
	return nil
}
