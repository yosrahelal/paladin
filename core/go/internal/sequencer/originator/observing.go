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
	o.heartbeatIntervalsSinceLastReceive = 0

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

	// Only process dispatch state updates from the active coordinator.
	if event.From != o.activeCoordinatorNode {
		log.L(ctx).Debugf("ignoring non-active coordinator heartbeat from %s (active: %s)", event.From, o.activeCoordinatorNode)
		return nil
	}

	// TODO AM A: this is for dropped transaction tracking-  need to think about this more
	o.latestCoordinatorSnapshot = event.CoordinatorSnapshot

	for _, dispatchedTransaction := range event.CoordinatorSnapshot.DispatchedTransactions {
		//if any of the dispatched transactions were sent by this originator, ensure that we have an up to date view of its state
		if dispatchedTransaction.Originator == o.nodeName {
			txn := o.transactionsByID[dispatchedTransaction.ID]
			if txn == nil {
				//unexpected situation to be in.  We trust our memory of transactions over the coordinator's, so we ignore this transaction
				log.L(ctx).Warnf("received heartbeat from %s with dispatched transaction %s but no transaction found in memory", o.activeCoordinatorNode, dispatchedTransaction.ID)
				continue
			}
			if dispatchedTransaction.LatestSubmissionHash != nil {
				//if the dispatched transaction has a hash, then we can update our view of the transaction
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
				//if the dispatched transaction has a nonce but no hash, then it is sequenced
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
	}

	// Note: sending dropped transaction re-delegations (i.e. those we are tracking but which the heartbeat doesn't mention)
	// is handled by state machine guards

	return nil
}

func guard_IdleThresholdExceeded(_ context.Context, o *originator) bool {
	return o.heartbeatIntervalsSinceLastReceive >= o.idleThreshold
}

func action_IncrementHeartbeatIntervalCounts(_ context.Context, o *originator, _ common.Event) error {
	o.heartbeatIntervalsSinceLastReceive++
	return nil
}
