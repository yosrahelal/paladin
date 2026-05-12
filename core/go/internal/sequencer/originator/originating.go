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
	"github.com/LFDT-Paladin/paladin/core/internal/components"
	"github.com/LFDT-Paladin/paladin/core/internal/msgs"
	"github.com/LFDT-Paladin/paladin/core/internal/sequencer/common"
	"github.com/LFDT-Paladin/paladin/core/internal/sequencer/originator/transaction"
	"github.com/LFDT-Paladin/paladin/toolkit/pkg/prototk"
	"github.com/google/uuid"
)

func action_TransactionCreated(ctx context.Context, o *originator, event common.Event) error {
	e := event.(*TransactionCreatedEvent)
	return o.addToTransactions(ctx, e.Transaction, o.newOriginatorTransaction)
}

func (o *originator) newOriginatorTransaction(ctx context.Context, pt *components.PrivateTransaction) (transaction.OriginatorTransaction, error) {
	return transaction.NewTransaction(ctx, pt, o.transportWriter, o.queueEventInternal, o.engineIntegration, o.metrics)
}

func (o *originator) addToTransactions(
	ctx context.Context,
	txn *components.PrivateTransaction,
	createTransaction func(
		ctx context.Context,
		pt *components.PrivateTransaction) (transaction.OriginatorTransaction, error)) error {
	newTxn, err := createTransaction(ctx, txn)
	if err != nil {
		log.L(ctx).Errorf("error creating transaction: %v", err)
		return err
	}
	o.transactionsByID[txn.ID] = newTxn
	o.transactionsOrdered = append(o.transactionsOrdered, newTxn)
	createdEvent := &transaction.CreatedEvent{}
	createdEvent.TransactionID = txn.ID
	err = newTxn.HandleEvent(ctx, createdEvent)
	if err != nil {
		log.L(ctx).Errorf("error handling CreatedEvent for transaction %s: %v", txn.ID.String(), err)
		return err
	}
	return nil
}

func sendDelegationRequest(ctx context.Context, o *originator) error {
	// Sending a delegation request means we are no longer watching the previous coordinator flush —
	// we have decided to act regardless of whether we saw a closing heartbeat.
	o.watchingPreviousCoordinatorFlush = false
	// Consume the redelegate flag; it has been actioned by this delegation.
	o.needsRedelegate = false

	// Re-delegate all transactions. Every delegation request must include all transaction, sent in the order they were created
	// on the originating node.

	// Note: we could track assemble errors here (not reverts, but domain bugs that prevent successful assembly) and penalise
	// transactions who assemble at error time by putting them to the back of the list. The coordinator already gives a limited
	// number of retries in such scenarios so the current worst case is a slightly delay before we give up on the failing TX anyway
	// so for now we just re-delegate all transactions in their original order.

	// Update internal TX state machines before sending delegation requests to avoid race condition
	transactionsToDelegate := make([]*components.PrivateTransaction, 0)
	for _, txn := range o.transactionsOrdered {
		transactionsToDelegate = append(transactionsToDelegate, txn.GetPrivateTransaction())
		err := txn.HandleEvent(ctx, &transaction.DelegatedEvent{
			BaseEvent: transaction.BaseEvent{
				TransactionID: txn.GetID(),
			},
			Coordinator: o.currentActiveCoordinator,
		})
		if err != nil {
			msg := fmt.Errorf("error handling delegated event for transaction %s: %v", txn.GetID(), err)
			return i18n.NewError(ctx, msgs.MsgSequencerInternalError, msg)
		}
	}

	log.L(ctx).Debugf("sending delegation request for %d transactions", len(o.transactionsOrdered))

	// Don't send delegation request before internal TX state machine has been updated
	return o.transportWriter.SendDelegationRequest(ctx, o.currentActiveCoordinator, transactionsToDelegate, o.currentBlockHeight)
}

func action_SendDelegationRequest(ctx context.Context, o *originator, _ common.Event) error {
	return sendDelegationRequest(ctx, o)
}

func guard_NeedsRedelegate(_ context.Context, o *originator) bool {
	return o.needsRedelegate
}

func guard_WatchingPreviousCoordinatorFlush(_ context.Context, o *originator) bool {
	return o.watchingPreviousCoordinatorFlush
}

func guard_InactiveGracePeriodExceeded(_ context.Context, o *originator) bool {
	return o.heartbeatIntervalsSinceLastReceive >= o.inactiveGracePeriod
}

func guard_PreferredAndCurrentDiffer(_ context.Context, o *originator) bool {
	return o.preferredActiveCoordinator != o.currentActiveCoordinator
}

func validator_IsHeartbeatFromCurrentActiveCoordinator(_ context.Context, o *originator, event common.Event) (bool, error) {
	e := event.(*common.HeartbeatReceivedEvent)
	return o.currentActiveCoordinator == e.From, nil
}

func validator_IsHeartbeatFromPreferredActiveCoordinator(_ context.Context, o *originator, event common.Event) (bool, error) {
	e := event.(*common.HeartbeatReceivedEvent)
	return o.preferredActiveCoordinator == e.From && e.CoordinatorSnapshot.CoordinatorState == common.CoordinatorState_Active, nil
}

func action_ResetHeartbeatIntervalsSinceLastReceive(_ context.Context, o *originator, _ common.Event) error {
	o.heartbeatIntervalsSinceLastReceive = 0
	return nil
}

func action_ResetCurrentToPreferred(ctx context.Context, o *originator, _ common.Event) error {
	log.L(ctx).Debugf("preferred coordinator %s is active again; realigning current from %s", o.preferredActiveCoordinator, o.currentActiveCoordinator)
	o.currentActiveCoordinator = o.preferredActiveCoordinator
	o.failoverOffset = 0
	o.heartbeatIntervalsSinceLastReceive = 0
	return nil
}

// action_IncrementFailoverOffset advances the endorser ring step. No-op in STATIC/SENDER modes.
func action_IncrementFailoverOffset(ctx context.Context, o *originator, _ common.Event) error {
	if o.domainAPI.ContractConfig().GetCoordinatorSelection() != prototk.ContractConfig_COORDINATOR_ENDORSER {
		return nil
	}
	log.L(ctx).Debugf("Current active coordinator %s is unavailable: incrementing failover offset from %d to %d", o.currentActiveCoordinator, o.failoverOffset, o.failoverOffset+1)
	o.failoverOffset++
	return nil
}

// Validate that the transaction doesn't already exist. When we resume transactions from the DB, e.g. after a restart or a timeout, we may already be processing
// the transaction and possibly taking a long time to complete them so we shouldn't restart the state machine from scratch for such in-progress transactions
func validator_TransactionDoesNotExist(ctx context.Context, o *originator, event common.Event) (bool, error) {
	transactionCreatedEvent, ok := event.(*TransactionCreatedEvent)
	if !ok {
		log.L(ctx).Errorf("expected event type *TransactionCreatedEvent, got %T", event)
		return false, nil
	}
	if transactionCreatedEvent.Transaction == nil {
		// If transaction is nil, let createTransaction handle the error
		return true, nil
	}
	if o.transactionsByID[transactionCreatedEvent.Transaction.ID] != nil {
		log.L(ctx).Debugf("transaction %s already in progress, not resuming", transactionCreatedEvent.Transaction.ID.String())
		return false, nil
	}

	return true, nil
}

func validator_OriginatorTransactionStateTransitionToFinal(ctx context.Context, _ *originator, event common.Event) (bool, error) {
	e := event.(*common.TransactionStateTransitionEvent[transaction.State])
	return e.To == transaction.State_Final, nil
}

func action_CleanUpTransaction(ctx context.Context, o *originator, event common.Event) error {
	e := event.(*common.TransactionStateTransitionEvent[transaction.State])
	o.removeTransaction(ctx, e.TransactionID)
	return nil
}

func validator_OriginatorTransactionStateTransitionToConfirmed(ctx context.Context, _ *originator, event common.Event) (bool, error) {
	e := event.(*common.TransactionStateTransitionEvent[transaction.State])
	return e.To == transaction.State_Confirmed, nil
}

func validator_OriginatorTransactionStateTransitionToReverted(ctx context.Context, _ *originator, event common.Event) (bool, error) {
	e := event.(*common.TransactionStateTransitionEvent[transaction.State])
	return e.To == transaction.State_Reverted, nil
}

func action_FinalizeTransaction(ctx context.Context, o *originator, event common.Event) error {
	e := event.(*common.TransactionStateTransitionEvent[transaction.State])
	o.queueEventInternal(ctx, &transaction.FinalizeEvent{
		BaseEvent:     common.BaseEvent{EventTime: e.GetEventTime()},
		TransactionID: e.TransactionID,
	})
	return nil
}

func (o *originator) removeTransaction(ctx context.Context, txnID uuid.UUID) {
	log.L(ctx).Debugf("removing transaction %s from originator", txnID.String())

	// Remove from transactionsByID
	delete(o.transactionsByID, txnID)

	// Remove from transactionsOrdered
	for i, txn := range o.transactionsOrdered {
		if txn.GetID() == txnID {
			o.transactionsOrdered = append(o.transactionsOrdered[:i], o.transactionsOrdered[i+1:]...)
			break
		}
	}
}

func action_UpdateBlockHeight(_ context.Context, o *originator, event common.Event) error {
	o.currentBlockHeight, o.newBlockRangeEpoch = common.DecodeNewBlockHeight(o.currentBlockHeight, o.blockRangeSize, event)
	o.needsFailoverOffsetReset = o.newBlockRangeEpoch
	return nil
}

func guard_IsNewBlockRangeEpoch(_ context.Context, o *originator) bool {
	return o.newBlockRangeEpoch
}

func action_SelectActiveCoordinator(ctx context.Context, o *originator, _ common.Event) error {
	if o.domainAPI.ContractConfig().GetCoordinatorSelection() != prototk.ContractConfig_COORDINATOR_ENDORSER {
		// For STATIC and SENDER modes, preferred/current coordinator are set once at construction time and never change.
		return nil
	}
	if o.needsFailoverOffsetReset || o.preferredActiveCoordinator == "" {
		o.failoverOffset = 0
	}
	o.previousActiveCoordinatorNode = o.currentActiveCoordinator
	o.preferredActiveCoordinator, o.currentActiveCoordinator = common.SelectCoordinatorNode(
		ctx,
		o.coordinatorEndorserPool,
		o.currentBlockHeight,
		o.blockRangeSize,
		o.failoverOffset,
	)
	if o.currentActiveCoordinator != o.previousActiveCoordinatorNode {
		o.heartbeatIntervalsSinceLastReceive = 0
		// When the coordinator changed due to inactivity failover (failoverOffset > 0, not an epoch reset),
		// notify the coordinator so it can update its own currentActiveCoordinator and set a flag to redelegate
		if o.failoverOffset > 0 {
			o.needsRedelegate = true
			o.queueActiveCoordinatorUnavailable(ctx, o.currentActiveCoordinator)
		}
	}
	o.needsFailoverOffsetReset = false
	// If the coordinator has changed because of new block-range epoch, start watching for the previous coordinator's closing heartbeat.
	// If we've selected a new coordinator because of inactivity, there will be no closing heartbeat to look for.
	if o.newBlockRangeEpoch && o.currentActiveCoordinator != o.previousActiveCoordinatorNode && o.previousActiveCoordinatorNode != "" {
		o.watchingPreviousCoordinatorFlush = true
	}
	return nil
}
