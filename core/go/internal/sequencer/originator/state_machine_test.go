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
	"testing"

	"github.com/LFDT-Paladin/paladin/core/internal/components"
	"github.com/LFDT-Paladin/paladin/core/internal/sequencer/common"
	"github.com/LFDT-Paladin/paladin/core/internal/sequencer/originator/transaction"
	"github.com/LFDT-Paladin/paladin/core/internal/sequencer/testutil"
	"github.com/LFDT-Paladin/paladin/core/mocks/originatortransactionmocks"
	"github.com/LFDT-Paladin/paladin/toolkit/pkg/prototk"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// ── Initial / Idle state transitions ─────────────────────────────────────────

func TestStateMachine_InitializeOK(t *testing.T) {
	o, _ := NewOriginatorBuilderForTesting(t, State_Idle).Build()
	assert.Equal(t, State_Idle, o.GetCurrentState(), "current state is %s", o.GetCurrentState().String())
}

// Firing OriginatorCreatedEvent from State_Initial transitions to State_Idle;
// action_SelectActiveCoordinator runs and seeds preferredActiveCoordinator from the pool.
func TestStateMachine_WhenCreated_TransitionsToIdle(t *testing.T) {
	ctx := context.Background()
	o, _ := NewOriginatorBuilderForTesting(t, State_Initial).
		DomainContractConfig(&prototk.ContractConfig{
			CoordinatorSelection: prototk.ContractConfig_COORDINATOR_ENDORSER,
		}).
		CoordinatorEndorserPool("node1", "node2").
		Build()
	require.NoError(t, o.stateMachineEventLoop.ProcessEvent(ctx, &OriginatorCreatedEvent{}))
	assert.Equal(t, State_Idle, o.GetCurrentState())
	assert.NotEmpty(t, o.preferredActiveCoordinator, "action_SelectActiveCoordinator must seed preferredActiveCoordinator from pool")
	assert.NotEmpty(t, o.currentActiveCoordinator, "action_SelectActiveCoordinator must seed currentActiveCoordinator from pool")
	assert.Equal(t, o.currentActiveCoordinator, o.preferredActiveCoordinator, "action_SelectActiveCoordinator must set currentActiveCoordinator to preferredActiveCoordinator")
}

func TestStateMachine_Idle_ToObserving_OnHeartbeatReceivedFromCurrentActiveCoordinator(t *testing.T) {
	ctx := context.Background()
	builder := NewOriginatorBuilderForTesting(t, State_Idle).
		CurrentActiveCoordinator("node2").
		NodeName("node1")
	o, _ := builder.Build()
	assert.Equal(t, State_Idle, o.GetCurrentState())
	ca := builder.GetContractAddress()
	heartbeatEvent := &common.HeartbeatReceivedEvent{
		From:            "node2",
		ContractAddress: &ca,
		CoordinatorSnapshot: &common.CoordinatorSnapshot{
			CoordinatorState: common.CoordinatorState_Active,
		},
	}
	heartbeatEvent.CoordinatorSnapshot = &common.CoordinatorSnapshot{}
	require.NoError(t, o.stateMachineEventLoop.ProcessEvent(ctx, heartbeatEvent))
	assert.Equal(t, State_Observing, o.GetCurrentState())
	assert.Equal(t, 0, o.heartbeatIntervalsSinceLastReceive)
}

func TestStateMachine_Idle_ToObserving_OnHeartbeatReceivedFromPreferredActiveCoordinator_RealignsCurrentAndTransitions(t *testing.T) {
	ctx := context.Background()
	builder := NewOriginatorBuilderForTesting(t, State_Idle).
		PreferredActiveCoordinator("node1").
		CurrentActiveCoordinator("node2").
		FailoverOffset(1).
		NodeName("node2")
	o, _ := builder.Build()
	ca := builder.GetContractAddress()
	heartbeatEvent := &common.HeartbeatReceivedEvent{
		From:                "node1",
		ContractAddress:     &ca,
		CoordinatorSnapshot: &common.CoordinatorSnapshot{CoordinatorState: common.CoordinatorState_Active},
	}
	require.NoError(t, o.stateMachineEventLoop.ProcessEvent(ctx, heartbeatEvent))
	assert.Equal(t, State_Observing, o.GetCurrentState())
	assert.Equal(t, "node1", o.currentActiveCoordinator)
	assert.Equal(t, 0, o.failoverOffset)
}

func TestStateMachine_Idle_StaysIdle_OnHeartbeatReceivedFromUnrelatedNode(t *testing.T) {
	ctx := context.Background()
	builder := NewOriginatorBuilderForTesting(t, State_Idle).
		PreferredActiveCoordinator("node2").
		CurrentActiveCoordinator("node2").
		NodeName("node1")
	o, _ := builder.Build()
	ca := builder.GetContractAddress()
	heartbeatEvent := &common.HeartbeatReceivedEvent{
		From:                "node3",
		ContractAddress:     &ca,
		CoordinatorSnapshot: &common.CoordinatorSnapshot{CoordinatorState: common.CoordinatorState_Active},
	}
	require.NoError(t, o.stateMachineEventLoop.ProcessEvent(ctx, heartbeatEvent))
	assert.Equal(t, State_Idle, o.GetCurrentState())
	assert.Equal(t, "node2", o.currentActiveCoordinator)
}

func TestStateMachine_Idle_ToSending_OnTransactionCreated(t *testing.T) {
	ctx := context.Background()
	builder := NewOriginatorBuilderForTesting(t, State_Idle).
		WithMockTransportWriter(t)
	o, mocks := builder.Build()
	assert.Equal(t, State_Idle, o.GetCurrentState())
	mocks.TransportWriter.EXPECT().
		SendDelegationRequest(mock.Anything, "coordinator", mock.Anything, mock.Anything).
		Return(nil).Once()
	txn := testutil.NewPrivateTransactionBuilderForTesting().Address(builder.GetContractAddress()).Originator("sender@node1").Build()
	require.NoError(t, o.stateMachineEventLoop.ProcessEvent(ctx, &TransactionCreatedEvent{Transaction: txn}))
	assert.Equal(t, State_Sending, o.GetCurrentState(), "current state is %s", o.GetCurrentState().String())
}

// A new block that crosses a block-range epoch boundary in Idle refreshes coordinator selection
// but keeps the originator in Idle (no transactions to send).
func TestStateMachine_WhenIdle_NewEpoch_RefreshesCoordinatorSelectionStaysIdle(t *testing.T) {
	ctx := context.Background()
	blockRange := uint64(50)

	o, _ := NewOriginatorBuilderForTesting(t, State_Idle).
		DomainContractConfig(&prototk.ContractConfig{
			CoordinatorSelection: prototk.ContractConfig_COORDINATOR_ENDORSER,
		}).
		CoordinatorEndorserPool("node1", "node2", "node3").
		BlockRangeSize(blockRange).
		CurrentBlockHeight(100).
		CurrentActiveCoordinator("node1").
		Build()
	require.NoError(t, o.stateMachineEventLoop.ProcessEvent(ctx, &common.NewBlockEvent{BlockHeight: 150}))
	assert.Equal(t, State_Idle, o.GetCurrentState())
	assert.Equal(t, "node2", o.preferredActiveCoordinator, "coordinator selection should refresh on epoch boundary")
}

// ── Observing state transitions ───────────────────────────────────────────────

func TestStateMachine_Observing_ToSending_OnTransactionCreated(t *testing.T) {
	ctx := context.Background()
	builder := NewOriginatorBuilderForTesting(t, State_Observing).
		WithMockTransportWriter(t)
	o, mocks := builder.Build()
	mocks.TransportWriter.EXPECT().
		SendDelegationRequest(mock.Anything, "coordinator", mock.Anything, mock.Anything).
		Return(nil).Once()
	txn := testutil.NewPrivateTransactionBuilderForTesting().Address(builder.GetContractAddress()).Originator("sender@node1").Build()
	require.NoError(t, o.stateMachineEventLoop.ProcessEvent(ctx, &TransactionCreatedEvent{Transaction: txn}))
	assert.Equal(t, State_Sending, o.GetCurrentState(), "current state is %s", o.GetCurrentState().String())
}

// HeartbeatInterval exceeding the inactive grace period transitions Observing → Idle.
func TestStateMachine_Observing_TransitionsToIdle_OnHeartbeatIntervalInactiveGrace(t *testing.T) {
	ctx := context.Background()
	o, _ := NewOriginatorBuilderForTesting(t, State_Observing).
		HeartbeatIntervalsSinceLastReceive(0).
		InactiveGracePeriod(1).
		Build()
	require.NoError(t, o.stateMachineEventLoop.ProcessEvent(ctx, &common.HeartbeatIntervalEvent{}))
	assert.Equal(t, State_Idle, o.GetCurrentState())
	assert.Equal(t, 1, o.heartbeatIntervalsSinceLastReceive, "counter incremented before transition check")
}

// ── Sending state transitions ─────────────────────────────────────────────────

func TestStateMachine_Sending_NoTransition_OnTransactionConfirmed_IfHasTransactionsInflight(t *testing.T) {
	ctx := context.Background()
	txn1ID := uuid.New()
	txn2ID := uuid.New()
	mockTxn1 := originatortransactionmocks.NewOriginatorTransaction(t)
	mockTxn1.On("GetID").Return(txn1ID)
	mockTxn1.On("HandleEvent", mock.Anything, mock.Anything).Return(nil)
	mockTxn2 := originatortransactionmocks.NewOriginatorTransaction(t)
	mockTxn2.On("GetID").Return(txn2ID)
	o, _ := NewOriginatorBuilderForTesting(t, State_Sending).
		Transactions(mockTxn1, mockTxn2).
		Build()
	require.NoError(t, o.stateMachineEventLoop.ProcessEvent(ctx, &transaction.ConfirmedSuccessEvent{
		BaseEvent: transaction.BaseEvent{TransactionID: txn1ID},
	}))
	assert.Equal(t, State_Sending, o.GetCurrentState(), "current state is %s", o.GetCurrentState().String())
	// txn2 is still unconfirmed; both transactions must remain in the map
	assert.Len(t, o.transactionsByID, 2, "both transactions must remain tracked while one is still unconfirmed")
}

func TestStateMachine_Sending_DoDelegateTransactions_OnHeartbeatReceived_IfHasDroppedTransaction(t *testing.T) {
	ctx := context.Background()
	coordinatorLocator := "node1"
	txn1ID := uuid.New()
	txn2ID := uuid.New()
	mockTxn1 := originatortransactionmocks.NewOriginatorTransaction(t)
	mockTxn1.On("GetID").Return(txn1ID)
	mockTxn1.On("GetCurrentState").Return(transaction.State_Delegated)
	mockTxn1.On("GetPrivateTransaction").Return(&components.PrivateTransaction{ID: txn1ID})
	mockTxn1.On("HandleEvent", mock.Anything, mock.Anything).Return(nil)
	mockTxn2 := originatortransactionmocks.NewOriginatorTransaction(t)
	mockTxn2.On("GetID").Return(txn2ID)
	mockTxn2.On("GetCurrentState").Return(transaction.State_Delegated)
	mockTxn2.On("GetPrivateTransaction").Return(&components.PrivateTransaction{ID: txn2ID})
	mockTxn2.On("HandleEvent", mock.Anything, mock.Anything).Return(nil)
	builder := NewOriginatorBuilderForTesting(t, State_Sending).
		CurrentActiveCoordinator(coordinatorLocator).
		WithMockTransportWriter(t).
		Transactions(mockTxn1, mockTxn2)
	o, mocks := builder.Build()
	mocks.TransportWriter.EXPECT().
		SendDelegationRequest(mock.Anything, coordinatorLocator, mock.Anything, mock.Anything).
		Return(nil).Once()
	// Send heartbeat with only txn1 in the snapshot — txn2 is "dropped"
	ca := builder.GetContractAddress()
	heartbeatEvent := &common.HeartbeatReceivedEvent{
		From:            coordinatorLocator,
		ContractAddress: &ca,
		CoordinatorSnapshot: &common.CoordinatorSnapshot{
			PooledTransactions: []*common.SnapshotPooledTransaction{
				{ID: txn1ID, Originator: "node1"},
			},
		},
	}
	require.NoError(t, o.stateMachineEventLoop.ProcessEvent(ctx, heartbeatEvent))
	assert.Equal(t, State_Sending, o.GetCurrentState())
}

func TestStateMachine_Sending_OnHeartbeatReceivedFromPreferredActiveCoordinator_RealignsAndRedelegates(t *testing.T) {
	ctx := context.Background()
	txID := uuid.New()
	mockTxn := originatortransactionmocks.NewOriginatorTransaction(t)
	mockTxn.On("GetID").Return(txID)
	mockTxn.On("GetCurrentState").Return(transaction.State_Delegated)
	mockTxn.On("GetPrivateTransaction").Return(&components.PrivateTransaction{ID: txID})
	mockTxn.On("HandleEvent", mock.Anything, mock.Anything).Return(nil)
	builder := NewOriginatorBuilderForTesting(t, State_Sending).
		PreferredActiveCoordinator("node1").
		CurrentActiveCoordinator("node2").
		FailoverOffset(1).
		NodeName("node3").
		WithMockTransportWriter(t).
		Transactions(mockTxn)
	o, mocks := builder.Build()
	ca := builder.GetContractAddress()
	// action_ResetCurrentToPreferred realigns current → preferred ("node1") before delegation fires.
	mocks.TransportWriter.EXPECT().
		SendDelegationRequest(mock.Anything, "node1", mock.Anything, mock.Anything).
		Return(nil).Once()
	// Preferred coordinator sends an Active heartbeat with an empty snapshot (our transactions are absent).
	heartbeatEvent := &common.HeartbeatReceivedEvent{
		From:            "node1",
		ContractAddress: &ca,
		CoordinatorSnapshot: &common.CoordinatorSnapshot{
			CoordinatorState: common.CoordinatorState_Active,
		},
	}
	require.NoError(t, o.stateMachineEventLoop.ProcessEvent(ctx, heartbeatEvent))
	assert.Equal(t, "node1", o.currentActiveCoordinator)
	assert.Equal(t, 0, o.failoverOffset)
}

// A new transaction created in Sending while not watching a flush immediately delegates.
func TestStateMachine_Sending_TransactionCreated_DelegatesImmediately_WhenNotWatching(t *testing.T) {
	ctx := context.Background()
	builder := NewOriginatorBuilderForTesting(t, State_Sending).
		WatchingPreviousCoordinatorFlush(false).
		WithMockTransportWriter(t)
	o, mocks := builder.Build()
	// Default currentActiveCoordinator is "coordinator" when none is explicitly set.
	mocks.TransportWriter.EXPECT().
		SendDelegationRequest(mock.Anything, "coordinator", mock.Anything, mock.Anything).
		Return(nil).Once()
	txn := testutil.NewPrivateTransactionBuilderForTesting().Address(builder.GetContractAddress()).Originator("sender@node1").Build()
	require.NoError(t, o.stateMachineEventLoop.ProcessEvent(ctx, &TransactionCreatedEvent{Transaction: txn}))
	assert.Equal(t, State_Sending, o.GetCurrentState())
}

// When the last transaction reaches State_Final in Sending, the originator transitions to Observing.
func TestStateMachine_Sending_TransitionsToObserving_WhenLastTransactionFinal(t *testing.T) {
	ctx := context.Background()
	txID := uuid.New()
	mockTxn := originatortransactionmocks.NewOriginatorTransaction(t)
	mockTxn.On("GetID").Return(txID)
	o, _ := NewOriginatorBuilderForTesting(t, State_Sending).
		Transactions(mockTxn).
		Build()
	// Fire a Final state-transition event directly — action_CleanUpTransaction removes the tx,
	// and with no remaining transactions GuardNot(guard_HasUnconfirmedTransactions) fires.
	require.NoError(t, o.stateMachineEventLoop.ProcessEvent(ctx, &common.TransactionStateTransitionEvent[transaction.State]{
		TransactionID: txID,
		From:          transaction.State_Delegated,
		To:            transaction.State_Final,
	}))
	assert.Equal(t, State_Observing, o.GetCurrentState())
	assert.Empty(t, o.transactionsByID, "transaction must be cleaned up")
}

// ── Epoch / coordinator selection ─────────────────────────────────────────────

// Crossing a block-range epoch in ENDORSER mode with a 3-node pool sets previousActiveCoordinatorNode
// and watchingPreviousCoordinatorFlush when the identity changes.  With a 1-node pool the identity
// cannot change, so watchingPreviousCoordinatorFlush stays false.
func TestOriginator_WhenNewEpochRuns_PreservesPreviousActiveAndRecomputesActiveWithWatchingFlushOnlyOnIdentityChange(t *testing.T) {
	ctx := context.Background()
	blockRange := uint64(50)

	// 3-node pool: coordinator changes → watchingPreviousCoordinatorFlush = true
	o, _ := NewOriginatorBuilderForTesting(t, State_Sending).
		DomainContractConfig(&prototk.ContractConfig{
			CoordinatorSelection: prototk.ContractConfig_COORDINATOR_ENDORSER,
		}).
		CoordinatorEndorserPool("node1", "node2", "node3").
		BlockRangeSize(blockRange).
		CurrentBlockHeight(100).
		CurrentActiveCoordinator("node1").
		PreviousActiveCoordinatorNode("node3").
		Build()
	require.NoError(t, o.stateMachineEventLoop.ProcessEvent(ctx, &common.NewBlockEvent{BlockHeight: 150}))
	assert.Equal(t, "node1", o.previousActiveCoordinatorNode)
	assert.True(t, o.watchingPreviousCoordinatorFlush, "must watch when coordinator identity changes at epoch boundary")

	// 1-node pool: coordinator stays the same → watchingPreviousCoordinatorFlush stays false
	o2, _ := NewOriginatorBuilderForTesting(t, State_Sending).
		DomainContractConfig(&prototk.ContractConfig{
			CoordinatorSelection: prototk.ContractConfig_COORDINATOR_ENDORSER,
		}).
		CoordinatorEndorserPool("node1").
		BlockRangeSize(blockRange).
		CurrentBlockHeight(100).
		CurrentActiveCoordinator("node1").
		PreviousActiveCoordinatorNode("node1").
		Build()
	require.NoError(t, o2.stateMachineEventLoop.ProcessEvent(ctx, &common.NewBlockEvent{BlockHeight: 150}))
	assert.False(t, o2.watchingPreviousCoordinatorFlush, "single-node pool: no identity change, no watching")
}

// ── watchingPreviousCoordinatorFlush suppression ──────────────────────────────

// Transitioning into Sending while watching and creating a new transaction both suppress delegation.
func TestOriginator_WhenWatchingPreviousFlush_DelegationSuppressedOnTransitionInAndOnNewTransaction(t *testing.T) {
	ctx := context.Background()
	builder := NewOriginatorBuilderForTesting(t, State_Observing).
		WatchingPreviousCoordinatorFlush(true)
	o, mocks := builder.Build()

	// First TransactionCreated: triggers Observing → Sending transition.
	// OnTransitionTo has action_SendDelegationRequest guarded by GuardNot(guard_WatchingPreviousCoordinatorFlush).
	txn1 := testutil.NewPrivateTransactionBuilderForTesting().Address(builder.GetContractAddress()).Originator("sender@node1").Build()
	require.NoError(t, o.stateMachineEventLoop.ProcessEvent(ctx, &TransactionCreatedEvent{Transaction: txn1}))
	assert.Equal(t, State_Sending, o.GetCurrentState())
	assert.False(t, mocks.SentMessageRecorder.HasSentDelegationRequest(), "watching: delegation must be suppressed on entry to Sending")

	// Second TransactionCreated in Sending: also guarded by GuardNot(guard_WatchingPreviousCoordinatorFlush).
	txn2 := testutil.NewPrivateTransactionBuilderForTesting().Address(builder.GetContractAddress()).Originator("sender@node1").Build()
	require.NoError(t, o.stateMachineEventLoop.ProcessEvent(ctx, &TransactionCreatedEvent{Transaction: txn2}))
	assert.False(t, mocks.SentMessageRecorder.HasSentDelegationRequest(), "watching: delegation must be suppressed for new transaction in Sending")
}

// A closing heartbeat from the previous coordinator exits watching and triggers a full redelegate.
func TestOriginator_WhenWatchingPreviousFlush_ExitsOnPreviousClosingHeartbeat(t *testing.T) {
	ctx := context.Background()
	builder := NewOriginatorBuilderForTesting(t, State_Sending).
		WatchingPreviousCoordinatorFlush(true).
		PreviousActiveCoordinatorNode("node2").
		CurrentActiveCoordinator("node1").
		PreferredActiveCoordinator("node1").
		WithMockTransportWriter(t)
	o, mocks := builder.Build()
	ca := builder.GetContractAddress()
	// Delegation fires to the current active coordinator ("node1") once watching is cleared.
	mocks.TransportWriter.EXPECT().
		SendDelegationRequest(mock.Anything, "node1", mock.Anything, mock.Anything).
		Return(nil).Once()
	require.NoError(t, o.stateMachineEventLoop.ProcessEvent(ctx, &common.HeartbeatReceivedEvent{
		From:            "node2",
		ContractAddress: &ca,
		CoordinatorSnapshot: &common.CoordinatorSnapshot{
			CoordinatorState: common.CoordinatorState_Closing,
		},
	}))
	assert.False(t, o.watchingPreviousCoordinatorFlush, "watching must be cleared on previous coordinator closing heartbeat")
}

// If the new active coordinator starts heartbeating before the previous has closed, watching exits.
func TestOriginator_WhenWatchingPreviousFlush_ExitsOnHeartbeatFromNewActiveWhileWatching(t *testing.T) {
	ctx := context.Background()
	builder := NewOriginatorBuilderForTesting(t, State_Sending).
		WatchingPreviousCoordinatorFlush(true).
		PreviousActiveCoordinatorNode("node2").
		CurrentActiveCoordinator("node1").
		PreferredActiveCoordinator("node1").
		WithMockTransportWriter(t)
	o, mocks := builder.Build()
	ca := builder.GetContractAddress()
	// Delegation fires to the new active coordinator ("node1") once watching is cleared.
	mocks.TransportWriter.EXPECT().
		SendDelegationRequest(mock.Anything, "node1", mock.Anything, mock.Anything).
		Return(nil).Once()
	require.NoError(t, o.stateMachineEventLoop.ProcessEvent(ctx, &common.HeartbeatReceivedEvent{
		From:                "node1",
		ContractAddress:     &ca,
		CoordinatorSnapshot: &common.CoordinatorSnapshot{},
	}))
	assert.False(t, o.watchingPreviousCoordinatorFlush, "new coordinator heartbeat while watching must clear the flag")
}

// The HeartbeatInterval inactive-grace path bypasses the watching guard and always delegates.
func TestOriginator_WhenWatchingPreviousFlush_ExitsOnHeartbeatIntervalInactivePathThatNudgesNewCoordinator(t *testing.T) {
	ctx := context.Background()
	builder := NewOriginatorBuilderForTesting(t, State_Sending).
		WatchingPreviousCoordinatorFlush(true).
		HeartbeatIntervalsSinceLastReceive(0).
		InactiveGracePeriod(1).
		CurrentActiveCoordinator("node1").
		PreferredActiveCoordinator("node1").
		WithMockTransportWriter(t)
	o, mocks := builder.Build()
	// Delegation fires to the current active coordinator ("node1"), bypassing the watching guard.
	mocks.TransportWriter.EXPECT().
		SendDelegationRequest(mock.Anything, "node1", mock.Anything, mock.Anything).
		Return(nil).Once()
	require.NoError(t, o.stateMachineEventLoop.ProcessEvent(ctx, &common.HeartbeatIntervalEvent{}))
	assert.False(t, o.watchingPreviousCoordinatorFlush, "inactive-grace path must clear watching flag as a side effect of sendDelegationRequest")
}

// ── Dropped-transaction detection ─────────────────────────────────────────────

// A non-final transaction absent from the coordinator's snapshot triggers needsRedelegate
// and a delegation request.
func TestOriginator_WhenSnapshotShowsMissingNonFinalTransaction_SetsNeedsRedelegate(t *testing.T) {
	ctx := context.Background()
	txID := uuid.New()
	mockTxn := originatortransactionmocks.NewOriginatorTransaction(t)
	mockTxn.On("GetID").Return(txID)
	mockTxn.On("GetCurrentState").Return(transaction.State_Delegated)
	mockTxn.On("GetPrivateTransaction").Return(&components.PrivateTransaction{ID: txID})
	mockTxn.On("HandleEvent", mock.Anything, mock.Anything).Return(nil)
	builder := NewOriginatorBuilderForTesting(t, State_Sending).
		CurrentActiveCoordinator("node1").
		WithMockTransportWriter(t).
		Transactions(mockTxn)
	o, mocks := builder.Build()
	ca := builder.GetContractAddress()
	// Dropped transaction must trigger redelegate to the current active coordinator ("node1").
	mocks.TransportWriter.EXPECT().
		SendDelegationRequest(mock.Anything, "node1", mock.Anything, mock.Anything).
		Return(nil).Once()
	// Send heartbeat with an empty snapshot — the delegated transaction is absent.
	require.NoError(t, o.stateMachineEventLoop.ProcessEvent(ctx, &common.HeartbeatReceivedEvent{
		From:                "node1",
		ContractAddress:     &ca,
		CoordinatorSnapshot: &common.CoordinatorSnapshot{},
	}))
}

// ── Failover-offset / coordinator-walk behaviour ──────────────────────────────

// In COORDINATOR_SENDER mode, action_IncrementFailoverOffset is a no-op — failoverOffset stays 0.
func TestOriginator_WhenCoordinatorSenderMode_DoesNotMutateFailoverOffset(t *testing.T) {
	ctx := context.Background()
	txID := uuid.New()
	mockTxn := originatortransactionmocks.NewOriginatorTransaction(t)
	mockTxn.On("GetID").Return(txID)
	mockTxn.On("GetPrivateTransaction").Return(&components.PrivateTransaction{ID: txID})
	mockTxn.On("HandleEvent", mock.Anything, mock.Anything).Return(nil)
	o, _ := NewOriginatorBuilderForTesting(t, State_Sending).
		// Default config is COORDINATOR_SENDER — no DomainContractConfig needed.
		HeartbeatIntervalsSinceLastReceive(0).
		InactiveGracePeriod(1).
		Transactions(mockTxn).
		Build()
	require.NoError(t, o.stateMachineEventLoop.ProcessEvent(ctx, &common.HeartbeatIntervalEvent{}))
	assert.Equal(t, 0, o.failoverOffset, "SENDER mode must not mutate failoverOffset")
}

// In COORDINATOR_ENDORSER mode, action_IncrementFailoverOffset advances the offset by one.
func TestOriginator_WhenCoordinatorEndorserMode_UsesCyclicWalkOnlyWhenConfigured(t *testing.T) {
	ctx := context.Background()
	txID := uuid.New()
	mockTxn := originatortransactionmocks.NewOriginatorTransaction(t)
	mockTxn.On("GetID").Return(txID)
	mockTxn.On("GetPrivateTransaction").Return(&components.PrivateTransaction{ID: txID})
	mockTxn.On("HandleEvent", mock.Anything, mock.Anything).Return(nil)
	o, _ := NewOriginatorBuilderForTesting(t, State_Sending).
		DomainContractConfig(&prototk.ContractConfig{
			CoordinatorSelection: prototk.ContractConfig_COORDINATOR_ENDORSER,
		}).
		CoordinatorEndorserPool("node1", "node2").
		BlockRangeSize(50).
		CurrentBlockHeight(100).
		HeartbeatIntervalsSinceLastReceive(0).
		InactiveGracePeriod(1).
		Transactions(mockTxn).
		Build()
	require.NoError(t, o.stateMachineEventLoop.ProcessEvent(ctx, &common.HeartbeatIntervalEvent{}))
	assert.Equal(t, 1, o.failoverOffset, "ENDORSER mode must increment failoverOffset when grace exceeded")
}

// Exceeding the inactive grace period in ENDORSER mode advances the offset, re-selects coordinator,
// and sends a delegation request to the new coordinator.
func TestOriginator_WhenHeartbeatFromCurrentStalePastInactive_AdvancedFailoverOffsetAndRedelegates(t *testing.T) {
	ctx := context.Background()
	blockRange := uint64(50)
	txID := uuid.New()
	mockTxn := originatortransactionmocks.NewOriginatorTransaction(t)
	mockTxn.On("GetID").Return(txID)
	mockTxn.On("GetPrivateTransaction").Return(&components.PrivateTransaction{ID: txID})
	mockTxn.On("HandleEvent", mock.Anything, mock.Anything).Return(nil)
	o, mocks := NewOriginatorBuilderForTesting(t, State_Sending).
		DomainContractConfig(&prototk.ContractConfig{
			CoordinatorSelection: prototk.ContractConfig_COORDINATOR_ENDORSER,
		}).
		CoordinatorEndorserPool("node1", "node2", "node3").
		BlockRangeSize(blockRange).
		CurrentBlockHeight(150).
		CurrentActiveCoordinator("node").
		HeartbeatIntervalsSinceLastReceive(0).
		InactiveGracePeriod(1).
		WithMockTransportWriter(t).
		Transactions(mockTxn).
		Build()
	// After failover offset increments, action_SelectActiveCoordinator re-picks from the pool.
	// The test already asserts o.currentActiveCoordinator == "node3"; delegation goes to that same node.
	mocks.TransportWriter.EXPECT().
		SendDelegationRequest(mock.Anything, "node3", mock.Anything, mock.Anything).
		Return(nil).Once()
	require.NoError(t, o.stateMachineEventLoop.ProcessEvent(ctx, &common.HeartbeatIntervalEvent{}))
	assert.Equal(t, 1, o.failoverOffset, "failoverOffset must advance by one on inactive grace exceeded")
	assert.Equal(t, "node3", o.currentActiveCoordinator, "coordinator must change when stepping to failover")
}

// Each HeartbeatInterval exceeding the grace period always advances the failover offset by one, stepping around the pool
func TestOriginator_WhenRepeatedCurrentCoordinatorFailures_AdvanceFailoverOffsetAroundPool(t *testing.T) {
	ctx := context.Background()
	blockRange := uint64(50)
	txID := uuid.New()
	mockTxn := originatortransactionmocks.NewOriginatorTransaction(t)
	mockTxn.On("GetID").Return(txID)
	mockTxn.On("GetPrivateTransaction").Return(&components.PrivateTransaction{ID: txID})
	mockTxn.On("HandleEvent", mock.Anything, mock.Anything).Return(nil)
	o, _ := NewOriginatorBuilderForTesting(t, State_Sending).
		DomainContractConfig(&prototk.ContractConfig{
			CoordinatorSelection: prototk.ContractConfig_COORDINATOR_ENDORSER,
		}).
		CoordinatorEndorserPool("node1", "node2", "node3").
		BlockRangeSize(blockRange).
		CurrentBlockHeight(150).
		CurrentActiveCoordinator("node2").
		PreferredActiveCoordinator("node2").
		HeartbeatIntervalsSinceLastReceive(0).
		InactiveGracePeriod(1).
		Transactions(mockTxn).
		Build()

	// First HeartbeatInterval: offset 0→1, counter resets to 0 (new coordinator selected).
	require.NoError(t, o.stateMachineEventLoop.ProcessEvent(ctx, &common.HeartbeatIntervalEvent{}))
	assert.Equal(t, 1, o.failoverOffset)
	assert.Equal(t, "node3", o.currentActiveCoordinator, "coordinator must change when stepping to failover")
	assert.Equal(t, "node2", o.preferredActiveCoordinator, "preferred coordinator must not change")
	// Reset counter to 0 so next interval also exceeds grace.
	o.heartbeatIntervalsSinceLastReceive = 0

	// Second HeartbeatInterval: offset 1→2.
	require.NoError(t, o.stateMachineEventLoop.ProcessEvent(ctx, &common.HeartbeatIntervalEvent{}))
	assert.Equal(t, 2, o.failoverOffset, "two consecutive inactive-grace intervals must advance offset to 2")
	assert.Equal(t, "node1", o.currentActiveCoordinator, "coordinator must change when stepping to failover")
	assert.Equal(t, "node2", o.preferredActiveCoordinator, "preferred coordinator must not change")
}

// A new block-range epoch resets failoverOffset to 0 even when currently on a fallback coordinator.
func TestOriginator_WhenNewEpochWhileOnFallback_ResetsFailoverOffsetToZero(t *testing.T) {
	ctx := context.Background()
	blockRange := uint64(50)
	o, _ := NewOriginatorBuilderForTesting(t, State_Sending).
		DomainContractConfig(&prototk.ContractConfig{
			CoordinatorSelection: prototk.ContractConfig_COORDINATOR_ENDORSER,
		}).
		CoordinatorEndorserPool("node1", "node2", "node3").
		BlockRangeSize(blockRange).
		CurrentBlockHeight(100).
		CurrentActiveCoordinator("node3").
		FailoverOffset(2).
		Build()
	require.NoError(t, o.stateMachineEventLoop.ProcessEvent(ctx, &common.NewBlockEvent{BlockHeight: 150}))
	assert.Equal(t, 0, o.failoverOffset, "epoch boundary must reset failoverOffset to 0")
}

// ── Preferred-coordinator recovery (fallback → preferred) ─────────────────────

// When on a fallback coordinator and the preferred sends an Active heartbeat,
// the originator realigns current to preferred and redelegates all inflight transactions.
func TestOriginator_WhenFallbackObservesPreferredActive_RedelegatesPerSpec(t *testing.T) {
	ctx := context.Background()
	txID := uuid.New()
	mockTxn := originatortransactionmocks.NewOriginatorTransaction(t)
	mockTxn.On("GetID").Return(txID)
	mockTxn.On("GetCurrentState").Return(transaction.State_Delegated)
	mockTxn.On("GetPrivateTransaction").Return(&components.PrivateTransaction{ID: txID})
	mockTxn.On("HandleEvent", mock.Anything, mock.Anything).Return(nil)
	builder := NewOriginatorBuilderForTesting(t, State_Sending).
		PreferredActiveCoordinator("node1").
		CurrentActiveCoordinator("node2").
		FailoverOffset(1).
		NodeName("node3").
		WithMockTransportWriter(t).
		Transactions(mockTxn)
	o, mocks := builder.Build()
	ca := builder.GetContractAddress()
	// After realignment current = "node1"; delegation must go to the preferred coordinator.
	mocks.TransportWriter.EXPECT().
		SendDelegationRequest(mock.Anything, "node1", mock.Anything, mock.Anything).
		Return(nil).Once()
	// Preferred sends Active heartbeat with an empty snapshot (our delegated tx is absent → dropped detection fires).
	require.NoError(t, o.stateMachineEventLoop.ProcessEvent(ctx, &common.HeartbeatReceivedEvent{
		From:            "node1",
		ContractAddress: &ca,
		CoordinatorSnapshot: &common.CoordinatorSnapshot{
			CoordinatorState: common.CoordinatorState_Active,
		},
	}))
	assert.Equal(t, "node1", o.currentActiveCoordinator, "current must realign to preferred")
	assert.Equal(t, 0, o.failoverOffset, "failoverOffset must reset when preferred is restored")
}

// Receiving only heartbeats from the fallback coordinator (with the transaction in the snapshot)
// produces no failover signal — originator remains on fallback.
func TestOriginator_WhenFallbackNeverReceivesPreferredHeartbeat_RemainsOnFallback(t *testing.T) {
	ctx := context.Background()
	preferred := "node1"
	fallback := "node2"
	txID := uuid.New()
	mockTxn := originatortransactionmocks.NewOriginatorTransaction(t)
	mockTxn.On("GetID").Return(txID)
	mockTxn.On("GetCurrentState").Return(transaction.State_Delegated)
	builder := NewOriginatorBuilderForTesting(t, State_Sending).
		PreferredActiveCoordinator(preferred).
		CurrentActiveCoordinator(fallback).
		FailoverOffset(1).
		NodeName("node3").
		Transactions(mockTxn)
	o, mocks := builder.Build()
	ca := builder.GetContractAddress()
	// Fallback sends heartbeat with the transaction in its snapshot — no drop detected, no redelegate.
	require.NoError(t, o.stateMachineEventLoop.ProcessEvent(ctx, &common.HeartbeatReceivedEvent{
		From:            fallback,
		ContractAddress: &ca,
		CoordinatorSnapshot: &common.CoordinatorSnapshot{
			PooledTransactions: []*common.SnapshotPooledTransaction{
				{ID: txID, Originator: "node3"},
			},
		},
	}))
	assert.Equal(t, fallback, o.currentActiveCoordinator, "current must remain on fallback coordinator")
	assert.Equal(t, 1, o.failoverOffset, "failoverOffset must not change when fallback heartbeat is healthy")
	assert.False(t, mocks.SentMessageRecorder.HasSentDelegationRequest(), "no redelegate when fallback snapshot is healthy")
}

// When on a fallback coordinator and the preferred sends an Active heartbeat,
// the originator redelegates all work to the preferred.
func TestOriginator_WhenOnFallbackAndPreferredBecomesVisible_RedelegatesNewWorkToPreferred(t *testing.T) {
	ctx := context.Background()
	preferred := "node1"
	fallback := "node2"
	txID := uuid.New()
	mockTxn := originatortransactionmocks.NewOriginatorTransaction(t)
	mockTxn.On("GetID").Return(txID)
	mockTxn.On("GetCurrentState").Return(transaction.State_Delegated)
	mockTxn.On("GetPrivateTransaction").Return(&components.PrivateTransaction{ID: txID})
	mockTxn.On("HandleEvent", mock.Anything, mock.Anything).Return(nil)
	builder := NewOriginatorBuilderForTesting(t, State_Sending).
		PreferredActiveCoordinator(preferred).
		CurrentActiveCoordinator(fallback).
		FailoverOffset(1).
		NodeName("node3").
		WithMockTransportWriter(t).
		Transactions(mockTxn)
	o, mocks := builder.Build()
	ca := builder.GetContractAddress()
	// After realignment current = preferred; all work is redelegated to the preferred coordinator.
	mocks.TransportWriter.EXPECT().
		SendDelegationRequest(mock.Anything, preferred, mock.Anything, mock.Anything).
		Return(nil).Once()
	// Preferred sends Active heartbeat with empty snapshot (transaction not listed → dropped detected).
	require.NoError(t, o.stateMachineEventLoop.ProcessEvent(ctx, &common.HeartbeatReceivedEvent{
		From:            preferred,
		ContractAddress: &ca,
		CoordinatorSnapshot: &common.CoordinatorSnapshot{
			CoordinatorState: common.CoordinatorState_Active,
		},
	}))
	assert.Equal(t, preferred, o.currentActiveCoordinator, "originator must realign current to preferred")
	assert.Equal(t, 0, o.failoverOffset, "failoverOffset resets when returning to preferred")
}

// When watching the previous flush AND on a fallback (failoverOffset > 0) AND inactive grace
// is exceeded, the inactive-grace HeartbeatInterval path clears watching AND sends delegation
// (the inactive-grace path bypasses the guard_WatchingPreviousCoordinatorFlush guard).
func TestOriginator_WhenWatchingPreviousFlushWhileRepointingToFallback_ReconcilesPerSpec(t *testing.T) {
	ctx := context.Background()
	pool := []string{"node1", "node2", "node3"}
	txID := uuid.New()
	mockTxn := originatortransactionmocks.NewOriginatorTransaction(t)
	mockTxn.On("GetID").Return(txID)
	mockTxn.On("GetPrivateTransaction").Return(&components.PrivateTransaction{ID: txID})
	mockTxn.On("HandleEvent", mock.Anything, mock.Anything).Return(nil)
	o, mocks := NewOriginatorBuilderForTesting(t, State_Sending).
		DomainContractConfig(&prototk.ContractConfig{
			CoordinatorSelection: prototk.ContractConfig_COORDINATOR_ENDORSER,
		}).
		CoordinatorEndorserPool(pool...).
		BlockRangeSize(50).
		CurrentBlockHeight(100).
		WatchingPreviousCoordinatorFlush(true).
		FailoverOffset(1).
		HeartbeatIntervalsSinceLastReceive(0).
		InactiveGracePeriod(1).
		WithMockTransportWriter(t).
		Transactions(mockTxn).
		Build()
	// After action_IncrementFailoverOffset (offset 1→2) and action_SelectActiveCoordinator, the
	// new current coordinator is determined by SelectCoordinatorNode(pool, 100, 50, 2).
	// The inactive-grace path then delegates to that coordinator regardless of the watching flag.
	_, expectedCoordinator := common.SelectCoordinatorNode(ctx, pool, 100, 50, 2)
	mocks.TransportWriter.EXPECT().
		SendDelegationRequest(mock.Anything, expectedCoordinator, mock.Anything, mock.Anything).
		Return(nil).Once()
	require.NoError(t, o.stateMachineEventLoop.ProcessEvent(ctx, &common.HeartbeatIntervalEvent{}))
	assert.False(t, o.watchingPreviousCoordinatorFlush, "inactive-grace path must clear watching even when on fallback")
	assert.Equal(t, expectedCoordinator, o.currentActiveCoordinator, "current coordinator must match selection after failover step")
}
