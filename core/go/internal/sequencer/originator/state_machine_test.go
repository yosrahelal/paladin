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
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// ── State_Initial ─────────────────────────────────────────────────────────────

// OriginatorCreatedEvent from Initial transitions unconditionally to Idle.
func TestStateMachine_Initial_OriginatorCreated_TransitionsToIdle(t *testing.T) {
	ctx := context.Background()
	o, _ := NewOriginatorBuilderForTesting(t, State_Initial).Build()

	require.NoError(t, o.stateMachineEventLoop.ProcessEvent(ctx, &OriginatorCreatedEvent{}))

	assert.Equal(t, State_Idle, o.GetCurrentState())
	// currentActiveCoordinator is set during Start() → initializeFromContractConfig, not here.
	// So the field value is whatever was set on the builder (default "coordinator").
	assert.NotEmpty(t, o.currentActiveCoordinator)
}

// ── State_Idle ────────────────────────────────────────────────────────────────

// HeartbeatReceived in Idle from a node in Active state → Observing; coordinator updated; timer reset.
func TestStateMachine_Idle_HeartbeatReceived_ActiveState_TransitionsToObserving(t *testing.T) {
	ctx := context.Background()
	builder := NewOriginatorBuilderForTesting(t, State_Idle).
		CurrentActiveCoordinator("old-coordinator").
		NodeName("node1")
	o, _ := builder.Build()
	o.heartbeatIntervalsSinceLastReceive = 5
	ca := builder.GetContractAddress()

	require.NoError(t, o.stateMachineEventLoop.ProcessEvent(ctx, &common.HeartbeatReceivedEvent{
		From:            "node2",
		ContractAddress: &ca,
		CoordinatorSnapshot: &common.CoordinatorSnapshot{
			CoordinatorState: common.CoordinatorState_Active,
		},
	}))

	assert.Equal(t, State_Observing, o.GetCurrentState())
	assert.Equal(t, "node2", o.currentActiveCoordinator, "coordinator must be updated to the Active heartbeat sender")
	assert.Equal(t, 0, o.heartbeatIntervalsSinceLastReceive, "liveness timer must be reset")
}

// HeartbeatReceived in Idle from a node in Elect state → Observing; Elect is a liveness-proving state.
func TestStateMachine_Idle_HeartbeatReceived_ElectState_TransitionsToObserving(t *testing.T) {
	ctx := context.Background()
	builder := NewOriginatorBuilderForTesting(t, State_Idle).
		CurrentActiveCoordinator("existing-coordinator").
		NodeName("node1")
	o, _ := builder.Build()
	ca := builder.GetContractAddress()

	require.NoError(t, o.stateMachineEventLoop.ProcessEvent(ctx, &common.HeartbeatReceivedEvent{
		From:            "node2",
		ContractAddress: &ca,
		CoordinatorSnapshot: &common.CoordinatorSnapshot{
			CoordinatorState: common.CoordinatorState_Elect,
		},
	}))

	assert.Equal(t, State_Observing, o.GetCurrentState())
	assert.Equal(t, "node2", o.currentActiveCoordinator, "coordinator must be updated to the Elect heartbeat sender")
	assert.Equal(t, 0, o.heartbeatIntervalsSinceLastReceive, "liveness timer must be reset")
}

// HeartbeatReceived in Idle from a node in Closing_Flush/Closing/Idle state → no state change.
func TestStateMachine_Idle_HeartbeatReceived_NonLiveState_StaysIdle(t *testing.T) {
	ctx := context.Background()
	builder := NewOriginatorBuilderForTesting(t, State_Idle).
		CurrentActiveCoordinator("existing-coordinator").
		NodeName("node1")
	o, _ := builder.Build()
	ca := builder.GetContractAddress()

	require.NoError(t, o.stateMachineEventLoop.ProcessEvent(ctx, &common.HeartbeatReceivedEvent{
		From:            "node2",
		ContractAddress: &ca,
		CoordinatorSnapshot: &common.CoordinatorSnapshot{
			CoordinatorState: common.CoordinatorState_Closing_Flush,
		},
	}))

	assert.Equal(t, State_Idle, o.GetCurrentState())
	assert.Equal(t, "existing-coordinator", o.currentActiveCoordinator, "coordinator must not change on non-live heartbeat in Idle")
}

// TransactionCreated in Idle → Sending; delegation request sent.
func TestStateMachine_Idle_TransactionCreated_TransitionsToSending_SendsDelegationRequest(t *testing.T) {
	ctx := context.Background()
	builder := NewOriginatorBuilderForTesting(t, State_Idle).
		CurrentActiveCoordinator("coordinator@node1").
		WithMockTransportWriter(t)
	o, mocks := builder.Build()

	mocks.TransportWriter.EXPECT().
		SendDelegationRequest(mock.Anything, "coordinator@node1", mock.Anything, mock.Anything).
		Return(nil).Once()

	txn := testutil.NewPrivateTransactionBuilderForTesting().Address(builder.GetContractAddress()).Originator("sender@node1").Build()
	require.NoError(t, o.stateMachineEventLoop.ProcessEvent(ctx, &TransactionCreatedEvent{Transaction: txn}))

	assert.Equal(t, State_Sending, o.GetCurrentState())
	assert.Len(t, o.transactionsByID, 1, "transaction must be tracked")
}

// Duplicate TransactionCreated (same ID) in Idle → no state change; no double tracking.
func TestStateMachine_Idle_TransactionCreated_DuplicateID_StaysIdle(t *testing.T) {
	ctx := context.Background()
	txID := uuid.New()
	mockTxn := originatortransactionmocks.NewOriginatorTransaction(t)
	mockTxn.On("GetID").Return(txID)
	o, _ := NewOriginatorBuilderForTesting(t, State_Idle).
		Transactions(mockTxn).
		Build()

	require.NoError(t, o.stateMachineEventLoop.ProcessEvent(ctx, &TransactionCreatedEvent{
		Transaction: &components.PrivateTransaction{ID: txID},
	}))

	assert.Equal(t, State_Idle, o.GetCurrentState())
	assert.Len(t, o.transactionsByID, 1, "duplicate transaction must not be double-tracked")
}

// NewBlock event in Idle updates currentBlockHeight; stays Idle.
func TestStateMachine_Idle_NewBlock_UpdatesBlockHeight_StaysIdle(t *testing.T) {
	ctx := context.Background()
	o, _ := NewOriginatorBuilderForTesting(t, State_Idle).CurrentBlockHeight(100).Build()

	require.NoError(t, o.stateMachineEventLoop.ProcessEvent(ctx, &common.NewBlockEvent{BlockHeight: 200}))

	assert.Equal(t, State_Idle, o.GetCurrentState())
	assert.Equal(t, uint64(200), o.currentBlockHeight)
}

// CoordinatorPriorityListUpdated in Idle updates the list and currentActiveCoordinator.
func TestStateMachine_Idle_CoordinatorPriorityListUpdated_UpdatesListAndCoordinator(t *testing.T) {
	ctx := context.Background()
	o, _ := NewOriginatorBuilderForTesting(t, State_Idle).
		CurrentActiveCoordinator("old").
		Build()

	require.NoError(t, o.stateMachineEventLoop.ProcessEvent(ctx, &common.CoordinatorPriorityListUpdatedEvent{
		Nodes: []string{"node1", "node2"},
	}))

	assert.Equal(t, State_Idle, o.GetCurrentState())
	assert.Equal(t, "node1", o.currentActiveCoordinator, "first node in list becomes active coordinator")
	assert.Equal(t, []string{"node1", "node2"}, o.coordinatorPriorityList)
}

// ── State_Observing ───────────────────────────────────────────────────────────

// TransactionCreated in Observing → Sending; delegation request sent.
func TestStateMachine_Observing_TransactionCreated_TransitionsToSending_SendsDelegation(t *testing.T) {
	ctx := context.Background()
	builder := NewOriginatorBuilderForTesting(t, State_Observing).
		CurrentActiveCoordinator("coordinator@node1").
		WithMockTransportWriter(t)
	o, mocks := builder.Build()

	mocks.TransportWriter.EXPECT().
		SendDelegationRequest(mock.Anything, "coordinator@node1", mock.Anything, mock.Anything).
		Return(nil).Once()

	txn := testutil.NewPrivateTransactionBuilderForTesting().Address(builder.GetContractAddress()).Originator("sender@node1").Build()
	require.NoError(t, o.stateMachineEventLoop.ProcessEvent(ctx, &TransactionCreatedEvent{Transaction: txn}))

	assert.Equal(t, State_Sending, o.GetCurrentState())
	assert.Len(t, o.transactionsByID, 1)
}

// HeartbeatReceived in Observing from Active node → coordinator updated; timer reset.
func TestStateMachine_Observing_HeartbeatReceived_ActiveState_UpdatesCoordinatorAndTimer(t *testing.T) {
	ctx := context.Background()
	builder := NewOriginatorBuilderForTesting(t, State_Observing).
		CurrentActiveCoordinator("old-coordinator")
	o, _ := builder.Build()
	o.heartbeatIntervalsSinceLastReceive = 3
	ca := builder.GetContractAddress()

	require.NoError(t, o.stateMachineEventLoop.ProcessEvent(ctx, &common.HeartbeatReceivedEvent{
		From:            "new-coordinator",
		ContractAddress: &ca,
		CoordinatorSnapshot: &common.CoordinatorSnapshot{
			CoordinatorState: common.CoordinatorState_Active,
		},
	}))

	assert.Equal(t, State_Observing, o.GetCurrentState())
	assert.Equal(t, "new-coordinator", o.currentActiveCoordinator)
	assert.Equal(t, 0, o.heartbeatIntervalsSinceLastReceive, "timer must be reset for Active heartbeat")
}

// HeartbeatReceived in Observing from Flush node → timer reset; coordinator NOT updated.
// HeartbeatReceived in Observing from Active_Flush node → timer reset; currentActiveCoordinator updated.
func TestStateMachine_Observing_HeartbeatReceived_ActiveFlushState_ResetsTimerAndUpdatesCoordinator(t *testing.T) {
	ctx := context.Background()
	builder := NewOriginatorBuilderForTesting(t, State_Observing).
		CurrentActiveCoordinator("existing-coordinator")
	o, _ := builder.Build()
	o.heartbeatIntervalsSinceLastReceive = 3
	ca := builder.GetContractAddress()

	require.NoError(t, o.stateMachineEventLoop.ProcessEvent(ctx, &common.HeartbeatReceivedEvent{
		From:            "other-node",
		ContractAddress: &ca,
		CoordinatorSnapshot: &common.CoordinatorSnapshot{
			CoordinatorState: common.CoordinatorState_Active_Flush,
		},
	}))

	assert.Equal(t, State_Observing, o.GetCurrentState())
	assert.Equal(t, "other-node", o.currentActiveCoordinator, "Active_Flush heartbeat must update coordinator")
	assert.Equal(t, 0, o.heartbeatIntervalsSinceLastReceive, "timer must be reset for Active_Flush heartbeat")
}

// HeartbeatReceived in Observing from Closing node → no timer reset; coordinator NOT updated.
func TestStateMachine_Observing_HeartbeatReceived_ClosingState_NoTimerResetAndNoCoordinatorUpdate(t *testing.T) {
	ctx := context.Background()
	builder := NewOriginatorBuilderForTesting(t, State_Observing).
		CurrentActiveCoordinator("existing-coordinator")
	o, _ := builder.Build()
	o.heartbeatIntervalsSinceLastReceive = 3
	ca := builder.GetContractAddress()

	require.NoError(t, o.stateMachineEventLoop.ProcessEvent(ctx, &common.HeartbeatReceivedEvent{
		From:            "other-node",
		ContractAddress: &ca,
		CoordinatorSnapshot: &common.CoordinatorSnapshot{
			CoordinatorState: common.CoordinatorState_Closing,
		},
	}))

	assert.Equal(t, State_Observing, o.GetCurrentState())
	assert.Equal(t, "existing-coordinator", o.currentActiveCoordinator, "Closing heartbeat must not update coordinator")
	assert.Equal(t, 3, o.heartbeatIntervalsSinceLastReceive, "timer must not be reset for Closing heartbeat")
}

// HeartbeatInterval in Observing within grace period → increments counter; stays Observing.
func TestStateMachine_Observing_HeartbeatInterval_WithinGrace_StaysObserving(t *testing.T) {
	ctx := context.Background()
	o, _ := NewOriginatorBuilderForTesting(t, State_Observing).
		HeartbeatIntervalsSinceLastReceive(0).
		InactiveGracePeriod(2).
		Build()

	require.NoError(t, o.stateMachineEventLoop.ProcessEvent(ctx, &common.HeartbeatIntervalEvent{}))

	assert.Equal(t, State_Observing, o.GetCurrentState())
	assert.Equal(t, 1, o.heartbeatIntervalsSinceLastReceive, "counter must be incremented")
}

// HeartbeatInterval in Observing exceeding grace period → transitions to Idle.
func TestStateMachine_Observing_HeartbeatInterval_GraceExceeded_TransitionsToIdle(t *testing.T) {
	ctx := context.Background()
	o, _ := NewOriginatorBuilderForTesting(t, State_Observing).
		HeartbeatIntervalsSinceLastReceive(1).
		InactiveGracePeriod(2).
		Build()

	require.NoError(t, o.stateMachineEventLoop.ProcessEvent(ctx, &common.HeartbeatIntervalEvent{}))

	assert.Equal(t, State_Idle, o.GetCurrentState())
	assert.Equal(t, 2, o.heartbeatIntervalsSinceLastReceive, "counter must be incremented before transition check")
}

// CoordinatorPriorityListUpdated in Observing updates the list.
func TestStateMachine_Observing_CoordinatorPriorityListUpdated_UpdatesList(t *testing.T) {
	ctx := context.Background()
	o, _ := NewOriginatorBuilderForTesting(t, State_Observing).
		CurrentActiveCoordinator("old").
		Build()

	require.NoError(t, o.stateMachineEventLoop.ProcessEvent(ctx, &common.CoordinatorPriorityListUpdatedEvent{
		Nodes: []string{"nodeA", "nodeB"},
	}))

	assert.Equal(t, State_Observing, o.GetCurrentState())
	assert.Equal(t, "nodeA", o.currentActiveCoordinator)
	assert.Equal(t, []string{"nodeA", "nodeB"}, o.coordinatorPriorityList)
}

// ── State_Sending ─────────────────────────────────────────────────────────────

// TransactionCreated in Sending → creates txn and sends delegation; stays Sending.
func TestStateMachine_Sending_TransactionCreated_CreatesTxnAndDelegates(t *testing.T) {
	ctx := context.Background()
	builder := NewOriginatorBuilderForTesting(t, State_Sending).
		CurrentActiveCoordinator("coordinator@node1").
		WithMockTransportWriter(t)
	o, mocks := builder.Build()

	mocks.TransportWriter.EXPECT().
		SendDelegationRequest(mock.Anything, "coordinator@node1", mock.Anything, mock.Anything).
		Return(nil).Once()

	txn := testutil.NewPrivateTransactionBuilderForTesting().Address(builder.GetContractAddress()).Originator("sender@node1").Build()
	require.NoError(t, o.stateMachineEventLoop.ProcessEvent(ctx, &TransactionCreatedEvent{Transaction: txn}))

	assert.Equal(t, State_Sending, o.GetCurrentState())
	assert.Len(t, o.transactionsByID, 1, "new transaction must be tracked")
}

// Duplicate TransactionCreated in Sending → validator blocks; no double delegation.
func TestStateMachine_Sending_TransactionCreated_DuplicateID_NoDelegation(t *testing.T) {
	ctx := context.Background()
	txID := uuid.New()
	mockTxn := originatortransactionmocks.NewOriginatorTransaction(t)
	mockTxn.On("GetID").Return(txID)
	o, _ := NewOriginatorBuilderForTesting(t, State_Sending).
		Transactions(mockTxn).
		Build()

	require.NoError(t, o.stateMachineEventLoop.ProcessEvent(ctx, &TransactionCreatedEvent{
		Transaction: &components.PrivateTransaction{ID: txID},
	}))

	assert.Equal(t, State_Sending, o.GetCurrentState())
	assert.Len(t, o.transactionsByID, 1, "duplicate must not be tracked twice")
}

// HeartbeatReceived in Sending with dropped transaction → redelegate.
func TestStateMachine_Sending_HeartbeatReceived_DroppedTransaction_Redelegates(t *testing.T) {
	ctx := context.Background()
	txID := uuid.New()
	mockTxn := originatortransactionmocks.NewOriginatorTransaction(t)
	mockTxn.On("GetID").Return(txID)
	mockTxn.On("GetCurrentState").Return(transaction.State_Delegated)
	mockTxn.On("GetPrivateTransaction").Return(&components.PrivateTransaction{ID: txID})
	mockTxn.On("HandleEvent", mock.Anything, mock.Anything).Return(nil)
	builder := NewOriginatorBuilderForTesting(t, State_Sending).
		CurrentActiveCoordinator("coordinator@node1").
		WithMockTransportWriter(t).
		Transactions(mockTxn)
	o, mocks := builder.Build()
	ca := builder.GetContractAddress()

	mocks.TransportWriter.EXPECT().
		SendDelegationRequest(mock.Anything, "coordinator@node1", mock.Anything, mock.Anything).
		Return(nil).Once()

	// Heartbeat with empty snapshot — txID is absent ⇒ dropped.
	require.NoError(t, o.stateMachineEventLoop.ProcessEvent(ctx, &common.HeartbeatReceivedEvent{
		From:            "coordinator@node1",
		ContractAddress: &ca,
		CoordinatorSnapshot: &common.CoordinatorSnapshot{
			CoordinatorState: common.CoordinatorState_Active,
		},
	}))

	assert.Equal(t, State_Sending, o.GetCurrentState())
}

// HeartbeatReceived in Sending from all-present snapshot → no redelegate.
func TestStateMachine_Sending_HeartbeatReceived_NoDroppedTransactions_NoRedelegate(t *testing.T) {
	ctx := context.Background()
	txID := uuid.New()
	mockTxn := originatortransactionmocks.NewOriginatorTransaction(t)
	mockTxn.On("GetID").Return(txID)
	mockTxn.On("GetCurrentState").Return(transaction.State_Delegated)
	builder := NewOriginatorBuilderForTesting(t, State_Sending).
		CurrentActiveCoordinator("coordinator@node1").
		Transactions(mockTxn)
	o, _ := builder.Build()
	ca := builder.GetContractAddress()

	require.NoError(t, o.stateMachineEventLoop.ProcessEvent(ctx, &common.HeartbeatReceivedEvent{
		From:            "coordinator@node1",
		ContractAddress: &ca,
		CoordinatorSnapshot: &common.CoordinatorSnapshot{
			CoordinatorState: common.CoordinatorState_Active,
			PooledTransactions: []*common.SnapshotPooledTransaction{
				{ID: txID, Originator: "sender@node1"},
			},
		},
	}))

	assert.Equal(t, State_Sending, o.GetCurrentState())
}

// HeartbeatReceived in Sending from a higher-priority node in Active state → redirects (step 2),
// then step 5 fires because the empty snapshot indicates the new coordinator has no record of our
// transaction, triggering a redelegate to it.
func TestStateMachine_Sending_HeartbeatReceived_HigherPriorityActiveNode_RedirectsAndRedelegates(t *testing.T) {
	ctx := context.Background()
	txID := uuid.New()
	mockTxn := originatortransactionmocks.NewOriginatorTransaction(t)
	mockTxn.On("GetID").Return(txID)
	mockTxn.On("GetCurrentState").Return(transaction.State_Delegated) // called by validator_HasDroppedTransactions (step 5)
	mockTxn.On("GetPrivateTransaction").Return(&components.PrivateTransaction{ID: txID})
	mockTxn.On("HandleEvent", mock.Anything, mock.Anything).Return(nil)
	builder := NewOriginatorBuilderForTesting(t, State_Sending).
		CurrentActiveCoordinator("node2"). // node1 is higher priority (index 0)
		CoordinatorPriorityList("node1", "node2", "node3").
		WithMockTransportWriter(t).
		Transactions(mockTxn)
	o, mocks := builder.Build()
	ca := builder.GetContractAddress()

	mocks.TransportWriter.EXPECT().
		SendDelegationRequest(mock.Anything, "node1", mock.Anything, mock.Anything).
		Return(nil).Once()

	require.NoError(t, o.stateMachineEventLoop.ProcessEvent(ctx, &common.HeartbeatReceivedEvent{
		From:            "node1",
		ContractAddress: &ca,
		CoordinatorSnapshot: &common.CoordinatorSnapshot{
			CoordinatorState: common.CoordinatorState_Active,
		},
	}))

	assert.Equal(t, State_Sending, o.GetCurrentState())
	assert.Equal(t, "node1", o.currentActiveCoordinator, "coordinator must be redirected to higher-priority node")
}

// HeartbeatInterval in Sending within grace period → counter incremented; no redelegate.
func TestStateMachine_Sending_HeartbeatInterval_WithinGrace_NoRedelegate(t *testing.T) {
	ctx := context.Background()
	o, _ := NewOriginatorBuilderForTesting(t, State_Sending).
		HeartbeatIntervalsSinceLastReceive(0).
		InactiveGracePeriod(2).
		Build()

	require.NoError(t, o.stateMachineEventLoop.ProcessEvent(ctx, &common.HeartbeatIntervalEvent{}))

	assert.Equal(t, State_Sending, o.GetCurrentState())
	assert.Equal(t, 1, o.heartbeatIntervalsSinceLastReceive)
}

// HeartbeatInterval in Sending exceeding grace → redelegates.
func TestStateMachine_Sending_HeartbeatInterval_GraceExceeded_Redelegates(t *testing.T) {
	ctx := context.Background()
	txID := uuid.New()
	mockTxn := originatortransactionmocks.NewOriginatorTransaction(t)
	mockTxn.On("GetID").Return(txID)
	mockTxn.On("GetPrivateTransaction").Return(&components.PrivateTransaction{ID: txID})
	mockTxn.On("HandleEvent", mock.Anything, mock.Anything).Return(nil)
	builder := NewOriginatorBuilderForTesting(t, State_Sending).
		CurrentActiveCoordinator("coordinator@node1").
		HeartbeatIntervalsSinceLastReceive(1).
		InactiveGracePeriod(2).
		WithMockTransportWriter(t).
		Transactions(mockTxn)
	o, mocks := builder.Build()

	mocks.TransportWriter.EXPECT().
		SendDelegationRequest(mock.Anything, "coordinator@node1", mock.Anything, mock.Anything).
		Return(nil).Once()

	require.NoError(t, o.stateMachineEventLoop.ProcessEvent(ctx, &common.HeartbeatIntervalEvent{}))

	assert.Equal(t, State_Sending, o.GetCurrentState())
	assert.Equal(t, 2, o.heartbeatIntervalsSinceLastReceive)
}

// DelegationRejected in Sending with higher-priority named coordinator → redirects and redelegates.
func TestStateMachine_Sending_DelegationRejected_HigherPriority_RedirectsAndRedelegates(t *testing.T) {
	ctx := context.Background()
	txID := uuid.New()
	mockTxn := originatortransactionmocks.NewOriginatorTransaction(t)
	mockTxn.On("GetID").Return(txID)
	mockTxn.On("GetPrivateTransaction").Return(&components.PrivateTransaction{ID: txID})
	mockTxn.On("HandleEvent", mock.Anything, mock.Anything).Return(nil)
	builder := NewOriginatorBuilderForTesting(t, State_Sending).
		CurrentActiveCoordinator("node2").
		CoordinatorPriorityList("node1", "node2", "node3").
		WithMockTransportWriter(t).
		Transactions(mockTxn)
	o, mocks := builder.Build()

	mocks.TransportWriter.EXPECT().
		SendDelegationRequest(mock.Anything, "node1", mock.Anything, mock.Anything).
		Return(nil).Once()

	require.NoError(t, o.stateMachineEventLoop.ProcessEvent(ctx, &common.DelegationRejectedEvent{
		ActiveCoordinator: "node1",
	}))

	assert.Equal(t, State_Sending, o.GetCurrentState())
	assert.Equal(t, "node1", o.currentActiveCoordinator)
}

// DelegationRejected in Sending with lower-priority named coordinator → no redirect; no redelegate.
func TestStateMachine_Sending_DelegationRejected_LowerPriority_NoChange(t *testing.T) {
	ctx := context.Background()
	o, _ := NewOriginatorBuilderForTesting(t, State_Sending).
		CurrentActiveCoordinator("node1").
		CoordinatorPriorityList("node1", "node2", "node3").
		Build()

	require.NoError(t, o.stateMachineEventLoop.ProcessEvent(ctx, &common.DelegationRejectedEvent{
		ActiveCoordinator: "node3",
	}))

	assert.Equal(t, State_Sending, o.GetCurrentState())
	assert.Equal(t, "node1", o.currentActiveCoordinator, "lower-priority coordinator must be ignored")
}

// TransactionStateTransition to Final in Sending removes transaction; transitions to Observing
// when it was the last unconfirmed transaction.
func TestStateMachine_Sending_TransactionFinal_LastTxn_TransitionsToObserving(t *testing.T) {
	ctx := context.Background()
	txID := uuid.New()
	mockTxn := originatortransactionmocks.NewOriginatorTransaction(t)
	mockTxn.On("GetID").Return(txID)
	o, _ := NewOriginatorBuilderForTesting(t, State_Sending).
		Transactions(mockTxn).
		Build()

	require.NoError(t, o.stateMachineEventLoop.ProcessEvent(ctx, &common.TransactionStateTransitionEvent[transaction.State]{
		TransactionID: txID,
		From:          transaction.State_Delegated,
		To:            transaction.State_Final,
	}))

	assert.Equal(t, State_Observing, o.GetCurrentState())
	assert.Empty(t, o.transactionsByID, "final transaction must be removed")
}

// TransactionStateTransition to Final in Sending when other transactions remain → stays Sending.
func TestStateMachine_Sending_TransactionFinal_OtherTxnsRemain_StaysSending(t *testing.T) {
	ctx := context.Background()
	txID1 := uuid.New()
	txID2 := uuid.New()
	mockTxn1 := originatortransactionmocks.NewOriginatorTransaction(t)
	mockTxn1.On("GetID").Return(txID1)
	mockTxn2 := originatortransactionmocks.NewOriginatorTransaction(t)
	mockTxn2.On("GetID").Return(txID2)
	// guard_HasUnconfirmedTransactions calls GetCurrentState on remaining transactions.
	mockTxn2.On("GetCurrentState").Return(transaction.State_Delegated)
	o, _ := NewOriginatorBuilderForTesting(t, State_Sending).
		Transactions(mockTxn1, mockTxn2).
		Build()

	require.NoError(t, o.stateMachineEventLoop.ProcessEvent(ctx, &common.TransactionStateTransitionEvent[transaction.State]{
		TransactionID: txID1,
		From:          transaction.State_Delegated,
		To:            transaction.State_Final,
	}))

	assert.Equal(t, State_Sending, o.GetCurrentState())
	assert.Len(t, o.transactionsByID, 1, "only the finalized transaction is removed")
}

// CoordinatorPriorityListUpdated in Sending updates the stored list and currentActiveCoordinator.
func TestStateMachine_Sending_CoordinatorPriorityListUpdated_UpdatesListAndCoordinator(t *testing.T) {
	ctx := context.Background()
	o, _ := NewOriginatorBuilderForTesting(t, State_Sending).
		CurrentActiveCoordinator("old-coordinator").
		Build()

	require.NoError(t, o.stateMachineEventLoop.ProcessEvent(ctx, &common.CoordinatorPriorityListUpdatedEvent{
		Nodes: []string{"new-node1", "new-node2"},
	}))

	assert.Equal(t, State_Sending, o.GetCurrentState())
	assert.Equal(t, "new-node1", o.currentActiveCoordinator)
	assert.Equal(t, []string{"new-node1", "new-node2"}, o.coordinatorPriorityList)
}

// NewBlock event in Sending updates currentBlockHeight; stays Sending.
func TestStateMachine_Sending_NewBlock_UpdatesBlockHeight_StaysSending(t *testing.T) {
	ctx := context.Background()
	txID := uuid.New()
	mockTxn := originatortransactionmocks.NewOriginatorTransaction(t)
	mockTxn.On("GetID").Return(txID)
	o, _ := NewOriginatorBuilderForTesting(t, State_Sending).
		CurrentBlockHeight(50).
		Transactions(mockTxn).
		Build()

	require.NoError(t, o.stateMachineEventLoop.ProcessEvent(ctx, &common.NewBlockEvent{BlockHeight: 100}))

	assert.Equal(t, State_Sending, o.GetCurrentState())
	assert.Equal(t, uint64(100), o.currentBlockHeight)
}
