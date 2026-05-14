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
	"testing"

	"github.com/LFDT-Paladin/paladin/core/internal/components"
	"github.com/LFDT-Paladin/paladin/core/internal/sequencer/common"
	"github.com/LFDT-Paladin/paladin/core/internal/sequencer/originator/transaction"
	"github.com/LFDT-Paladin/paladin/core/internal/sequencer/testutil"
	"github.com/LFDT-Paladin/paladin/core/mocks/originatortransactionmocks"
	"github.com/LFDT-Paladin/paladin/toolkit/pkg/prototk"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	mock "github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

func Test_action_UpdateBlockHeight_SetsCurrentBlockHeight(t *testing.T) {
	ctx := context.Background()
	o, _ := NewOriginatorBuilderForTesting(t, State_Idle).Build()
	err := action_UpdateBlockHeight(ctx, o, &common.NewBlockEvent{BlockHeight: 1000})
	require.NoError(t, err)
	assert.Equal(t, uint64(1000), o.currentBlockHeight)
}

func Test_action_UpdateCoordinatorPriorityList_UpdatesListOnly_CoordinatorUnchanged(t *testing.T) {
	ctx := context.Background()
	o, _ := NewOriginatorBuilderForTesting(t, State_Idle).
		CurrentActiveCoordinator("coordinator").
		Build()

	err := action_UpdateCoordinatorPriorityList(ctx, o, &common.CoordinatorPriorityListUpdatedEvent{
		Nodes: []string{"node1", "node2", "node3"},
	})
	require.NoError(t, err)

	assert.Equal(t, []string{"node1", "node2", "node3"}, o.coordinatorPriorityList)
	assert.Equal(t, "coordinator", o.currentActiveCoordinator, "action_UpdateCoordinatorPriorityList must not change currentActiveCoordinator")
}

func Test_action_UpdateCoordinatorPriorityList_EmptyNodeList_NoChange(t *testing.T) {
	ctx := context.Background()
	o, _ := NewOriginatorBuilderForTesting(t, State_Idle).
		CurrentActiveCoordinator("existing-coordinator").
		CoordinatorPriorityList("existing-coordinator").
		Build()

	err := action_UpdateCoordinatorPriorityList(ctx, o, &common.CoordinatorPriorityListUpdatedEvent{
		Nodes: []string{},
	})
	require.NoError(t, err)

	assert.Equal(t, "existing-coordinator", o.currentActiveCoordinator, "empty list must not overwrite current coordinator")
}

func Test_action_UpdateActiveCoordinatorFromHeartbeat_SetsCoordinator(t *testing.T) {
	ctx := context.Background()
	o, _ := NewOriginatorBuilderForTesting(t, State_Idle).Build()

	err := action_UpdateActiveCoordinatorFromHeartbeat(ctx, o, &common.HeartbeatReceivedEvent{
		From: "new-coordinator@node2",
		CoordinatorSnapshot: &common.CoordinatorSnapshot{
			CoordinatorState: common.CoordinatorState_Active,
		},
	})
	require.NoError(t, err)

	assert.Equal(t, "new-coordinator@node2", o.currentActiveCoordinator)
}

func Test_action_HandleDelegationRejected_HigherPriorityCoordinator_Redirects(t *testing.T) {
	// The rejection names a coordinator that has higher priority (lower index) than the current one.
	ctx := context.Background()
	o, _ := NewOriginatorBuilderForTesting(t, State_Sending).
		CurrentActiveCoordinator("node2").
		CoordinatorPriorityList("node1", "node2", "node3").
		Build()

	err := action_HandleDelegationRejected(ctx, o, &common.DelegationRejectedEvent{
		ActiveCoordinator: "node1",
	})
	require.NoError(t, err)

	assert.Equal(t, "node1", o.currentActiveCoordinator, "coordinator must be redirected to the higher-priority node")
}

func Test_action_HandleDelegationRejected_LowerPriorityCoordinator_NoChange(t *testing.T) {
	// The rejection names a coordinator with lower priority than the current one; we ignore it.
	ctx := context.Background()
	o, _ := NewOriginatorBuilderForTesting(t, State_Sending).
		CurrentActiveCoordinator("node1").
		CoordinatorPriorityList("node1", "node2", "node3").
		Build()

	err := action_HandleDelegationRejected(ctx, o, &common.DelegationRejectedEvent{
		ActiveCoordinator: "node3",
	})
	require.NoError(t, err)

	assert.Equal(t, "node1", o.currentActiveCoordinator, "coordinator must not change when named node has lower priority")
}

func Test_action_HandleDelegationRejected_NoActiveCoordinator_NoChange(t *testing.T) {
	ctx := context.Background()
	o, _ := NewOriginatorBuilderForTesting(t, State_Sending).
		CurrentActiveCoordinator("node1").
		Build()

	err := action_HandleDelegationRejected(ctx, o, &common.DelegationRejectedEvent{
		ActiveCoordinator: "",
	})
	require.NoError(t, err)

	assert.Equal(t, "node1", o.currentActiveCoordinator)
}

func Test_validator_IsHeartbeatSenderLive_ActiveState_ReturnsTrue(t *testing.T) {
	ctx := context.Background()
	o, _ := NewOriginatorBuilderForTesting(t, State_Observing).Build()
	valid, err := validator_IsHeartbeatSenderLive(ctx, o, &common.HeartbeatReceivedEvent{
		From: "coordinator@node1",
		CoordinatorSnapshot: &common.CoordinatorSnapshot{
			CoordinatorState: common.CoordinatorState_Active,
		},
	})
	require.NoError(t, err)
	assert.True(t, valid)
}

func Test_validator_IsHeartbeatSenderLive_PreparedState_ReturnsTrue(t *testing.T) {
	ctx := context.Background()
	o, _ := NewOriginatorBuilderForTesting(t, State_Observing).Build()
	valid, err := validator_IsHeartbeatSenderLive(ctx, o, &common.HeartbeatReceivedEvent{
		From: "coordinator@node1",
		CoordinatorSnapshot: &common.CoordinatorSnapshot{
			CoordinatorState: common.CoordinatorState_Prepared,
		},
	})
	require.NoError(t, err)
	assert.True(t, valid)
}

func Test_validator_IsHeartbeatSenderLive_ActiveFlushState_ReturnsTrue(t *testing.T) {
	ctx := context.Background()
	o, _ := NewOriginatorBuilderForTesting(t, State_Observing).Build()
	valid, err := validator_IsHeartbeatSenderLive(ctx, o, &common.HeartbeatReceivedEvent{
		From: "coordinator@node1",
		CoordinatorSnapshot: &common.CoordinatorSnapshot{
			CoordinatorState: common.CoordinatorState_Active_Flush,
		},
	})
	require.NoError(t, err)
	assert.True(t, valid)
}

func Test_validator_IsHeartbeatSenderLive_ClosingFlushState_ReturnsFalse(t *testing.T) {
	ctx := context.Background()
	o, _ := NewOriginatorBuilderForTesting(t, State_Observing).Build()
	valid, err := validator_IsHeartbeatSenderLive(ctx, o, &common.HeartbeatReceivedEvent{
		From: "coordinator@node1",
		CoordinatorSnapshot: &common.CoordinatorSnapshot{
			CoordinatorState: common.CoordinatorState_Closing_Flush,
		},
	})
	require.NoError(t, err)
	assert.False(t, valid)
}

func Test_validator_IsHeartbeatSenderLive_ClosingState_ReturnsFalse(t *testing.T) {
	ctx := context.Background()
	o, _ := NewOriginatorBuilderForTesting(t, State_Sending).Build()
	valid, err := validator_IsHeartbeatSenderLive(ctx, o, &common.HeartbeatReceivedEvent{
		From: "coordinator@node1",
		CoordinatorSnapshot: &common.CoordinatorSnapshot{
			CoordinatorState: common.CoordinatorState_Closing,
		},
	})
	require.NoError(t, err)
	assert.False(t, valid)
}

func Test_hasDroppedTransactions_TrueWhenDelegatedTxnNotInSnapshot(t *testing.T) {
	ctx := context.Background()
	txID := uuid.New()
	mockTxn := originatortransactionmocks.NewOriginatorTransaction(t)
	mockTxn.On("GetID").Return(txID)
	mockTxn.On("GetCurrentState").Return(transaction.State_Delegated)
	o, _ := NewOriginatorBuilderForTesting(t, State_Sending).
		Transactions(mockTxn).
		Build()
	snapshot := &common.CoordinatorSnapshot{
		PooledTransactions: []*common.SnapshotPooledTransaction{},
	}
	assert.True(t, o.hasDroppedTransactions(ctx, snapshot))
}
func Test_hasDroppedTransactions_FalseWhenDelegatedTxnInSnapshot(t *testing.T) {
	ctx := context.Background()
	originatorLocator := "sender@senderNode"
	txID := uuid.New()
	mockTxn := originatortransactionmocks.NewOriginatorTransaction(t)
	mockTxn.On("GetID").Return(txID)
	mockTxn.On("GetCurrentState").Return(transaction.State_Delegated)
	o, _ := NewOriginatorBuilderForTesting(t, State_Sending).
		Transactions(mockTxn).
		Build()
	snapshot := &common.CoordinatorSnapshot{
		PooledTransactions: []*common.SnapshotPooledTransaction{
			{ID: txID, Originator: originatorLocator},
		},
	}
	assert.False(t, o.hasDroppedTransactions(ctx, snapshot))
}
func Test_transactionFoundInSnapshot_TrueWhenInDispatchedTransactions(t *testing.T) {
	originatorLocator := "sender@senderNode"
	txID := uuid.New()
	mockTxn := originatortransactionmocks.NewOriginatorTransaction(t)
	mockTxn.On("GetID").Return(txID)
	snapshot := &common.CoordinatorSnapshot{
		DispatchedTransactions: []*common.SnapshotDispatchedTransaction{
			{SnapshotPooledTransaction: common.SnapshotPooledTransaction{ID: txID, Originator: originatorLocator}},
		},
		PooledTransactions:    []*common.SnapshotPooledTransaction{},
		ConfirmedTransactions: []*common.SnapshotConfirmedTransaction{},
	}
	assert.True(t, transactionFoundInSnapshot(snapshot, mockTxn))
}
func Test_transactionFoundInSnapshot_TrueWhenInPooledTransactions(t *testing.T) {
	originatorLocator := "sender@senderNode"
	txID := uuid.New()
	mockTxn := originatortransactionmocks.NewOriginatorTransaction(t)
	mockTxn.On("GetID").Return(txID)
	snapshot := &common.CoordinatorSnapshot{
		DispatchedTransactions: []*common.SnapshotDispatchedTransaction{},
		PooledTransactions: []*common.SnapshotPooledTransaction{
			{ID: txID, Originator: originatorLocator},
		},
		ConfirmedTransactions: []*common.SnapshotConfirmedTransaction{},
	}
	assert.True(t, transactionFoundInSnapshot(snapshot, mockTxn))
}
func Test_transactionFoundInSnapshot_TrueWhenInConfirmedTransactions(t *testing.T) {
	originatorLocator := "sender@senderNode"
	txID := uuid.New()
	mockTxn := originatortransactionmocks.NewOriginatorTransaction(t)
	mockTxn.On("GetID").Return(txID)
	snapshot := &common.CoordinatorSnapshot{
		DispatchedTransactions: []*common.SnapshotDispatchedTransaction{},
		PooledTransactions:     []*common.SnapshotPooledTransaction{},
		ConfirmedTransactions: []*common.SnapshotConfirmedTransaction{
			{SnapshotDispatchedTransaction: common.SnapshotDispatchedTransaction{
				SnapshotPooledTransaction: common.SnapshotPooledTransaction{ID: txID, Originator: originatorLocator},
			}},
		},
	}
	assert.True(t, transactionFoundInSnapshot(snapshot, mockTxn))
}

func Test_transactionFoundInSnapshot_FalseWhenOnlyOtherTxnsInSnapshot(t *testing.T) {
	originatorLocator := "sender@senderNode"
	txID := uuid.New()
	otherID := uuid.New()
	mockTxn := originatortransactionmocks.NewOriginatorTransaction(t)
	mockTxn.On("GetID").Return(txID)
	snapshot := &common.CoordinatorSnapshot{
		PooledTransactions: []*common.SnapshotPooledTransaction{
			{ID: otherID, Originator: originatorLocator},
		},
		DispatchedTransactions: []*common.SnapshotDispatchedTransaction{},
		ConfirmedTransactions:  []*common.SnapshotConfirmedTransaction{},
	}
	assert.False(t, transactionFoundInSnapshot(snapshot, mockTxn))
}

func Test_addToTransactions_HandleCreatedEventError_ReturnsError(t *testing.T) {
	ctx := context.Background()
	builder := NewOriginatorBuilderForTesting(t, State_Idle)
	o, _ := builder.Build()
	txnID := uuid.New()
	pt := &components.PrivateTransaction{ID: txnID}
	expectedErr := fmt.Errorf("created event handling failed")
	mockTxn := originatortransactionmocks.NewOriginatorTransaction(t)
	mockTxn.On("HandleEvent", mock.Anything, mock.Anything).Return(expectedErr)
	createTransaction := func(context.Context, *components.PrivateTransaction) (transaction.OriginatorTransaction, error) {
		return mockTxn, nil
	}
	err := o.addToTransactions(ctx, pt, createTransaction)
	require.Error(t, err)
	assert.Equal(t, expectedErr, err)
}
func Test_sendDelegationRequest_HandleEventError_ReturnsWrappedError(t *testing.T) {
	ctx := context.Background()
	txnID := uuid.New()
	pt := &components.PrivateTransaction{ID: txnID}
	expectedErr := fmt.Errorf("delegated event handling failed")
	mockTxn := originatortransactionmocks.NewOriginatorTransaction(t)
	mockTxn.On("GetPrivateTransaction").Return(pt)
	mockTxn.On("GetID").Return(txnID)
	mockTxn.On("HandleEvent", mock.Anything, mock.Anything).Return(expectedErr)
	o, _ := NewOriginatorBuilderForTesting(t, State_Sending).
		Transactions(mockTxn).
		CurrentActiveCoordinator("coordinator@coordinatorNode").
		Build()
	err := sendDelegationRequest(ctx, o)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "error handling delegated event for transaction")
	assert.Contains(t, err.Error(), txnID.String())
	assert.Contains(t, err.Error(), expectedErr.Error())
}
func Test_validator_TransactionDoesNotExist_InvalidEventTypeReturnsFalse(t *testing.T) {
	ctx := context.Background()
	builder := NewOriginatorBuilderForTesting(t, State_Observing)
	o, _ := builder.Build()
	valid, err := validator_TransactionDoesNotExist(ctx, o, &common.HeartbeatReceivedEvent{})
	assert.NoError(t, err)
	assert.False(t, valid)
}
func Test_validator_TransactionDoesNotExist_NilTransactionReturnsTrue(t *testing.T) {
	ctx := context.Background()
	builder := NewOriginatorBuilderForTesting(t, State_Observing)
	o, _ := builder.Build()
	valid, err := validator_TransactionDoesNotExist(ctx, o, &TransactionCreatedEvent{Transaction: nil})
	assert.NoError(t, err)
	assert.True(t, valid)
}
func Test_validator_TransactionDoesNotExist_TransactionAlreadyExistsReturnsFalse(t *testing.T) {
	ctx := context.Background()
	txID := uuid.New()
	mockTxn := originatortransactionmocks.NewOriginatorTransaction(t)
	mockTxn.On("GetID").Return(txID)
	o, _ := NewOriginatorBuilderForTesting(t, State_Observing).Transactions(mockTxn).Build()
	require.NotNil(t, o.transactionsByID[txID])
	valid, err := validator_TransactionDoesNotExist(ctx, o, &TransactionCreatedEvent{
		Transaction: &components.PrivateTransaction{ID: txID},
	})
	assert.NoError(t, err)
	assert.False(t, valid)
}
func Test_validator_TransactionDoesNotExist_NewTransactionReturnsTrue(t *testing.T) {
	ctx := context.Background()
	o, _ := NewOriginatorBuilderForTesting(t, State_Observing).Build()
	pt := &components.PrivateTransaction{ID: uuid.New()}
	valid, err := validator_TransactionDoesNotExist(ctx, o, &TransactionCreatedEvent{Transaction: pt})
	assert.NoError(t, err)
	assert.True(t, valid)
}
func Test_validator_OriginatorTransactionStateTransitionToFinal(t *testing.T) {
	ctx := context.Background()
	valid, err := validator_OriginatorTransactionStateTransitionToFinal(ctx, nil, &common.TransactionStateTransitionEvent[transaction.State]{To: transaction.State_Final})
	require.NoError(t, err)
	assert.True(t, valid)
	valid, err = validator_OriginatorTransactionStateTransitionToFinal(ctx, nil, &common.TransactionStateTransitionEvent[transaction.State]{To: transaction.State_Confirmed})
	require.NoError(t, err)
	assert.False(t, valid)
}
func Test_validator_OriginatorTransactionStateTransitionToConfirmed(t *testing.T) {
	ctx := context.Background()
	valid, err := validator_OriginatorTransactionStateTransitionToConfirmed(ctx, nil, &common.TransactionStateTransitionEvent[transaction.State]{To: transaction.State_Confirmed})
	require.NoError(t, err)
	assert.True(t, valid)
	valid, err = validator_OriginatorTransactionStateTransitionToConfirmed(ctx, nil, &common.TransactionStateTransitionEvent[transaction.State]{To: transaction.State_Reverted})
	require.NoError(t, err)
	assert.False(t, valid)
}
func Test_validator_OriginatorTransactionStateTransitionToReverted(t *testing.T) {
	ctx := context.Background()
	valid, err := validator_OriginatorTransactionStateTransitionToReverted(ctx, nil, &common.TransactionStateTransitionEvent[transaction.State]{To: transaction.State_Reverted})
	require.NoError(t, err)
	assert.True(t, valid)
	valid, err = validator_OriginatorTransactionStateTransitionToReverted(ctx, nil, &common.TransactionStateTransitionEvent[transaction.State]{To: transaction.State_Final})
	require.NoError(t, err)
	assert.False(t, valid)
}
func Test_guard_InactiveGracePeriodExceeded_WhileSending_TrueWhenCounterExceedsThreshold(t *testing.T) {
	ctx := context.Background()
	o, _ := NewOriginatorBuilderForTesting(t, State_Sending).
		HeartbeatIntervalsSinceLastReceive(2).
		InactiveGracePeriod(2).
		Build()
	assert.True(t, guard_InactiveGracePeriodExceeded(ctx, o))
}
func Test_guard_InactiveGracePeriodExceeded_WhileSending_FalseWhenCounterBelowThreshold(t *testing.T) {
	ctx := context.Background()
	o, _ := NewOriginatorBuilderForTesting(t, State_Sending).
		HeartbeatIntervalsSinceLastReceive(1).
		InactiveGracePeriod(2).
		Build()
	assert.False(t, guard_InactiveGracePeriodExceeded(ctx, o))
}

func Test_sendDelegationRequest_TransportError_ReturnsError(t *testing.T) {
	ctx := t.Context()
	builder := NewOriginatorBuilderForTesting(t, State_Sending).WithMockTransportWriter(t)
	txn := testutil.NewPrivateTransactionBuilderForTesting().Build()
	mockTxn := originatortransactionmocks.NewOriginatorTransaction(t)
	mockTxn.On("GetID").Return(txn.ID)
	mockTxn.On("GetPrivateTransaction").Return(txn)
	mockTxn.On("HandleEvent", mock.Anything, mock.Anything).Return(nil)
	o, mocks := builder.Transactions(mockTxn).CurrentActiveCoordinator("coordinator@node1").Build()

	mocks.TransportWriter.EXPECT().
		SendDelegationRequest(mock.Anything, mock.Anything, mock.Anything, mock.Anything).
		Return(fmt.Errorf("transport error"))

	err := sendDelegationRequest(ctx, o)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "transport error")
}

func Test_action_UpdateCoordinatorPriorityList_EndorserMode_UpdatesListOnly_CoordinatorUnchanged(t *testing.T) {
	// In COORDINATOR_ENDORSER mode the originator receives priority-list updates from the
	// co-located coordinator. The list is updated but currentActiveCoordinator is left alone;
	// only a live heartbeat or a delegation rejection can redirect the originator.
	ctx := context.Background()
	o, _ := NewOriginatorBuilderForTesting(t, State_Idle).
		DomainContractConfig(&prototk.ContractConfig{
			CoordinatorSelection:          prototk.ContractConfig_COORDINATOR_ENDORSER,
			CoordinatorEndorserCandidates: []string{"id@node1", "id@node2"},
		}).
		CoordinatorPriorityList("node1", "node2").
		CurrentActiveCoordinator("node2").
		Build()

	err := action_UpdateCoordinatorPriorityList(ctx, o, &common.CoordinatorPriorityListUpdatedEvent{
		Nodes: []string{"node1", "node2"},
	})
	require.NoError(t, err)
	assert.Equal(t, []string{"node1", "node2"}, o.coordinatorPriorityList)
	assert.Equal(t, "node2", o.currentActiveCoordinator, "action_UpdateCoordinatorPriorityList must not change currentActiveCoordinator")
}
