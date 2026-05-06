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
	"github.com/LFDT-Paladin/paladin/core/mocks/componentsmocks"
	"github.com/LFDT-Paladin/paladin/core/mocks/originatortransactionmocks"
	"github.com/LFDT-Paladin/paladin/toolkit/pkg/prototk"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	mock "github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

func Test_action_UpdateBlockHeight_SetsCurrentBlockHeight(t *testing.T) {
	ctx := context.Background()
	o, _ := NewOriginatorBuilderForTesting(State_Idle).Build()
	err := action_UpdateBlockHeight(ctx, o, &common.NewBlockEvent{BlockHeight: 1000})
	require.NoError(t, err)
	assert.Equal(t, uint64(1000), o.currentBlockHeight)
}
func Test_action_UpdateBlockHeight_NewEpoch_SetsNewBlockRangeEpochTrue(t *testing.T) {
	ctx := context.Background()
	o, _ := NewOriginatorBuilderForTesting(State_Idle).BlockRangeSize(10).CurrentBlockHeight(9).Build()
	err := action_UpdateBlockHeight(ctx, o, &common.NewBlockEvent{BlockHeight: 10})
	require.NoError(t, err)
	assert.True(t, o.newBlockRangeEpoch)
}
func Test_action_UpdateBlockHeight_SameEpoch_SetsNewBlockRangeEpochFalse(t *testing.T) {
	ctx := context.Background()
	o, _ := NewOriginatorBuilderForTesting(State_Idle).BlockRangeSize(10).CurrentBlockHeight(0).Build()
	err := action_UpdateBlockHeight(ctx, o, &common.NewBlockEvent{BlockHeight: 1})
	require.NoError(t, err)
	assert.False(t, o.newBlockRangeEpoch)
}
func Test_guard_IsNewBlockRangeEpoch_WhenNewEpoch_ReturnsTrue(t *testing.T) {
	ctx := context.Background()
	o, _ := NewOriginatorBuilderForTesting(State_Idle).NewBlockRangeEpoch(true).Build()
	assert.True(t, guard_IsNewBlockRangeEpoch(ctx, o))
}
func Test_guard_IsNewBlockRangeEpoch_WhenSameEpoch_ReturnsFalse(t *testing.T) {
	ctx := context.Background()
	o, _ := NewOriginatorBuilderForTesting(State_Idle).NewBlockRangeEpoch(false).Build()
	assert.False(t, guard_IsNewBlockRangeEpoch(ctx, o))
}
func Test_action_SelectActiveCoordinator_SenderMode_NoOp_ActiveCoordinatorUnchanged(t *testing.T) {
	ctx := context.Background()
	o, _ := NewOriginatorBuilderForTesting(State_Idle).Build()
	// In SENDER mode, action_SelectActiveCoordinator is a no-op; activeCoordinatorNode is unchanged.
	before := o.activeCoordinatorNode
	err := action_SelectActiveCoordinator(ctx, o, nil)
	require.NoError(t, err)
	assert.Equal(t, before, o.activeCoordinatorNode)
}
func Test_action_SelectActiveCoordinator_EndorserMode_WhenCoordinatorChanges_SetsChangedFlag(t *testing.T) {
	ctx := context.Background()
	domainAPI := &componentsmocks.DomainSmartContract{}
	domainAPI.On("ContractConfig").Return(&prototk.ContractConfig{
		CoordinatorSelection:          prototk.ContractConfig_COORDINATOR_ENDORSER,
		CoordinatorEndorserCandidates: []string{"id@node1", "id@node2"},
	})
	o, _ := NewOriginatorBuilderForTesting(State_Idle).
		DomainAPI(domainAPI).
		CoordinatorEndorserPool("node1", "node2").
		ActiveCoordinatorNode("some-other-node").
		CurrentBlockHeight(1000).
		Build()
	err := action_SelectActiveCoordinator(ctx, o, nil)
	require.NoError(t, err)
}
func Test_action_UpdateBlockHeight_ResetsCoordinatorChangedFlag(t *testing.T) {
	ctx := context.Background()
	o, _ := NewOriginatorBuilderForTesting(State_Idle).BlockRangeSize(10).Build()
	err := action_UpdateBlockHeight(ctx, o, &common.NewBlockEvent{BlockHeight: 1})
	require.NoError(t, err)
}
func Test_hasDroppedTransactions_TrueWhenDelegatedTxnNotInSnapshot(t *testing.T) {
	ctx := context.Background()
	txBuilder := transaction.NewTransactionBuilderForTesting(t, transaction.State_Delegated)
	o, _ := NewOriginatorBuilderForTesting(State_Sending).
		TransactionBuilders(txBuilder).
		Build()
	txn := txBuilder.GetBuiltTransaction()
	require.NotNil(t, txn)
	snapshot := &common.CoordinatorSnapshot{
		PooledTransactions: []*common.SnapshotPooledTransaction{},
	}
	assert.True(t, o.hasDroppedTransactions(ctx, snapshot))
}
func Test_hasDroppedTransactions_FalseWhenDelegatedTxnInSnapshot(t *testing.T) {
	ctx := context.Background()
	originatorLocator := "sender@senderNode"
	txBuilder := transaction.NewTransactionBuilderForTesting(t, transaction.State_Delegated)
	o, _ := NewOriginatorBuilderForTesting(State_Sending).
		TransactionBuilders(txBuilder).
		Build()
	txn := txBuilder.GetBuiltTransaction()
	require.NotNil(t, txn)
	snapshot := &common.CoordinatorSnapshot{
		PooledTransactions: []*common.SnapshotPooledTransaction{
			{ID: txn.GetID(), Originator: originatorLocator},
		},
	}
	assert.False(t, o.hasDroppedTransactions(ctx, snapshot))
}
func Test_transactionFoundInSnapshot_TrueWhenInDispatchedTransactions(t *testing.T) {
	originatorLocator := "sender@senderNode"
	txBuilder := transaction.NewTransactionBuilderForTesting(t, transaction.State_Delegated)
	o, _ := NewOriginatorBuilderForTesting(State_Sending).
		TransactionBuilders(txBuilder).
		Build()
	txn := txBuilder.GetBuiltTransaction()
	require.NotNil(t, txn)
	snapshot := &common.CoordinatorSnapshot{
		DispatchedTransactions: []*common.SnapshotDispatchedTransaction{
			{SnapshotPooledTransaction: common.SnapshotPooledTransaction{ID: txn.GetID(), Originator: originatorLocator}},
		},
		PooledTransactions:    []*common.SnapshotPooledTransaction{},
		ConfirmedTransactions: []*common.SnapshotConfirmedTransaction{},
	}
	_ = o
	assert.True(t, transactionFoundInSnapshot(snapshot, txn))
}
func Test_transactionFoundInSnapshot_TrueWhenInPooledTransactions(t *testing.T) {
	originatorLocator := "sender@senderNode"
	txBuilder := transaction.NewTransactionBuilderForTesting(t, transaction.State_Delegated)
	o, _ := NewOriginatorBuilderForTesting(State_Sending).
		TransactionBuilders(txBuilder).
		Build()
	txn := txBuilder.GetBuiltTransaction()
	require.NotNil(t, txn)
	snapshot := &common.CoordinatorSnapshot{
		DispatchedTransactions: []*common.SnapshotDispatchedTransaction{},
		PooledTransactions: []*common.SnapshotPooledTransaction{
			{ID: txn.GetID(), Originator: originatorLocator},
		},
		ConfirmedTransactions: []*common.SnapshotConfirmedTransaction{},
	}
	_ = o
	assert.True(t, transactionFoundInSnapshot(snapshot, txn))
}
func Test_transactionFoundInSnapshot_TrueWhenInConfirmedTransactions(t *testing.T) {
	originatorLocator := "sender@senderNode"
	txBuilder := transaction.NewTransactionBuilderForTesting(t, transaction.State_Delegated)
	o, _ := NewOriginatorBuilderForTesting(State_Sending).
		TransactionBuilders(txBuilder).
		Build()
	txn := txBuilder.GetBuiltTransaction()
	require.NotNil(t, txn)
	snapshot := &common.CoordinatorSnapshot{
		DispatchedTransactions: []*common.SnapshotDispatchedTransaction{},
		PooledTransactions:     []*common.SnapshotPooledTransaction{},
		ConfirmedTransactions: []*common.SnapshotConfirmedTransaction{
			{SnapshotDispatchedTransaction: common.SnapshotDispatchedTransaction{
				SnapshotPooledTransaction: common.SnapshotPooledTransaction{ID: txn.GetID(), Originator: originatorLocator},
			}},
		},
	}
	_ = o
	assert.True(t, transactionFoundInSnapshot(snapshot, txn))
}
func Test_transactionFoundInSnapshot_FalseWhenNotInSnapshot(t *testing.T) {
	txBuilder := transaction.NewTransactionBuilderForTesting(t, transaction.State_Delegated)
	o, _ := NewOriginatorBuilderForTesting(State_Sending).
		TransactionBuilders(txBuilder).
		Build()
	txn := txBuilder.GetBuiltTransaction()
	require.NotNil(t, txn)
	snapshot := &common.CoordinatorSnapshot{
		DispatchedTransactions: []*common.SnapshotDispatchedTransaction{},
		PooledTransactions:     []*common.SnapshotPooledTransaction{},
		ConfirmedTransactions:  []*common.SnapshotConfirmedTransaction{},
	}
	_ = o
	assert.False(t, transactionFoundInSnapshot(snapshot, txn))
}
func Test_transactionFoundInSnapshot_FalseWhenOnlyOtherTxnsInSnapshot(t *testing.T) {
	originatorLocator := "sender@senderNode"
	txBuilder := transaction.NewTransactionBuilderForTesting(t, transaction.State_Delegated)
	otherID := uuid.New()
	o, _ := NewOriginatorBuilderForTesting(State_Sending).
		TransactionBuilders(txBuilder).
		Build()
	txn := txBuilder.GetBuiltTransaction()
	require.NotNil(t, txn)
	snapshot := &common.CoordinatorSnapshot{
		PooledTransactions: []*common.SnapshotPooledTransaction{
			{ID: otherID, Originator: originatorLocator},
		},
		DispatchedTransactions: []*common.SnapshotDispatchedTransaction{},
		ConfirmedTransactions:  []*common.SnapshotConfirmedTransaction{},
	}
	_ = o
	assert.False(t, transactionFoundInSnapshot(snapshot, txn))
}

func Test_addToTransactions_HandleCreatedEventError_ReturnsError(t *testing.T) {
	ctx := context.Background()
	builder := NewOriginatorBuilderForTesting(State_Idle)
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
	o, _ := NewOriginatorBuilderForTesting(State_Sending).
		Transactions(mockTxn).
		ActiveCoordinatorNode("coordinator@coordinatorNode").
		Build()
	err := sendDelegationRequest(ctx, o)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "error handling delegated event for transaction")
	assert.Contains(t, err.Error(), txnID.String())
	assert.Contains(t, err.Error(), expectedErr.Error())
}
func Test_validator_TransactionDoesNotExist_InvalidEventTypeReturnsFalse(t *testing.T) {
	ctx := context.Background()
	builder := NewOriginatorBuilderForTesting(State_Observing)
	o, _ := builder.Build()
	valid, err := validator_TransactionDoesNotExist(ctx, o, &common.HeartbeatReceivedEvent{})
	assert.NoError(t, err)
	assert.False(t, valid)
}
func Test_validator_TransactionDoesNotExist_NilTransactionReturnsTrue(t *testing.T) {
	ctx := context.Background()
	builder := NewOriginatorBuilderForTesting(State_Observing)
	o, _ := builder.Build()
	valid, err := validator_TransactionDoesNotExist(ctx, o, &TransactionCreatedEvent{Transaction: nil})
	assert.NoError(t, err)
	assert.True(t, valid)
}
func Test_validator_TransactionDoesNotExist_TransactionAlreadyExistsReturnsFalse(t *testing.T) {
	ctx := context.Background()
	txBuilder := transaction.NewTransactionBuilderForTesting(t, transaction.State_Pending)
	builder := NewOriginatorBuilderForTesting(State_Observing).TransactionBuilders(txBuilder)
	o, _ := builder.Build()
	txn := txBuilder.GetBuiltTransaction()
	require.NotNil(t, txn)
	require.NotNil(t, o.transactionsByID[txn.GetID()])
	valid, err := validator_TransactionDoesNotExist(ctx, o, &TransactionCreatedEvent{
		Transaction: txn.GetPrivateTransaction(),
	})
	assert.NoError(t, err)
	assert.False(t, valid)
}
func Test_validator_TransactionDoesNotExist_NewTransactionReturnsTrue(t *testing.T) {
	ctx := context.Background()
	builder := NewOriginatorBuilderForTesting(State_Observing)
	o, _ := builder.Build()
	transactionBuilder := transaction.NewTransactionBuilderForTesting(t, transaction.State_Pending)
	pt := transactionBuilder.Build().GetPrivateTransaction()
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
func Test_guard_RedelegateThresholdExceeded_TrueWhenCounterExceedsThreshold(t *testing.T) {
	ctx := context.Background()
	o, _ := NewOriginatorBuilderForTesting(State_Sending).
		HeartbeatIntervalsSinceLastReceive(2).
		RedelegateThreshold(2).
		Build()
	assert.True(t, guard_RedelegateThresholdExceeded(ctx, o))
}
func Test_guard_RedelegateThresholdExceeded_FalseWhenCounterBelowThreshold(t *testing.T) {
	ctx := context.Background()
	o, _ := NewOriginatorBuilderForTesting(State_Sending).
		HeartbeatIntervalsSinceLastReceive(1).
		RedelegateThreshold(2).
		Build()
	assert.False(t, guard_RedelegateThresholdExceeded(ctx, o))
}
