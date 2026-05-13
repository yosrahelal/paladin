/*
 * Copyright © 2026 Kaleido, Inc.
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

	"github.com/LFDT-Paladin/paladin/core/internal/sequencer/common"
	"github.com/LFDT-Paladin/paladin/core/internal/sequencer/originator/transaction"
	"github.com/LFDT-Paladin/paladin/core/internal/sequencer/testutil"
	"github.com/LFDT-Paladin/paladin/core/mocks/originatortransactionmocks"
	"github.com/LFDT-Paladin/paladin/sdk/go/pkg/pldtypes"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

func Test_applyHeartbeatReceived_BasicUpdate(t *testing.T) {
	ctx := context.Background()
	coordinatorLocator := "coordinator@coordinatorNode"
	// Seed the current coordinator to match the heartbeat sender so the active-coordinator path is exercised.
	builder := NewOriginatorBuilderForTesting(t, State_Observing).
		CurrentActiveCoordinator(coordinatorLocator)
	o, _ := builder.Build()
	heartbeatEvent := &common.HeartbeatReceivedEvent{}
	heartbeatEvent.From = coordinatorLocator
	contractAddress := builder.GetContractAddress()
	heartbeatEvent.ContractAddress = &contractAddress
	heartbeatEvent.CoordinatorSnapshot = &common.CoordinatorSnapshot{
		BlockHeight: 1000,
	}
	err := o.applyHeartbeatReceived(ctx, heartbeatEvent)
	assert.NoError(t, err)
	// Verify counter was reset
	assert.Equal(t, 0, o.heartbeatIntervalsSinceLastReceive)
	// Verify active coordinator node remains unchanged (heartbeat does NOT update it)
	assert.Equal(t, coordinatorLocator, o.currentActiveCoordinator)
}

func Test_validator_IsHeartbeatFromCurrentActiveCoordinator_TrueWhenFromCurrent(t *testing.T) {
	ctx := context.Background()
	o, _ := NewOriginatorBuilderForTesting(t, State_Observing).
		CurrentActiveCoordinator("nodeB").
		NodeName("self").
		Build()
	event := &common.HeartbeatReceivedEvent{}
	event.From = "nodeB"
	event.CoordinatorSnapshot = &common.CoordinatorSnapshot{}
	ok, err := validator_IsHeartbeatFromCurrentActiveCoordinator(ctx, o, event)
	require.NoError(t, err)
	assert.True(t, ok)
}

func Test_validator_IsHeartbeatFromCurrentActiveCoordinator_FalseWhenFromOtherNode(t *testing.T) {
	ctx := context.Background()
	o, _ := NewOriginatorBuilderForTesting(t, State_Observing).
		CurrentActiveCoordinator("nodeB").
		NodeName("self").
		Build()
	event := &common.HeartbeatReceivedEvent{}
	event.From = "nodeC"
	event.CoordinatorSnapshot = &common.CoordinatorSnapshot{}
	ok, err := validator_IsHeartbeatFromCurrentActiveCoordinator(ctx, o, event)
	require.NoError(t, err)
	assert.False(t, ok)
}

func Test_guard_InactiveGracePeriodExceeded_WhileObserving_TrueWhenCounterExceedsThreshold(t *testing.T) {
	ctx := context.Background()
	o, _ := NewOriginatorBuilderForTesting(t, State_Observing).
		HeartbeatIntervalsSinceLastReceive(10).
		InactiveGracePeriod(10).
		Build()
	assert.True(t, guard_InactiveGracePeriodExceeded(ctx, o))
}
func Test_guard_InactiveGracePeriodExceeded_WhileObserving_FalseWhenCounterBelowThreshold(t *testing.T) {
	ctx := context.Background()
	o, _ := NewOriginatorBuilderForTesting(t, State_Observing).
		HeartbeatIntervalsSinceLastReceive(5).
		InactiveGracePeriod(10).
		Build()
	assert.False(t, guard_InactiveGracePeriodExceeded(ctx, o))
}
func Test_ProcessEvent_HeartbeatIntervalWhileObserving_IncrementsHeartbeatIntervalsSinceLastReceive(t *testing.T) {
	ctx := context.Background()
	o, _ := NewOriginatorBuilderForTesting(t, State_Observing).
		HeartbeatIntervalsSinceLastReceive(4).
		InactiveGracePeriod(100).
		Build()
	require.NoError(t, o.stateMachineEventLoop.ProcessEvent(ctx, &common.HeartbeatIntervalEvent{}))
	assert.Equal(t, 5, o.heartbeatIntervalsSinceLastReceive)
	assert.Equal(t, State_Observing, o.GetCurrentState())
}

func Test_ProcessEvent_HeartbeatReceivedWhileObserving_FromCurrentActiveCoordinator_ResetsLivenessCounter(t *testing.T) {
	ctx := context.Background()
	o, _ := NewOriginatorBuilderForTesting(t, State_Observing).
		CurrentActiveCoordinator("nodeB").
		NodeName("self@selfNode").
		HeartbeatIntervalsSinceLastReceive(5).
		InactiveGracePeriod(100).
		Build()
	heartbeatEvent := &common.HeartbeatReceivedEvent{}
	heartbeatEvent.From = "nodeB"
	heartbeatEvent.ContractAddress = o.contractAddress
	heartbeatEvent.CoordinatorSnapshot = &common.CoordinatorSnapshot{}
	require.NoError(t, o.stateMachineEventLoop.ProcessEvent(ctx, heartbeatEvent))
	assert.Equal(t, State_Observing, o.GetCurrentState())
	assert.Equal(t, 0, o.heartbeatIntervalsSinceLastReceive)
}

func Test_ProcessEvent_HeartbeatReceivedWhileObserving_FromUnrelatedNode_NoChange(t *testing.T) {
	ctx := context.Background()
	o, _ := NewOriginatorBuilderForTesting(t, State_Observing).
		CurrentActiveCoordinator("nodeB").
		NodeName("self@selfNode").
		HeartbeatIntervalsSinceLastReceive(5).
		InactiveGracePeriod(100).
		Build()
	heartbeatEvent := &common.HeartbeatReceivedEvent{}
	heartbeatEvent.From = "nodeC"
	heartbeatEvent.ContractAddress = o.contractAddress
	heartbeatEvent.CoordinatorSnapshot = &common.CoordinatorSnapshot{CoordinatorState: common.CoordinatorState_Active}
	require.NoError(t, o.stateMachineEventLoop.ProcessEvent(ctx, heartbeatEvent))
	assert.Equal(t, State_Observing, o.GetCurrentState())
	assert.Equal(t, "nodeB", o.currentActiveCoordinator)
	assert.Equal(t, 5, o.heartbeatIntervalsSinceLastReceive)
}

func Test_applyHeartbeatReceived_DispatchedTransactionNotFoundLogsAndContinues(t *testing.T) {
	ctx := context.Background()
	originatorLocator := "sender@senderNode"
	coordinatorLocator := "coordinator@coordinatorNode"
	// nodeName must match DispatchedTransactions[].Originator or the heartbeat entry is skipped entirely.
	builder := NewOriginatorBuilderForTesting(t, State_Sending).
		NodeName(originatorLocator).
		CurrentActiveCoordinator(coordinatorLocator)
	o, _ := builder.Build()
	heartbeatEvent := &common.HeartbeatReceivedEvent{}
	heartbeatEvent.From = coordinatorLocator
	contractAddress := builder.GetContractAddress()
	heartbeatEvent.ContractAddress = &contractAddress
	// Create a dispatched transaction that doesn't exist in memory
	unknownTxID := uuid.New()
	heartbeatEvent.CoordinatorSnapshot = &common.CoordinatorSnapshot{
		DispatchedTransactions: []*common.SnapshotDispatchedTransaction{
			{
				SnapshotPooledTransaction: common.SnapshotPooledTransaction{
					ID:         unknownTxID,
					Originator: originatorLocator,
				},
			},
		},
	}
	err := o.applyHeartbeatReceived(ctx, heartbeatEvent)
	// Should not error, just log a warning
	assert.NoError(t, err)
}
func Test_applyHeartbeatReceived_DispatchedTransactionWithHashUpdatesSubmitted(t *testing.T) {
	ctx := context.Background()
	originatorLocator := "sender@senderNode"
	coordinatorLocator := "coordinator@coordinatorNode"
	builder := NewOriginatorBuilderForTesting(t, State_Sending).
		CurrentActiveCoordinator(coordinatorLocator)
	o, _ := builder.Build()
	// Create a real transaction
	transactionBuilder := testutil.NewPrivateTransactionBuilderForTesting().
		Address(builder.GetContractAddress()).
		Originator(originatorLocator).
		NumberOfRequiredEndorsers(1)
	txn := transactionBuilder.BuildSparse()
	// Create the transaction in the originator
	err := o.addToTransactions(ctx, txn, o.newOriginatorTransaction)
	require.NoError(t, err)
	// Create heartbeat with dispatched transaction that has a hash
	signerAddress := pldtypes.RandAddress()
	submissionHash := pldtypes.RandBytes32()
	nonce := uint64(42)
	heartbeatEvent := &common.HeartbeatReceivedEvent{}
	heartbeatEvent.From = coordinatorLocator
	contractAddress := builder.GetContractAddress()
	heartbeatEvent.ContractAddress = &contractAddress
	heartbeatEvent.CoordinatorSnapshot = &common.CoordinatorSnapshot{
		DispatchedTransactions: []*common.SnapshotDispatchedTransaction{
			{
				SnapshotPooledTransaction: common.SnapshotPooledTransaction{
					ID:         txn.ID,
					Originator: originatorLocator,
				},
				Signer:               *signerAddress,
				LatestSubmissionHash: &submissionHash,
				Nonce:                &nonce,
			},
		},
	}
	err = o.applyHeartbeatReceived(ctx, heartbeatEvent)
	assert.NoError(t, err)
}
func Test_applyHeartbeatReceived_DispatchedTransactionWithNonceOnlySendsNonceAssigned(t *testing.T) {
	ctx := context.Background()
	originatorLocator := "sender@senderNode"
	coordinatorLocator := "coordinator@coordinatorNode"
	builder := NewOriginatorBuilderForTesting(t, State_Sending).
		CurrentActiveCoordinator(coordinatorLocator)
	o, _ := builder.Build()
	// Create a real transaction
	transactionBuilder := testutil.NewPrivateTransactionBuilderForTesting().
		Address(builder.GetContractAddress()).
		Originator(originatorLocator).
		NumberOfRequiredEndorsers(1)
	txn := transactionBuilder.BuildSparse()
	// Create the transaction in the originator
	err := o.addToTransactions(ctx, txn, o.newOriginatorTransaction)
	require.NoError(t, err)
	// Create heartbeat with dispatched transaction that has a nonce but no hash
	nonce := uint64(42)
	heartbeatEvent := &common.HeartbeatReceivedEvent{}
	heartbeatEvent.From = coordinatorLocator
	contractAddress := builder.GetContractAddress()
	heartbeatEvent.ContractAddress = &contractAddress
	heartbeatEvent.CoordinatorSnapshot = &common.CoordinatorSnapshot{
		DispatchedTransactions: []*common.SnapshotDispatchedTransaction{
			{
				SnapshotPooledTransaction: common.SnapshotPooledTransaction{
					ID:         txn.ID,
					Originator: originatorLocator,
				},
				Nonce: &nonce,
				// No LatestSubmissionHash
			},
		},
	}
	err = o.applyHeartbeatReceived(ctx, heartbeatEvent)
	assert.NoError(t, err)
}
func Test_applyHeartbeatReceived_DispatchedTransactionFromDifferentOriginatorIgnored(t *testing.T) {
	ctx := context.Background()
	otherOriginatorLocator := "otherSender@otherNode"
	coordinatorLocator := "coordinator@coordinatorNode"
	builder := NewOriginatorBuilderForTesting(t, State_Sending).
		CurrentActiveCoordinator(coordinatorLocator)
	o, _ := builder.Build()
	heartbeatEvent := &common.HeartbeatReceivedEvent{}
	heartbeatEvent.From = coordinatorLocator
	contractAddress := builder.GetContractAddress()
	heartbeatEvent.ContractAddress = &contractAddress
	heartbeatEvent.CoordinatorSnapshot = &common.CoordinatorSnapshot{
		DispatchedTransactions: []*common.SnapshotDispatchedTransaction{
			{
				SnapshotPooledTransaction: common.SnapshotPooledTransaction{
					ID:         uuid.New(),
					Originator: otherOriginatorLocator, // Different originator
				},
			},
		},
	}
	err := o.applyHeartbeatReceived(ctx, heartbeatEvent)
	assert.NoError(t, err)
}
func Test_applyHeartbeatReceived_DispatchedTransactionWithHashAndNonceSucceeds(t *testing.T) {
	ctx := context.Background()
	originatorLocator := "sender@senderNode"
	coordinatorLocator := "coordinator@coordinatorNode"
	builder := NewOriginatorBuilderForTesting(t, State_Sending).
		CurrentActiveCoordinator(coordinatorLocator)
	o, _ := builder.Build()
	// Create a real transaction
	transactionBuilder := testutil.NewPrivateTransactionBuilderForTesting().
		Address(builder.GetContractAddress()).
		Originator(originatorLocator).
		NumberOfRequiredEndorsers(1)
	txn := transactionBuilder.BuildSparse()
	// Create the transaction in the originator
	err := o.addToTransactions(ctx, txn, o.newOriginatorTransaction)
	require.NoError(t, err)
	submissionHash := pldtypes.RandBytes32()
	nonce := uint64(42)
	heartbeatEvent := &common.HeartbeatReceivedEvent{}
	heartbeatEvent.From = coordinatorLocator
	contractAddress := builder.GetContractAddress()
	heartbeatEvent.ContractAddress = &contractAddress
	heartbeatEvent.CoordinatorSnapshot = &common.CoordinatorSnapshot{
		DispatchedTransactions: []*common.SnapshotDispatchedTransaction{
			{
				SnapshotPooledTransaction: common.SnapshotPooledTransaction{
					ID:         txn.ID,
					Originator: originatorLocator,
				},
				LatestSubmissionHash: &submissionHash,
				Nonce:                &nonce,
			},
		},
	}
	// This should succeed with a real transaction
	err = o.applyHeartbeatReceived(ctx, heartbeatEvent)
	assert.NoError(t, err)
}
func Test_applyHeartbeatReceived_DispatchedTransactionNonceOnlySucceeds(t *testing.T) {
	ctx := context.Background()
	originatorLocator := "sender@senderNode"
	coordinatorLocator := "coordinator@coordinatorNode"
	builder := NewOriginatorBuilderForTesting(t, State_Sending).
		CurrentActiveCoordinator(coordinatorLocator)
	o, _ := builder.Build()
	// Create a real transaction
	transactionBuilder := testutil.NewPrivateTransactionBuilderForTesting().
		Address(builder.GetContractAddress()).
		Originator(originatorLocator).
		NumberOfRequiredEndorsers(1)
	txn := transactionBuilder.BuildSparse()
	// Create the transaction in the originator
	err := o.addToTransactions(ctx, txn, o.newOriginatorTransaction)
	require.NoError(t, err)
	// Create heartbeat with dispatched transaction that has a nonce but no hash
	nonce := uint64(42)
	heartbeatEvent := &common.HeartbeatReceivedEvent{}
	heartbeatEvent.From = coordinatorLocator
	contractAddress := builder.GetContractAddress()
	heartbeatEvent.ContractAddress = &contractAddress
	heartbeatEvent.CoordinatorSnapshot = &common.CoordinatorSnapshot{
		DispatchedTransactions: []*common.SnapshotDispatchedTransaction{
			{
				SnapshotPooledTransaction: common.SnapshotPooledTransaction{
					ID:         txn.ID,
					Originator: originatorLocator,
				},
				Nonce: &nonce,
				// No LatestSubmissionHash
			},
		},
	}
	// This should succeed with a real transaction
	err = o.applyHeartbeatReceived(ctx, heartbeatEvent)
	assert.NoError(t, err)
}
func Test_applyHeartbeatReceived_SubmittedHandleEventError_ReturnsWrappedError(t *testing.T) {
	ctx := context.Background()
	originatorLocator := "sender@senderNode"
	coordinatorLocator := "coordinator@coordinatorNode"
	txnID := uuid.New()
	innerErr := fmt.Errorf("simulated submitted handling failure")
	mockTxn := originatortransactionmocks.NewOriginatorTransaction(t)
	mockTxn.EXPECT().GetID().Return(txnID)
	mockTxn.EXPECT().GetCurrentState().Return(transaction.State_Delegated)
	mockTxn.EXPECT().HandleEvent(ctx, mock.AnythingOfType("*transaction.SubmittedEvent")).Return(innerErr)
	builder := NewOriginatorBuilderForTesting(t, State_Sending).
		NodeName(originatorLocator).
		CurrentActiveCoordinator(coordinatorLocator).
		Transactions(mockTxn)
	o, _ := builder.Build()
	signerAddress := pldtypes.RandAddress()
	submissionHash := pldtypes.RandBytes32()
	heartbeatEvent := &common.HeartbeatReceivedEvent{}
	heartbeatEvent.From = coordinatorLocator
	contractAddress := builder.GetContractAddress()
	heartbeatEvent.ContractAddress = &contractAddress
	heartbeatEvent.CoordinatorSnapshot = &common.CoordinatorSnapshot{
		DispatchedTransactions: []*common.SnapshotDispatchedTransaction{
			{
				SnapshotPooledTransaction: common.SnapshotPooledTransaction{
					ID:         txnID,
					Originator: originatorLocator,
				},
				Signer:               *signerAddress,
				LatestSubmissionHash: &submissionHash,
			},
		},
	}
	err := o.applyHeartbeatReceived(ctx, heartbeatEvent)
	require.Error(t, err)
	assert.ErrorContains(t, err, "error handling transaction submitted event")
	assert.Contains(t, err.Error(), txnID.String())
	assert.Contains(t, err.Error(), innerErr.Error())
}
func Test_applyHeartbeatReceived_NonceAssignedHandleEventError_ReturnsWrappedError(t *testing.T) {
	ctx := context.Background()
	originatorLocator := "sender@senderNode"
	coordinatorLocator := "coordinator@coordinatorNode"
	txnID := uuid.New()
	innerErr := fmt.Errorf("simulated nonce handling failure")
	mockTxn := originatortransactionmocks.NewOriginatorTransaction(t)
	mockTxn.EXPECT().GetID().Return(txnID)
	mockTxn.EXPECT().GetCurrentState().Return(transaction.State_Delegated)
	mockTxn.EXPECT().HandleEvent(ctx, mock.AnythingOfType("*transaction.NonceAssignedEvent")).Return(innerErr)
	builder := NewOriginatorBuilderForTesting(t, State_Sending).
		NodeName(originatorLocator).
		CurrentActiveCoordinator(coordinatorLocator).
		Transactions(mockTxn)
	o, _ := builder.Build()
	nonce := uint64(99)
	heartbeatEvent := &common.HeartbeatReceivedEvent{}
	heartbeatEvent.From = coordinatorLocator
	contractAddress := builder.GetContractAddress()
	heartbeatEvent.ContractAddress = &contractAddress
	heartbeatEvent.CoordinatorSnapshot = &common.CoordinatorSnapshot{
		DispatchedTransactions: []*common.SnapshotDispatchedTransaction{
			{
				SnapshotPooledTransaction: common.SnapshotPooledTransaction{
					ID:         txnID,
					Originator: originatorLocator,
				},
				Nonce: &nonce,
			},
		},
	}
	err := o.applyHeartbeatReceived(ctx, heartbeatEvent)
	require.Error(t, err)
	assert.ErrorContains(t, err, "error handling nonce assigned event")
	assert.Contains(t, err.Error(), txnID.String())
	assert.Contains(t, err.Error(), innerErr.Error())
}

func Test_applyHeartbeatReceived_ConfirmedTransaction_Success(t *testing.T) {
	ctx := context.Background()
	txID := uuid.New()

	mockTxn := originatortransactionmocks.NewOriginatorTransaction(t)
	mockTxn.On("GetID").Return(txID)
	mockTxn.On("GetCurrentState").Return(transaction.State_Submitted)
	mockTxn.On("HandleEvent", mock.Anything, mock.MatchedBy(func(e transaction.Event) bool {
		_, ok := e.(*transaction.ConfirmedSuccessEvent)
		return ok
	})).Return(nil)

	o, _ := NewOriginatorBuilderForTesting(t, State_Observing).
		NodeName("member1@node1").
		CurrentActiveCoordinator("coordinator@node1").
		Transactions(mockTxn).
		Build()

	contractAddress := *pldtypes.RandAddress()
	event := &common.HeartbeatReceivedEvent{
		From:            "coordinator@node1",
		ContractAddress: &contractAddress,
		CoordinatorSnapshot: &common.CoordinatorSnapshot{
			ConfirmedTransactions: []*common.SnapshotConfirmedTransaction{
				{
					SnapshotDispatchedTransaction: common.SnapshotDispatchedTransaction{
						SnapshotPooledTransaction: common.SnapshotPooledTransaction{
							ID:         txID,
							Originator: "member1@node1",
						},
					},
				},
			},
		},
	}

	err := o.applyHeartbeatReceived(ctx, event)
	require.NoError(t, err)
	mockTxn.AssertExpectations(t)
}

func Test_applyHeartbeatReceived_ConfirmedTransaction_Reverted(t *testing.T) {
	ctx := context.Background()
	txID := uuid.New()

	mockTxn := originatortransactionmocks.NewOriginatorTransaction(t)
	mockTxn.On("GetID").Return(txID)
	mockTxn.On("GetCurrentState").Return(transaction.State_Submitted)
	mockTxn.On("HandleEvent", mock.Anything, mock.MatchedBy(func(e transaction.Event) bool {
		rev, ok := e.(*transaction.ConfirmedRevertedEvent)
		return ok && len(rev.RevertReason) > 0
	})).Return(nil)

	o, _ := NewOriginatorBuilderForTesting(t, State_Observing).
		NodeName("member1@node1").
		CurrentActiveCoordinator("coordinator@node1").
		Transactions(mockTxn).
		Build()

	contractAddress := *pldtypes.RandAddress()
	event := &common.HeartbeatReceivedEvent{
		From:            "coordinator@node1",
		ContractAddress: &contractAddress,
		CoordinatorSnapshot: &common.CoordinatorSnapshot{
			ConfirmedTransactions: []*common.SnapshotConfirmedTransaction{
				{
					SnapshotDispatchedTransaction: common.SnapshotDispatchedTransaction{
						SnapshotPooledTransaction: common.SnapshotPooledTransaction{
							ID:         txID,
							Originator: "member1@node1",
						},
					},
					RevertReason: pldtypes.HexBytes{0x01, 0x02},
				},
			},
		},
	}

	err := o.applyHeartbeatReceived(ctx, event)
	require.NoError(t, err)
	mockTxn.AssertExpectations(t)
}

func Test_applyHeartbeatReceived_ConfirmedTransaction_NotOurNode_Skipped(t *testing.T) {
	ctx := context.Background()

	o, _ := NewOriginatorBuilderForTesting(t, State_Observing).
		NodeName("member1@node1").
		CurrentActiveCoordinator("coordinator@node1").
		Build()

	contractAddress := *pldtypes.RandAddress()
	event := &common.HeartbeatReceivedEvent{
		From:            "coordinator@node1",
		ContractAddress: &contractAddress,
		CoordinatorSnapshot: &common.CoordinatorSnapshot{
			ConfirmedTransactions: []*common.SnapshotConfirmedTransaction{
				{
					SnapshotDispatchedTransaction: common.SnapshotDispatchedTransaction{
						SnapshotPooledTransaction: common.SnapshotPooledTransaction{
							ID:         uuid.New(),
							Originator: "other@otherNode",
						},
					},
				},
			},
		},
	}

	err := o.applyHeartbeatReceived(ctx, event)
	require.NoError(t, err)
}

func Test_applyHeartbeatReceived_ConfirmedTransaction_NotInMemory_Skipped(t *testing.T) {
	ctx := context.Background()

	o, _ := NewOriginatorBuilderForTesting(t, State_Observing).
		NodeName("member1@node1").
		CurrentActiveCoordinator("coordinator@node1").
		Build()

	contractAddress := *pldtypes.RandAddress()
	event := &common.HeartbeatReceivedEvent{
		From:            "coordinator@node1",
		ContractAddress: &contractAddress,
		CoordinatorSnapshot: &common.CoordinatorSnapshot{
			ConfirmedTransactions: []*common.SnapshotConfirmedTransaction{
				{
					SnapshotDispatchedTransaction: common.SnapshotDispatchedTransaction{
						SnapshotPooledTransaction: common.SnapshotPooledTransaction{
							ID:         uuid.New(),
							Originator: "member1@node1",
						},
					},
				},
			},
		},
	}

	err := o.applyHeartbeatReceived(ctx, event)
	require.NoError(t, err)
}

func Test_applyHeartbeatReceived_ConfirmedTransaction_SuccessHandleEventError(t *testing.T) {
	ctx := context.Background()
	txID := uuid.New()

	mockTxn := originatortransactionmocks.NewOriginatorTransaction(t)
	mockTxn.On("GetID").Return(txID)
	mockTxn.On("GetCurrentState").Return(transaction.State_Submitted).Maybe()
	mockTxn.On("HandleEvent", mock.Anything, mock.Anything).Return(fmt.Errorf("handle event error"))

	o, _ := NewOriginatorBuilderForTesting(t, State_Observing).
		NodeName("member1@node1").
		CurrentActiveCoordinator("coordinator@node1").
		Transactions(mockTxn).
		Build()

	contractAddress := *pldtypes.RandAddress()
	event := &common.HeartbeatReceivedEvent{
		From:            "coordinator@node1",
		ContractAddress: &contractAddress,
		CoordinatorSnapshot: &common.CoordinatorSnapshot{
			ConfirmedTransactions: []*common.SnapshotConfirmedTransaction{
				{
					SnapshotDispatchedTransaction: common.SnapshotDispatchedTransaction{
						SnapshotPooledTransaction: common.SnapshotPooledTransaction{
							ID:         txID,
							Originator: "member1@node1",
						},
					},
				},
			},
		},
	}

	err := o.applyHeartbeatReceived(ctx, event)
	require.Error(t, err)
}

func Test_applyHeartbeatReceived_ConfirmedRevertedHandleEventError(t *testing.T) {
	ctx := context.Background()
	txID := uuid.New()

	mockTxn := originatortransactionmocks.NewOriginatorTransaction(t)
	mockTxn.On("GetID").Return(txID)
	mockTxn.On("GetCurrentState").Return(transaction.State_Submitted).Maybe()
	mockTxn.On("HandleEvent", mock.Anything, mock.MatchedBy(func(e transaction.Event) bool {
		_, ok := e.(*transaction.ConfirmedRevertedEvent)
		return ok
	})).Return(fmt.Errorf("revert handle error"))

	o, _ := NewOriginatorBuilderForTesting(t, State_Observing).
		NodeName("member1@node1").
		CurrentActiveCoordinator("coordinator@node1").
		Transactions(mockTxn).
		Build()

	contractAddress := *pldtypes.RandAddress()
	event := &common.HeartbeatReceivedEvent{
		From:            "coordinator@node1",
		ContractAddress: &contractAddress,
		CoordinatorSnapshot: &common.CoordinatorSnapshot{
			ConfirmedTransactions: []*common.SnapshotConfirmedTransaction{
				{
					SnapshotDispatchedTransaction: common.SnapshotDispatchedTransaction{
						SnapshotPooledTransaction: common.SnapshotPooledTransaction{
							ID:         txID,
							Originator: "member1@node1",
						},
					},
					RevertReason: pldtypes.HexBytes("out of gas"),
				},
			},
		},
	}

	err := o.applyHeartbeatReceived(ctx, event)
	require.Error(t, err)
}

func Test_applyHeartbeatReceived_NonActiveCoordinator_Ignored(t *testing.T) {
	// Heartbeat from a node that is neither the active coordinator nor the previous coordinator
	// should be silently ignored (lines 92-95 in observing.go).
	ctx := context.Background()

	o, _ := NewOriginatorBuilderForTesting(t, State_Observing).
		NodeName("member1@node1").
		CurrentActiveCoordinator("coordinator@node1").
		Build()

	contractAddress := *pldtypes.RandAddress()
	event := &common.HeartbeatReceivedEvent{
		From:                "some-other@node3",
		ContractAddress:     &contractAddress,
		CoordinatorSnapshot: &common.CoordinatorSnapshot{},
	}

	err := o.applyHeartbeatReceived(ctx, event)
	require.NoError(t, err)
	assert.False(t, o.needsRedelegate)
}

func Test_applyHeartbeatReceived_WatchingPrevious_PreClosing_ResetsCounter(t *testing.T) {
	// watchingPreviousCoordinatorFlush=true, heartbeat from previous coordinator, NOT closing:
	// reset heartbeatIntervalsSinceLastReceive but do NOT set needsRedelegate.
	ctx := context.Background()
	o, _ := NewOriginatorBuilderForTesting(t, State_Observing).
		NodeName("member1@node1").
		CurrentActiveCoordinator("new-coordinator@node2").
		PreviousActiveCoordinatorNode("old-coordinator@node1").
		WatchingPreviousCoordinatorFlush(true).
		Build()

	o.heartbeatIntervalsSinceLastReceive = 5

	contractAddress := *pldtypes.RandAddress()
	event := &common.HeartbeatReceivedEvent{
		From:            "old-coordinator@node1",
		ContractAddress: &contractAddress,
		CoordinatorSnapshot: &common.CoordinatorSnapshot{
			CoordinatorState: common.CoordinatorState_Active,
		},
	}

	err := o.applyHeartbeatReceived(ctx, event)
	require.NoError(t, err)

	assert.Equal(t, 0, o.heartbeatIntervalsSinceLastReceive)
	assert.False(t, o.needsRedelegate)
	assert.True(t, o.watchingPreviousCoordinatorFlush)
}

func Test_applyHeartbeatReceived_WatchingPrevious_ClosingHeartbeat_Redelegates(t *testing.T) {
	// watchingPreviousCoordinatorFlush=true, heartbeat from previous coordinator, IS closing:
	// stop watching and set needsRedelegate.
	ctx := context.Background()
	o, _ := NewOriginatorBuilderForTesting(t, State_Observing).
		NodeName("member1@node1").
		CurrentActiveCoordinator("new-coordinator@node2").
		PreviousActiveCoordinatorNode("old-coordinator@node1").
		WatchingPreviousCoordinatorFlush(true).
		Build()

	contractAddress := *pldtypes.RandAddress()
	event := &common.HeartbeatReceivedEvent{
		From:            "old-coordinator@node1",
		ContractAddress: &contractAddress,
		CoordinatorSnapshot: &common.CoordinatorSnapshot{
			CoordinatorState: common.CoordinatorState_Closing,
		},
	}

	err := o.applyHeartbeatReceived(ctx, event)
	require.NoError(t, err)

	assert.False(t, o.watchingPreviousCoordinatorFlush)
	assert.True(t, o.needsRedelegate)
}

func Test_applyHeartbeatReceived_WatchingPrevious_ActiveCoordinatorHeartbeat_Redelegates(t *testing.T) {
	// watchingPreviousCoordinatorFlush=true but heartbeat is from the NEW active coordinator:
	// exit watching state and set needsRedelegate.
	ctx := context.Background()
	o, _ := NewOriginatorBuilderForTesting(t, State_Observing).
		NodeName("member1@node1").
		CurrentActiveCoordinator("new-coordinator@node2").
		PreviousActiveCoordinatorNode("old-coordinator@node1").
		WatchingPreviousCoordinatorFlush(true).
		Build()

	contractAddress := *pldtypes.RandAddress()
	event := &common.HeartbeatReceivedEvent{
		From:                "new-coordinator@node2",
		ContractAddress:     &contractAddress,
		CoordinatorSnapshot: &common.CoordinatorSnapshot{},
	}

	err := o.applyHeartbeatReceived(ctx, event)
	require.NoError(t, err)

	assert.False(t, o.watchingPreviousCoordinatorFlush)
	assert.True(t, o.needsRedelegate)
}

func Test_applyHeartbeatReceived_DroppedTransaction_SetsNeedsRedelegate(t *testing.T) {
	// A transaction present in memory but absent from the coordinator snapshot triggers redelegate.
	ctx := context.Background()
	txID := uuid.New()

	mockTxn := originatortransactionmocks.NewOriginatorTransaction(t)
	mockTxn.On("GetID").Return(txID)
	mockTxn.On("GetCurrentState").Return(transaction.State_Delegated)

	o, _ := NewOriginatorBuilderForTesting(t, State_Observing).
		NodeName("member1@node1").
		CurrentActiveCoordinator("coordinator@node1").
		Transactions(mockTxn).
		Build()

	contractAddress := *pldtypes.RandAddress()
	event := &common.HeartbeatReceivedEvent{
		From:                "coordinator@node1",
		ContractAddress:     &contractAddress,
		CoordinatorSnapshot: &common.CoordinatorSnapshot{},
	}

	err := o.applyHeartbeatReceived(ctx, event)
	require.NoError(t, err)
	assert.True(t, o.needsRedelegate)
}
