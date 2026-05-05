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

	"github.com/LFDT-Paladin/paladin/core/internal/sequencer/common"
	"github.com/LFDT-Paladin/paladin/core/internal/sequencer/originator/transaction"
	"github.com/LFDT-Paladin/paladin/core/internal/sequencer/statemachine"
	"github.com/LFDT-Paladin/paladin/core/internal/sequencer/testutil"
	"github.com/LFDT-Paladin/paladin/sdk/go/pkg/pldtypes"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	mock "github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

func TestOriginator_SingleTransactionLifecycle(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	originatorLocator := "sender@senderNode"
	coordinatorLocator := "coordinator@coordinatorNode"
	builder := NewOriginatorBuilderForTesting(State_Idle)
	o, mocks := builder.Build()
	require.NoError(t, o.Start(ctx))
	defer func() {
		cancel()
		o.WaitForDone(t.Context())
	}()
	// Ensure the originator is in observing mode by queuing a heartbeat from an active coordinator
	contractAddress := builder.GetContractAddress()
	heartbeatEvent := &common.HeartbeatReceivedEvent{
		From:                coordinatorLocator,
		ContractAddress:     &contractAddress,
		CoordinatorSnapshot: &common.CoordinatorSnapshot{},
	}
	o.QueueEvent(ctx, heartbeatEvent)
	sync := statemachine.NewSyncEvent()
	o.QueueEvent(ctx, sync)
	<-sync.Done
	require.Equal(t, State_Observing, o.GetCurrentState(), "Originator should transition to Observing")
	// Start by creating a transaction with the originator
	transactionBuilder := testutil.NewPrivateTransactionBuilderForTesting().Address(builder.GetContractAddress()).Originator(originatorLocator).NumberOfRequiredEndorsers(1)
	txn := transactionBuilder.BuildSparse()
	postAssembly, postAssemblyHash := transactionBuilder.BuildPostAssemblyAndHash()
	mocks.EngineIntegration.On(
		"AssembleAndSign",
		mock.Anything,
		mock.Anything,
		mock.Anything,
		mock.Anything,
		mock.Anything,
	).Return(postAssembly, nil)
	// Queue TransactionCreated and the coordinator's assemble request together
	o.QueueEvent(ctx, &TransactionCreatedEvent{Transaction: txn})
	// Simulate the coordinator sending an assemble request
	assembleRequestIdempotencyKey := uuid.New()
	o.QueueEvent(ctx, &transaction.AssembleRequestReceivedEvent{
		BaseEvent: transaction.BaseEvent{TransactionID: txn.ID},
		RequestID: assembleRequestIdempotencyKey, Coordinator: coordinatorLocator,
		CoordinatorsBlockHeight: 1000, StateLocksJSON: []byte("{}"),
	})
	sync = statemachine.NewSyncEvent()
	o.QueueEvent(ctx, sync)
	<-sync.Done
	assert.True(t, mocks.SentMessageRecorder.HasSentDelegationRequest(), "Delegation request should be sent")
	// Assert that the transaction was assembled and a response sent
	require.True(t, mocks.SentMessageRecorder.HasSentAssembleSuccessResponse(), "Assemble success response should be sent")
	// Simulate the coordinator sending a dispatch confirmation
	o.QueueEvent(ctx, &transaction.PreDispatchRequestReceivedEvent{
		BaseEvent: transaction.BaseEvent{TransactionID: txn.ID},
		RequestID: assembleRequestIdempotencyKey, Coordinator: coordinatorLocator, PostAssemblyHash: postAssemblyHash,
	})
	sync = statemachine.NewSyncEvent()
	o.QueueEvent(ctx, sync)
	<-sync.Done
	// Assert that a dispatch confirmation was returned
	require.True(t, mocks.SentMessageRecorder.HasSentPreDispatchResponse(), "Pre-dispatch response should be sent")
	// Simulate the coordinator having dispatched the transaction (Prepared → Dispatched) so the
	// following heartbeat with LatestSubmissionHash is accepted (State_Dispatched handles Event_Submitted).
	signerAddress := pldtypes.RandAddress()
	o.QueueEvent(ctx, &transaction.DispatchedEvent{
		BaseEvent:     transaction.BaseEvent{TransactionID: txn.ID},
		SignerAddress: *signerAddress,
	})
	// Simulate the coordinator sending a heartbeat after the transaction was submitted
	submissionHash := pldtypes.RandBytes32()
	nonce := uint64(42)
	// Originator must match the originator's nodeName so the heartbeat is applied
	// (builder defaults nodeName to "member1@node1").
	heartbeatEvent.CoordinatorSnapshot = &common.CoordinatorSnapshot{
		DispatchedTransactions: []*common.SnapshotDispatchedTransaction{
			{
				SnapshotPooledTransaction: common.SnapshotPooledTransaction{
					ID:         txn.ID,
					Originator: "member1@node1",
				},
				Signer:               *signerAddress,
				SignerLocator:        "signer@node2",
				Nonce:                &nonce,
				LatestSubmissionHash: &submissionHash,
			},
		},
	}
	o.QueueEvent(ctx, heartbeatEvent)
	// Simulate the block indexer confirming the transaction
	o.QueueEvent(ctx, &transaction.ConfirmedSuccessEvent{
		BaseEvent: transaction.BaseEvent{
			TransactionID: txn.ID,
		},
	})
	// After confirmation: the transaction state machine transitions Submitted → Confirmed → Final,
	// and the originator removes the transaction from memory (removeTransaction). With no
	// unconfirmed transactions left, the originator transitions back to State_Observing.
	sync = statemachine.NewSyncEvent()
	o.QueueEvent(ctx, sync)
	<-sync.Done
	require.Nil(t, o.transactionsByID[txn.ID], "Transaction should be cleaned up from transactionsByID after confirmation")
	require.Equal(t, State_Observing, o.GetCurrentState(), "Originator should transition to Observing when all transactions are confirmed")
}
func Test_propagateEventToTransaction_UnknownTransaction_AssembleRequestSendsUnknown(t *testing.T) {
	ctx := context.Background()
	coordinatorLocator := "coordinator@coordinatorNode"
	builder := NewOriginatorBuilderForTesting(State_Observing)
	o, mocks := builder.Build()
	// Create a transaction event with a transaction ID that doesn't exist in the originator
	unknownTxID := uuid.New()
	assembleRequestIdempotencyKey := uuid.New()
	event := &transaction.AssembleRequestReceivedEvent{
		BaseEvent: transaction.BaseEvent{
			TransactionID: unknownTxID,
		},
		RequestID:               assembleRequestIdempotencyKey,
		Coordinator:             coordinatorLocator,
		CoordinatorsBlockHeight: 1000,
		StateLocksJSON:          []byte("{}"),
	}
	require.NoError(t, o.stateMachineEventLoop.ProcessEvent(ctx, event))
	// State machine should call propagateEventToTransaction, which should send a TransactionUnknown response
	assert.True(t, mocks.SentMessageRecorder.HasSentTransactionUnknown(), "SendTransactionUnknown should be called")
	txID, coordinator := mocks.SentMessageRecorder.GetTransactionUnknownDetails()
	assert.Equal(t, unknownTxID, txID, "TransactionUnknown should be sent for the correct transaction ID")
	assert.Equal(t, coordinatorLocator, coordinator, "TransactionUnknown should be sent to the correct coordinator")
}
func Test_propagateEventToTransaction_UnknownTransaction_NonRequestEventReturnsNil(t *testing.T) {
	ctx := context.Background()
	builder := NewOriginatorBuilderForTesting(State_Observing)
	o, mocks := builder.Build()
	// Create a ConfirmedSuccessEvent for an unknown transaction
	unknownTxID := uuid.New()
	event := &transaction.ConfirmedSuccessEvent{
		BaseEvent: transaction.BaseEvent{
			TransactionID: unknownTxID,
		},
	}
	require.NoError(t, o.stateMachineEventLoop.ProcessEvent(ctx, event))
	// Verify that SendTransactionUnknown was NOT called
	assert.False(t, mocks.SentMessageRecorder.HasSentTransactionUnknown(), "Expected SendTransactionUnknown to NOT be called for confirmation events")
}
func TestOriginator_CreateTransaction_ErrorFromNewTransaction(t *testing.T) {
	ctx := context.Background()
	builder := NewOriginatorBuilderForTesting(State_Observing)
	o, mocks := builder.Build()
	// Nil transaction triggers a handled error; state should remain Observing
	_ = o.stateMachineEventLoop.ProcessEvent(ctx, &TransactionCreatedEvent{Transaction: nil})
	assert.True(t, o.GetCurrentState() == State_Observing, "State should remain Observing after nil transaction event")
	assert.False(t, mocks.SentMessageRecorder.HasSentDelegationRequest(), "No delegation should be sent for nil transaction")
}
func TestOriginator_EventLoop_ErrorHandling(t *testing.T) {
	ctx := context.Background()
	originatorLocator := "sender@senderNode"
	builder := NewOriginatorBuilderForTesting(State_Observing)
	o, mocks := builder.Build()
	// Process a TransactionCreatedEvent with a nil transaction to trigger an error
	_ = o.stateMachineEventLoop.ProcessEvent(ctx, &TransactionCreatedEvent{Transaction: nil})
	transactionBuilder := testutil.NewPrivateTransactionBuilderForTesting().Address(builder.GetContractAddress()).Originator(originatorLocator).NumberOfRequiredEndorsers(1)
	txn := transactionBuilder.BuildSparse()
	validEvent := &TransactionCreatedEvent{
		Transaction: txn,
	}
	// Process a valid event to verify the originator is still working
	require.NoError(t, o.stateMachineEventLoop.ProcessEvent(ctx, validEvent))
	assert.True(t, mocks.SentMessageRecorder.HasSentDelegationRequest(), "Originator should still process valid event after error")
}
func Test_getTransactionsInStates_ReturnsOnlyTransactionsWhoseStateIsListed(t *testing.T) {
	tbPending := transaction.NewTransactionBuilderForTesting(t, transaction.State_Pending)
	tbDelegated := transaction.NewTransactionBuilderForTesting(t, transaction.State_Delegated)
	tbAssembling := transaction.NewTransactionBuilderForTesting(t, transaction.State_Assembling)
	builder := NewOriginatorBuilderForTesting(State_Sending).
		TransactionBuilders(tbPending, tbDelegated, tbAssembling)
	o, _ := builder.Build()
	matching := o.getTransactionsInStates([]transaction.State{transaction.State_Pending, transaction.State_Delegated})
	require.Len(t, matching, 2)
	byID := make(map[uuid.UUID]transaction.State)
	for _, txn := range matching {
		byID[txn.GetID()] = txn.GetCurrentState()
	}
	assert.Equal(t, transaction.State_Pending, byID[tbPending.GetBuiltTransaction().GetID()])
	assert.Equal(t, transaction.State_Delegated, byID[tbDelegated.GetBuiltTransaction().GetID()])
}
func Test_getTransactionsInStates_EmptyStateListReturnsNoTransactions(t *testing.T) {
	tb := transaction.NewTransactionBuilderForTesting(t, transaction.State_Pending)
	builder := NewOriginatorBuilderForTesting(State_Sending).
		TransactionBuilders(tb)
	o, _ := builder.Build()
	assert.Empty(t, o.getTransactionsInStates(nil))
	assert.Empty(t, o.getTransactionsInStates([]transaction.State{}))
}
func Test_propagateEventToTransaction_UnknownTransaction_PreDispatchRequestSendsUnknown(t *testing.T) {
	ctx := context.Background()
	coordinatorLocator := "coordinator@coordinatorNode"
	builder := NewOriginatorBuilderForTesting(State_Observing)
	o, mocks := builder.Build()
	unknownTxID := uuid.New()
	postAssemblyHash := pldtypes.RandBytes32()
	event := &transaction.PreDispatchRequestReceivedEvent{
		BaseEvent:        transaction.BaseEvent{TransactionID: unknownTxID},
		Coordinator:      coordinatorLocator,
		PostAssemblyHash: &postAssemblyHash,
	}
	require.NoError(t, o.stateMachineEventLoop.ProcessEvent(ctx, event))
	assert.True(t, mocks.SentMessageRecorder.HasSentTransactionUnknown(), "SendTransactionUnknown should be called")
	txID, coordinator := mocks.SentMessageRecorder.GetTransactionUnknownDetails()
	assert.Equal(t, unknownTxID, txID)
	assert.Equal(t, coordinatorLocator, coordinator)
}

// State machine spec tests (moved from spec/originator_test.go)

func TestStateMachine_InitializeOK(t *testing.T) {
	o, _ := NewOriginatorBuilderForTesting(State_Idle).Build()
	assert.Equal(t, State_Idle, o.GetCurrentState(), "current state is %s", o.GetCurrentState().String())
}

func TestStateMachine_Idle_ToObserving_OnHeartbeatReceived(t *testing.T) {
	ctx := context.Background()
	builder := NewOriginatorBuilderForTesting(State_Idle)
	o, _ := builder.Build()
	assert.Equal(t, State_Idle, o.GetCurrentState())
	ca := builder.GetContractAddress()
	heartbeatEvent := &common.HeartbeatReceivedEvent{}
	heartbeatEvent.From = "coordinator"
	heartbeatEvent.ContractAddress = &ca
	heartbeatEvent.CoordinatorSnapshot = &common.CoordinatorSnapshot{}
	require.NoError(t, o.stateMachineEventLoop.ProcessEvent(ctx, heartbeatEvent))
	assert.Equal(t, State_Observing, o.GetCurrentState(), "current state is %s", o.GetCurrentState().String())
}

func TestStateMachine_Idle_ToSending_OnTransactionCreated(t *testing.T) {
	ctx := context.Background()
	builder := NewOriginatorBuilderForTesting(State_Idle)
	o, mocks := builder.Build()
	assert.Equal(t, State_Idle, o.GetCurrentState())
	txn := testutil.NewPrivateTransactionBuilderForTesting().Address(builder.GetContractAddress()).Originator("sender@node1").Build()
	require.NoError(t, o.stateMachineEventLoop.ProcessEvent(ctx, &TransactionCreatedEvent{Transaction: txn}))
	assert.Equal(t, State_Sending, o.GetCurrentState(), "current state is %s", o.GetCurrentState().String())
	assert.True(t, mocks.SentMessageRecorder.HasSentDelegationRequest(), "Delegation request should be sent")
}

func TestStateMachine_Observing_ToSending_OnTransactionCreated(t *testing.T) {
	ctx := context.Background()
	builder := NewOriginatorBuilderForTesting(State_Observing)
	o, mocks := builder.Build()
	txn := testutil.NewPrivateTransactionBuilderForTesting().Address(builder.GetContractAddress()).Originator("sender@node1").Build()
	require.NoError(t, o.stateMachineEventLoop.ProcessEvent(ctx, &TransactionCreatedEvent{Transaction: txn}))
	assert.Equal(t, State_Sending, o.GetCurrentState(), "current state is %s", o.GetCurrentState().String())
	assert.True(t, mocks.SentMessageRecorder.HasSentDelegationRequest(), "Delegation request should be sent")
}

func TestStateMachine_Sending_NoTransition_OnTransactionConfirmed_IfHasTransactionsInflight(t *testing.T) {
	ctx := context.Background()
	txn1Builder := transaction.NewTransactionBuilderForTesting(t, transaction.State_Submitted)
	txn2Builder := transaction.NewTransactionBuilderForTesting(t, transaction.State_Submitted)
	o, _ := NewOriginatorBuilderForTesting(State_Sending).
		TransactionBuilders(txn1Builder, txn2Builder).
		Build()
	txn1 := txn1Builder.GetBuiltTransaction()
	txn2 := txn2Builder.GetBuiltTransaction()
	require.NotNil(t, txn1)
	require.NotNil(t, txn2)
	require.NoError(t, o.stateMachineEventLoop.ProcessEvent(ctx, &transaction.ConfirmedSuccessEvent{
		BaseEvent: transaction.BaseEvent{TransactionID: txn1.GetID()},
	}))
	assert.Equal(t, State_Sending, o.GetCurrentState(), "current state is %s", o.GetCurrentState().String())
}

func TestStateMachine_Sending_DoDelegateTransactions_OnHeartbeatReceived_IfHasDroppedTransaction(t *testing.T) {
	ctx := context.Background()
	coordinatorLocator := "coordinator@node1"
	txn1Builder := transaction.NewTransactionBuilderForTesting(t, transaction.State_Delegated)
	txn2Builder := transaction.NewTransactionBuilderForTesting(t, transaction.State_Delegated)
	builder := NewOriginatorBuilderForTesting(State_Sending).
		TransactionBuilders(txn1Builder, txn2Builder)
	o, mocks := builder.Build()
	txn1 := txn1Builder.GetBuiltTransaction()
	require.NotNil(t, txn1)
	// Send heartbeat with only txn1 in the snapshot — txn2 is "dropped"
	ca := builder.GetContractAddress()
	heartbeatEvent := &common.HeartbeatReceivedEvent{
		From:            coordinatorLocator,
		ContractAddress: &ca,
		CoordinatorSnapshot: &common.CoordinatorSnapshot{
			PooledTransactions: []*common.SnapshotPooledTransaction{
				{ID: txn1.GetID(), Originator: "sender@node1"},
			},
		},
	}
	require.NoError(t, o.stateMachineEventLoop.ProcessEvent(ctx, heartbeatEvent))
	assert.True(t, mocks.SentMessageRecorder.HasSentDelegationRequest(), "Delegation request should be sent after heartbeat")
}
