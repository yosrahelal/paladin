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

package coordinator

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/LFDT-Paladin/paladin/config/pkg/confutil"
	"github.com/LFDT-Paladin/paladin/core/internal/components"
	"github.com/LFDT-Paladin/paladin/core/internal/sequencer/common"
	"github.com/LFDT-Paladin/paladin/core/internal/sequencer/coordinator/transaction"
	"github.com/LFDT-Paladin/paladin/core/internal/sequencer/syncpoints"
	"github.com/LFDT-Paladin/paladin/core/internal/sequencer/testutil"
	"github.com/LFDT-Paladin/paladin/core/internal/sequencer/transport"
	"github.com/LFDT-Paladin/paladin/core/mocks/componentsmocks"
	"github.com/LFDT-Paladin/paladin/core/mocks/coordinatortransactionmocks"
	"github.com/LFDT-Paladin/paladin/core/mocks/graphermocks"
	"github.com/LFDT-Paladin/paladin/sdk/go/pkg/pldapi"
	"github.com/LFDT-Paladin/paladin/sdk/go/pkg/pldtypes"
	"github.com/LFDT-Paladin/paladin/toolkit/pkg/prototk"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	mock "github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
)

func TestCoordinator_SingleTransactionLifecycle(t *testing.T) {
	// Test the progression of a single transaction through the coordinator's lifecycle
	// Simulating originator node, endorser node and the public transaction manager (submitter)
	// by inspecting the coordinator output messages and by sending events that would normally be triggered by those components sending messages to the coordinator.
	// At each stage, we inspect the state of the coordinator by checking the snapshot it produces on heartbeat messages

	originator := "sender@senderNode"
	builder := NewCoordinatorBuilderForTesting(t, State_Idle)
	mockDomain := componentsmocks.NewDomain(t)
	mockDomain.On("FixedSigningIdentity").Return("")
	builder.GetDomainAPI().On("Domain").Return(mockDomain)
	builder.GetDomainAPI().On("ContractConfig").Return(&prototk.ContractConfig{
		CoordinatorSelection: prototk.ContractConfig_COORDINATOR_SENDER,
	})
	builder.GetDomainAPI().On("PrepareTransaction", mock.Anything, mock.Anything, mock.Anything).Run(func(args mock.Arguments) {
		tx := args.Get(2).(*components.PrivateTransaction)
		tx.PreparedPrivateTransaction = &pldapi.TransactionInput{}
	}).Return(nil).Once()
	builder.GetSequencerManager().On("BuildNullifiers", mock.Anything, mock.Anything).Return(nil, nil).Once()
	config := builder.GetSequencerConfig()
	config.MaxDispatchAhead = confutil.P(-1) // Stop the dispatcher loop from progressing states - we're manually updating state throughout the test
	builder.OverrideSequencerConfig(config)
	builder.ActiveCoordinatorNode("node1")
	c, mocks := builder.Build()
	ctx, cancel := context.WithCancel(t.Context())
	require.NoError(t, c.Start(ctx))
	defer func() {
		cancel()
		c.WaitForDone(t.Context())
	}()
	mocks.SyncPoints.(*syncpoints.MockSyncPoints).On("PersistDispatchBatch", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(nil).Once()

	// Start by simulating the originator and delegate a transaction to the coordinator
	transactionBuilder := testutil.NewPrivateTransactionBuilderForTesting().
		Address(builder.GetContractAddress()).
		Originator(originator).
		NumberOfRequiredEndorsers(1).
		PreAssembly(&components.TransactionPreAssembly{
			TransactionSpecification: &prototk.TransactionSpecification{
				From:   originator,
				Intent: prototk.TransactionSpecification_PREPARE_TRANSACTION,
			},
		})
	txn := transactionBuilder.BuildSparse()
	c.QueueEvent(ctx, &TransactionsDelegatedEvent{
		FromNode:     "testNode",
		Originator:   originator,
		Transactions: []*components.PrivateTransaction{txn},
	})

	var snapshot *common.CoordinatorSnapshot

	// Assert that snapshot contains a transaction with matching ID
	require.Eventually(t, func() bool {
		snapshot = c.getSnapshot(ctx)
		return snapshot != nil && len(snapshot.PooledTransactions) == 1
	}, 100*time.Millisecond, 1*time.Millisecond, "Snapshot should contain one pooled transaction")

	assert.Equal(t, txn.ID.String(), snapshot.PooledTransactions[0].ID.String(), "Snapshot should contain the pooled transaction with ID %s", txn.ID.String())

	// Assert that a request has been sent to the originator and respond with an assembled transaction
	assert.Eventually(t, func() bool {
		return mocks.SentMessageRecorder.HasSentAssembleRequest()
	}, 100*time.Millisecond, 1*time.Millisecond, "Assemble request should be sent")
	c.QueueEvent(ctx, &transaction.AssembleSuccessEvent{
		BaseCoordinatorEvent: transaction.BaseCoordinatorEvent{
			TransactionID: txn.ID,
		},
		RequestID:    mocks.SentMessageRecorder.SentAssembleRequestIdempotencyKey(),
		PostAssembly: transactionBuilder.BuildPostAssembly(),
		PreAssembly:  transactionBuilder.BuildPreAssembly(),
	})

	// Assert that the coordinator has sent an endorsement request to the endorser
	assert.Eventually(t, func() bool {
		return mocks.SentMessageRecorder.NumberOfSentEndorsementRequests() == 1
	}, 100*time.Millisecond, 1*time.Millisecond, "Endorsement request should be sent")

	// Assert that snapshot still contains the same single transaction in the pooled transactions
	snapshot = c.getSnapshot(ctx)
	require.NotNil(t, snapshot)
	require.Equal(t, 1, len(snapshot.PooledTransactions))
	assert.Equal(t, txn.ID.String(), snapshot.PooledTransactions[0].ID.String(), "Snapshot should contain the pooled transaction with ID %s", txn.ID.String())

	// now respond with an endorsement
	c.QueueEvent(ctx, &transaction.EndorsedEvent{
		BaseCoordinatorEvent: transaction.BaseCoordinatorEvent{
			TransactionID: txn.ID,
		},
		RequestID:   mocks.SentMessageRecorder.SentEndorsementRequestsForPartyIdempotencyKey(transactionBuilder.GetEndorserIdentityLocator(0)),
		Endorsement: transactionBuilder.BuildEndorsement(0),
	})

	// Assert that the coordinator has sent a dispatch confirmation request to the transaction sender
	assert.Eventually(t, func() bool {
		return mocks.SentMessageRecorder.HasSentDispatchConfirmationRequest()
	}, 100*time.Millisecond, 1*time.Millisecond, "Dispatch confirmation request should be sent")

	// Assert that snapshot still contains the same single transaction in the pooled transactions
	snapshot = c.getSnapshot(ctx)
	require.NotNil(t, snapshot)
	require.Equal(t, 1, len(snapshot.PooledTransactions))
	assert.Equal(t, txn.ID.String(), snapshot.PooledTransactions[0].ID.String(), "Snapshot should contain the pooled transaction with ID %s", txn.ID.String())

	// now respond with a dispatch confirmation
	c.QueueEvent(ctx, &transaction.DispatchRequestApprovedEvent{
		BaseCoordinatorEvent: transaction.BaseCoordinatorEvent{
			TransactionID: txn.ID,
		},
		RequestID: mocks.SentMessageRecorder.SentDispatchConfirmationRequestIdempotencyKey(),
	})

	// Assert that the transaction is ready to be collected by the dispatcher thread
	assert.Eventually(t, func() bool {
		readyTransactions := c.getTransactionsInStates(ctx, []transaction.State{transaction.State_Ready_For_Dispatch})
		return len(readyTransactions) == 1 &&
			readyTransactions[0].GetID().String() == txn.ID.String()
	}, 100*time.Millisecond, 1*time.Millisecond, "There should be exactly one transaction ready to dispatch")

	// Assert that snapshot no longer contains that transaction in the pooled transactions but does contain it in the dispatched transactions
	//NOTE: This is a key design point.  When a transaction is ready to be dispatched, we communicate to other nodes, via the heartbeat snapshot, that the transaction is dispatched.
	assert.Eventually(t, func() bool {
		snapshot := c.getSnapshot(ctx)
		return snapshot != nil &&
			len(snapshot.PooledTransactions) == 0 &&
			len(snapshot.DispatchedTransactions) == 1 &&
			snapshot.DispatchedTransactions[0].ID.String() == txn.ID.String()
	}, 100*time.Millisecond, 1*time.Millisecond, "Snapshot should contain exactly one dispatched transaction")

	// Simulate the dispatcher thread collecting the transaction and dispatching it to a public transaction manager
	c.QueueEvent(ctx, &transaction.DispatchedEvent{
		BaseCoordinatorEvent: transaction.BaseCoordinatorEvent{
			TransactionID: txn.ID,
		},
	})

	// Simulate the public transaction manager collecting the dispatched transaction and associating a signing address with it
	signerAddress := pldtypes.RandAddress()
	c.QueueEvent(ctx, &transaction.CollectedEvent{
		BaseCoordinatorEvent: transaction.BaseCoordinatorEvent{
			TransactionID: txn.ID,
		},
		SignerAddress: *signerAddress,
	})

	// Assert that we now have a signer address in the snapshot
	assert.Eventually(t, func() bool {
		snapshot := c.getSnapshot(ctx)
		return snapshot != nil &&
			len(snapshot.PooledTransactions) == 0 &&
			len(snapshot.DispatchedTransactions) == 1 &&
			snapshot.DispatchedTransactions[0].ID.String() == txn.ID.String() &&
			snapshot.DispatchedTransactions[0].Signer.String() == signerAddress.String()
	}, 100*time.Millisecond, 1*time.Millisecond, "Snapshot should contain dispatched transaction with signer address")

	// Simulate the dispatcher thread allocating a nonce for the transaction
	c.QueueEvent(ctx, &transaction.NonceAllocatedEvent{
		BaseCoordinatorEvent: transaction.BaseCoordinatorEvent{
			TransactionID: txn.ID,
		},
		Nonce: 42,
	})

	// Assert that the nonce is now included in the snapshot
	assert.Eventually(t, func() bool {
		snapshot := c.getSnapshot(ctx)
		return snapshot != nil &&
			len(snapshot.PooledTransactions) == 0 &&
			len(snapshot.DispatchedTransactions) == 1 &&
			snapshot.DispatchedTransactions[0].ID.String() == txn.ID.String() &&
			snapshot.DispatchedTransactions[0].Nonce != nil &&
			*snapshot.DispatchedTransactions[0].Nonce == uint64(42)
	}, 100*time.Millisecond, 1*time.Millisecond, "Snapshot should contain dispatched transaction with nonce 42")

	// Simulate the public transaction manager submitting the transaction
	submissionHash := pldtypes.Bytes32(pldtypes.RandBytes(32))
	c.QueueEvent(ctx, &transaction.SubmittedEvent{
		BaseCoordinatorEvent: transaction.BaseCoordinatorEvent{
			TransactionID: txn.ID,
		},
		SubmissionHash: submissionHash,
	})

	// Assert that the hash is now included in the snapshot
	assert.Eventually(t, func() bool {
		snapshot := c.getSnapshot(ctx)
		return snapshot != nil &&
			len(snapshot.PooledTransactions) == 0 &&
			len(snapshot.DispatchedTransactions) == 1 &&
			snapshot.DispatchedTransactions[0].ID.String() == txn.ID.String() &&
			snapshot.DispatchedTransactions[0].LatestSubmissionHash != nil &&
			*snapshot.DispatchedTransactions[0].LatestSubmissionHash == submissionHash
	}, 100*time.Millisecond, 1*time.Millisecond, "Snapshot should contain dispatched transaction with a submission hash")

	// Simulate the block indexer confirming the transaction
	nonce42 := pldtypes.HexUint64(42)
	c.QueueEvent(ctx, &transaction.ConfirmedSuccessEvent{
		BaseCoordinatorEvent: transaction.BaseCoordinatorEvent{
			TransactionID: txn.ID,
		},
		Nonce: &nonce42,
		Hash:  submissionHash,
	})

	// Assert that snapshot contains a confirmed transaction with matching ID
	assert.Eventually(t, func() bool {
		snapshot := c.getSnapshot(ctx)
		return snapshot != nil &&
			len(snapshot.ConfirmedTransactions) == 1 &&
			snapshot.ConfirmedTransactions[0].ID.String() == txn.ID.String()
	}, 100*time.Millisecond, 1*time.Millisecond, "Snapshot should contain exactly one confirmed transaction")

}

func TestCoordinator_MaxInflightTransactions(t *testing.T) {
	ctx := t.Context()
	originator := "sender@senderNode"
	builder := NewCoordinatorBuilderForTesting(t, State_Idle)
	config := builder.GetSequencerConfig()
	config.MaxInflightTransactions = confutil.P(5)
	mockDomain := componentsmocks.NewDomain(t)
	mockDomain.On("FixedSigningIdentity").Return("")
	builder.GetDomainAPI().On("Domain").Return(mockDomain)
	builder.GetDomainAPI().On("ContractConfig").Return(&prototk.ContractConfig{
		CoordinatorSelection: prototk.ContractConfig_COORDINATOR_SENDER,
	})
	c, _ := builder.Build()

	// Start by simulating the originator and delegate a transaction to the coordinator
	for i := range 100 {
		transactionBuilder := testutil.NewPrivateTransactionBuilderForTesting().Address(builder.GetContractAddress()).Originator(originator).NumberOfRequiredEndorsers(1)
		txn := transactionBuilder.BuildSparse()
		err := c.addToDelegatedTransactions(ctx, originator, []*components.PrivateTransaction{txn}, "", c.newCoordinatorTransaction)

		if i < 5 {
			require.NoError(t, err)
		} else {
			require.Error(t, err)
			require.ErrorContains(t, err, "PD012642")
		}
	}
}

func TestCoordinator_GetTransactionsInStates_EmptyMapReturnsEmpty(t *testing.T) {
	ctx := t.Context()
	c, _ := NewCoordinatorBuilderForTesting(t, State_Idle).Build()

	result := c.getTransactionsInStates(ctx, []transaction.State{transaction.State_Ready_For_Dispatch})
	assert.Empty(t, result)
}

func TestCoordinator_GetTransactionsInStates_SingleStateFilter_ReturnsMatching(t *testing.T) {
	ctx := t.Context()
	txn, _ := transaction.NewTransactionBuilderForTesting(t, transaction.State_Ready_For_Dispatch).Build()
	c, _ := NewCoordinatorBuilderForTesting(t, State_Idle).Transactions(txn).Build()

	result := c.getTransactionsInStates(ctx, []transaction.State{transaction.State_Ready_For_Dispatch})
	require.Len(t, result, 1)
	assert.Equal(t, txn.GetID(), result[0].GetID())
	assert.Equal(t, transaction.State_Ready_For_Dispatch, result[0].GetCurrentState())
}

func TestCoordinator_GetTransactionsInStates_SingleStateFilter_ReturnsEmptyWhenNoMatch(t *testing.T) {
	ctx := t.Context()
	txn, _ := transaction.NewTransactionBuilderForTesting(t, transaction.State_Pooled).Build()
	c, _ := NewCoordinatorBuilderForTesting(t, State_Idle).Transactions(txn).Build()

	result := c.getTransactionsInStates(ctx, []transaction.State{transaction.State_Ready_For_Dispatch})
	assert.Empty(t, result)
}

func TestCoordinator_GetTransactionsInStates_MultipleStatesFilter_ReturnsAllMatching(t *testing.T) {
	ctx := t.Context()
	txReady, _ := transaction.NewTransactionBuilderForTesting(t, transaction.State_Ready_For_Dispatch).Build()
	txDispatched, _ := transaction.NewTransactionBuilderForTesting(t, transaction.State_Dispatched).Build()
	txPooled, _ := transaction.NewTransactionBuilderForTesting(t, transaction.State_Pooled).Build()
	c, _ := NewCoordinatorBuilderForTesting(t, State_Idle).Transactions(txReady, txDispatched, txPooled).Build()

	result := c.getTransactionsInStates(ctx, []transaction.State{
		transaction.State_Ready_For_Dispatch,
		transaction.State_Dispatched,
	})
	require.Len(t, result, 2)
	ids := make(map[uuid.UUID]bool)
	for _, txn := range result {
		ids[txn.GetID()] = true
		assert.Contains(t, []transaction.State{transaction.State_Ready_For_Dispatch, transaction.State_Dispatched}, txn.GetCurrentState())
	}
	assert.True(t, ids[txReady.GetID()])
	assert.True(t, ids[txDispatched.GetID()])
	assert.False(t, ids[txPooled.GetID()])
}

func TestCoordinator_GetTransactionsInStates_MultipleTransactionsInSameState(t *testing.T) {
	ctx := t.Context()
	tx1, _ := transaction.NewTransactionBuilderForTesting(t, transaction.State_Assembling).Build()
	tx2, _ := transaction.NewTransactionBuilderForTesting(t, transaction.State_Assembling).Build()
	tx3, _ := transaction.NewTransactionBuilderForTesting(t, transaction.State_Pooled).Build()
	c, _ := NewCoordinatorBuilderForTesting(t, State_Idle).Transactions(tx1, tx2, tx3).Build()

	result := c.getTransactionsInStates(ctx, []transaction.State{transaction.State_Assembling})
	require.Len(t, result, 2)
	ids := make(map[uuid.UUID]bool)
	for _, txn := range result {
		ids[txn.GetID()] = true
		assert.Equal(t, transaction.State_Assembling, txn.GetCurrentState())
	}
	assert.True(t, ids[tx1.GetID()])
	assert.True(t, ids[tx2.GetID()])
	assert.False(t, ids[tx3.GetID()])
}

func TestCoordinator_GetTransactionsInStates_EmptyStatesFilter_ReturnsEmpty(t *testing.T) {
	ctx := t.Context()
	txn, _ := transaction.NewTransactionBuilderForTesting(t, transaction.State_Ready_For_Dispatch).Build()
	c, _ := NewCoordinatorBuilderForTesting(t, State_Idle).Transactions(txn).Build()

	result := c.getTransactionsInStates(ctx, nil)
	assert.Empty(t, result)
	result = c.getTransactionsInStates(ctx, []transaction.State{})
	assert.Empty(t, result)
}

func TestCoordinator_GetTransactionsNotInStates_EmptyMapReturnsEmpty(t *testing.T) {
	ctx := t.Context()
	c, _ := NewCoordinatorBuilderForTesting(t, State_Idle).Build()

	result := c.getTransactionsNotInStates(ctx, []transaction.State{transaction.State_Ready_For_Dispatch})
	assert.Empty(t, result)
}

func TestCoordinator_GetTransactionsNotInStates_SingleStateFilter_ReturnsNonMatching(t *testing.T) {
	ctx := t.Context()
	txReady, _ := transaction.NewTransactionBuilderForTesting(t, transaction.State_Ready_For_Dispatch).Build()
	txPooled, _ := transaction.NewTransactionBuilderForTesting(t, transaction.State_Pooled).Build()
	c, _ := NewCoordinatorBuilderForTesting(t, State_Idle).Transactions(txReady, txPooled).Build()

	result := c.getTransactionsNotInStates(ctx, []transaction.State{transaction.State_Ready_For_Dispatch})
	require.Len(t, result, 1)
	assert.Equal(t, txPooled.GetID(), result[0].GetID())
	assert.Equal(t, transaction.State_Pooled, result[0].GetCurrentState())
}

func TestCoordinator_GetTransactionsNotInStates_SingleStateFilter_ReturnsAllWhenNoMatch(t *testing.T) {
	ctx := t.Context()
	txn, _ := transaction.NewTransactionBuilderForTesting(t, transaction.State_Pooled).Build()
	c, _ := NewCoordinatorBuilderForTesting(t, State_Idle).Transactions(txn).Build()

	result := c.getTransactionsNotInStates(ctx, []transaction.State{transaction.State_Ready_For_Dispatch})
	require.Len(t, result, 1)
	assert.Equal(t, txn.GetID(), result[0].GetID())
}

func TestCoordinator_GetTransactionsNotInStates_MultipleStatesFilter_ExcludesAllMatching(t *testing.T) {
	ctx := t.Context()
	txReady, _ := transaction.NewTransactionBuilderForTesting(t, transaction.State_Ready_For_Dispatch).Build()
	txDispatched, _ := transaction.NewTransactionBuilderForTesting(t, transaction.State_Dispatched).Build()
	txPooled, _ := transaction.NewTransactionBuilderForTesting(t, transaction.State_Pooled).Build()
	c, _ := NewCoordinatorBuilderForTesting(t, State_Idle).Transactions(txReady, txDispatched, txPooled).Build()

	result := c.getTransactionsNotInStates(ctx, []transaction.State{
		transaction.State_Ready_For_Dispatch,
		transaction.State_Dispatched,
	})
	require.Len(t, result, 1)
	assert.Equal(t, txPooled.GetID(), result[0].GetID())
}

func TestCoordinator_GetTransactionsNotInStates_MultipleTransactionsExcluded(t *testing.T) {
	ctx := t.Context()
	tx1, _ := transaction.NewTransactionBuilderForTesting(t, transaction.State_Assembling).Build()
	tx2, _ := transaction.NewTransactionBuilderForTesting(t, transaction.State_Assembling).Build()
	tx3, _ := transaction.NewTransactionBuilderForTesting(t, transaction.State_Pooled).Build()
	c, _ := NewCoordinatorBuilderForTesting(t, State_Idle).Transactions(tx1, tx2, tx3).Build()

	result := c.getTransactionsNotInStates(ctx, []transaction.State{transaction.State_Assembling})
	require.Len(t, result, 1)
	assert.Equal(t, tx3.GetID(), result[0].GetID())
	assert.Equal(t, transaction.State_Pooled, result[0].GetCurrentState())
}

func TestCoordinator_GetTransactionsNotInStates_EmptyStatesFilter_ReturnsAll(t *testing.T) {
	ctx := t.Context()
	txn, _ := transaction.NewTransactionBuilderForTesting(t, transaction.State_Ready_For_Dispatch).Build()
	c, _ := NewCoordinatorBuilderForTesting(t, State_Idle).Transactions(txn).Build()

	result := c.getTransactionsNotInStates(ctx, nil)
	require.Len(t, result, 1)
	result = c.getTransactionsNotInStates(ctx, []transaction.State{})
	require.Len(t, result, 1)
}

func TestCoordinator_NewCoordinator_EndorserMode_NoConfiguredCandidates_Fails(t *testing.T) {
	ctx := t.Context()
	builder := NewCoordinatorBuilderForTesting(t, State_Idle)
	builder.GetDomainAPI().On("ContractConfig").Return(&prototk.ContractConfig{
		CoordinatorSelection: prototk.ContractConfig_COORDINATOR_ENDORSER,
	})
	c, _ := builder.Build()
	assert.Error(t, c.Start(ctx))
}

func TestCoordinator_NewCoordinator_StaticMode_EmptyStaticCoordinator_Fails(t *testing.T) {
	ctx := t.Context()
	builder := NewCoordinatorBuilderForTesting(t, State_Idle)
	builder.GetDomainAPI().On("ContractConfig").Return(&prototk.ContractConfig{
		CoordinatorSelection: prototk.ContractConfig_COORDINATOR_STATIC,
		StaticCoordinator:    proto.String(""),
	})
	c, _ := builder.Build()
	assert.Error(t, c.Start(ctx))
}

func TestCoordinator_NewCoordinator_StaticMode_InvalidIdentity_Fails(t *testing.T) {
	ctx := t.Context()
	builder := NewCoordinatorBuilderForTesting(t, State_Idle)
	builder.GetDomainAPI().On("ContractConfig").Return(&prototk.ContractConfig{
		CoordinatorSelection: prototk.ContractConfig_COORDINATOR_STATIC,
		StaticCoordinator:    proto.String("identity"), // no @node
	})
	c, _ := builder.Build()
	assert.Error(t, c.Start(ctx))
}

func TestCoordinator_NewCoordinator_StaticMode_ValidStaticCoordinator_StoresNodeName(t *testing.T) {
	builder := NewCoordinatorBuilderForTesting(t, State_Idle)
	builder.GetDomainAPI().On("ContractConfig").Return(&prototk.ContractConfig{
		CoordinatorSelection: prototk.ContractConfig_COORDINATOR_STATIC,
		StaticCoordinator:    proto.String("identity@nodeA"),
	})
	c, _ := builder.Build()
	ctx, cancel := context.WithCancel(t.Context())
	require.NoError(t, c.Start(ctx))
	defer func() {
		cancel()
		c.WaitForDone(t.Context())
	}()
	assert.Equal(t, "nodeA", c.staticCoordinatorNode)
}

func TestCoordinator_NewCoordinator_EndorserMode_FailsOnInvalidConfiguredCandidate(t *testing.T) {
	ctx := t.Context()
	builder := NewCoordinatorBuilderForTesting(t, State_Idle)
	builder.GetDomainAPI().On("ContractConfig").Return(&prototk.ContractConfig{
		CoordinatorSelection:          prototk.ContractConfig_COORDINATOR_ENDORSER,
		CoordinatorEndorserCandidates: []string{"endorser1"},
	})
	c, _ := builder.Build()
	assert.Error(t, c.Start(ctx))
}

func TestCoordinator_NewCoordinator_EndorserMode_InitializesPoolFromConfiguredCandidates(t *testing.T) {
	builder := NewCoordinatorBuilderForTesting(t, State_Idle)
	builder.GetDomainAPI().On("ContractConfig").Return(&prototk.ContractConfig{
		CoordinatorSelection:          prototk.ContractConfig_COORDINATOR_ENDORSER,
		CoordinatorEndorserCandidates: []string{"endorser1@nodeB", "endorser2@nodeA", "endorser3@nodeB"},
	})
	c, _ := builder.Build()
	ctx, cancel := context.WithCancel(t.Context())
	require.NoError(t, c.Start(ctx))
	defer func() {
		cancel()
		c.WaitForDone(t.Context())
	}()
	defer cancel()
	assert.Equal(t, []string{"nodeA", "nodeB", "nodeB"}, c.originatorNodePool)
}

func TestCoordinator_CancelContext_StopsEventLoopAndDispatchLoop(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	builder := NewCoordinatorBuilderForTesting(t, State_Idle)
	c, _ := builder.Build()
	require.NoError(t, c.Start(ctx))

	// Verify event loop is running
	require.False(t, c.stateMachineEventLoop.IsStopped(), "event loop should not be stopped initially")

	select {
	case <-c.dispatchLoopStopped:
		t.Fatal("dispatch loop should not be stopped initially")
	default:
	}

	// Cancel the context then wait for shutdown to complete
	cancel()
	c.WaitForDone(t.Context())

	// Verify both loops have stopped
	require.True(t, c.stateMachineEventLoop.IsStopped(), "event loop should be stopped")

	select {
	case _, ok := <-c.dispatchLoopStopped:
		require.False(t, ok, "dispatch loop stopped channel should be closed")
	case <-time.After(10 * time.Millisecond):
		t.Fatal("dispatch loop did not stop within timeout")
	}

	// Verify context was cancelled
	select {
	case <-c.ctx.Done():
		// Context was cancelled as expected
	default:
		t.Fatal("context should be cancelled after done()")
	}
}

func TestCoordinator_CancelContext_WaitsForTransportShutdown(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	builder := NewCoordinatorBuilderForTesting(t, State_Idle)
	c, _ := builder.Build()
	defer func() {
		cancel()
		c.WaitForDone(t.Context())
	}()

	mockTransport := transport.NewMockTransportWriter(t)
	// Start uses StartLoopbackWriter on the original transport; replace writer after Start
	// so that WaitForDone is called on the mock.
	mockTransport.On("WaitForDone", mock.Anything).Return().Maybe()
	mockTransport.On("StopLoopbackWriter").Return().Maybe()
	require.NoError(t, c.Start(ctx))

	// Replace the transport writer after Start
	c.transportWriter = mockTransport
}

func TestCoordinator_CancelContext_CompletesSuccessfullyWhenCalledOnce(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	builder := NewCoordinatorBuilderForTesting(t, State_Idle)
	c, _ := builder.Build()
	require.NoError(t, c.Start(ctx))

	cancel()
	c.WaitForDone(t.Context())

	// Verify both loops have stopped
	require.True(t, c.stateMachineEventLoop.IsStopped(), "event loop should be stopped")
	select {
	case _, ok := <-c.dispatchLoopStopped:
		require.False(t, ok, "dispatch loop stopped channel should be closed")
	default:
		t.Fatal("dispatch loop should be stopped")
	}
}

func TestCoordinator_CancelContext_StopsLoopsEvenWhenProcessingEvents(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	builder := NewCoordinatorBuilderForTesting(t, State_Idle)
	c, _ := builder.Build()
	require.NoError(t, c.Start(ctx))

	// Queue some events to ensure loops are busy
	for i := 0; i < 10; i++ {
		c.QueueEvent(ctx, &common.HeartbeatIntervalEvent{})
	}

	cancel()
	c.WaitForDone(t.Context())

	// Verify both loops have stopped
	require.True(t, c.stateMachineEventLoop.IsStopped(), "event loop should be stopped")

	select {
	case _, ok := <-c.dispatchLoopStopped:
		require.False(t, ok, "dispatch loop stopped channel should be closed")
	default:
		t.Fatal("dispatch loop should be stopped")
	}
}

func TestCoordinator_CancelContext_WhenAlreadyCancelled_ReturnsImmediately(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	builder := NewCoordinatorBuilderForTesting(t, State_Idle)
	c, _ := builder.Build()
	require.NoError(t, c.Start(ctx))

	cancel()
	c.WaitForDone(t.Context())

	require.True(t, c.stateMachineEventLoop.IsStopped(), "event loop should be stopped")

	// Second cancel should return immediately without blocking or panicking
	cancel()
	require.True(t, c.stateMachineEventLoop.IsStopped(), "event loop should still be stopped")
}

func Test_propagateEventToTransaction_UnknownTransaction_ReturnsNil(t *testing.T) {
	ctx := t.Context()
	builder := NewCoordinatorBuilderForTesting(t, State_Idle)
	c, _ := builder.Build()

	event := &transaction.ConfirmedSuccessEvent{
		BaseCoordinatorEvent: transaction.BaseCoordinatorEvent{TransactionID: uuid.New()},
		Hash:                 pldtypes.Bytes32(pldtypes.RandBytes(32)),
	}

	err := c.propagateEventToTransaction(ctx, event)
	require.NoError(t, err)
	assert.Empty(t, c.transactionsByID, "transaction should not be added")
}

func TestCoordinator_PropagateEventToAllTransactions_ReturnsNilWhenNoTransactionsExist(t *testing.T) {
	ctx := t.Context()
	c, _ := NewCoordinatorBuilderForTesting(t, State_Idle).Build()

	event := &common.HeartbeatIntervalEvent{}
	err := c.propagateEventToAllTransactions(ctx, event)

	assert.NoError(t, err, "should return nil when no transactions exist")
}

func TestCoordinator_PropagateEventToAllTransactions_SuccessfullyPropagatesEventToSingleTransaction(t *testing.T) {
	ctx := t.Context()
	txn, _ := transaction.NewTransactionBuilderForTesting(t, transaction.State_Pooled).Build()
	c, _ := NewCoordinatorBuilderForTesting(t, State_Idle).Transactions(txn).Build()

	// Propagate heartbeat event (should be handled successfully by any state)
	event := &common.HeartbeatIntervalEvent{}
	err := c.propagateEventToAllTransactions(ctx, event)

	assert.NoError(t, err, "should successfully propagate event to single transaction")
}

func TestCoordinator_PropagateEventToAllTransactions_SuccessfullyPropagatesEventToMultipleTransactions(t *testing.T) {
	ctx := t.Context()
	txn1, _ := transaction.NewTransactionBuilderForTesting(t, transaction.State_Pooled).Build()
	txn2, _ := transaction.NewTransactionBuilderForTesting(t, transaction.State_Assembling).Build()
	txn3, _ := transaction.NewTransactionBuilderForTesting(t, transaction.State_Dispatched).Build()
	c, _ := NewCoordinatorBuilderForTesting(t, State_Idle).Transactions(txn1, txn2, txn3).Build()

	// Propagate heartbeat event
	event := &common.HeartbeatIntervalEvent{}
	err := c.propagateEventToAllTransactions(ctx, event)

	assert.NoError(t, err, "should successfully propagate event to all transactions")
}

func TestCoordinator_PropagateEventToAllTransactions_ReturnsErrorWhenSingleTransactionFailsToHandleEvent(t *testing.T) {
	ctx := t.Context()
	txn, _ := transaction.NewTransactionBuilderForTesting(t, transaction.State_Pooled).Build()
	c, _ := NewCoordinatorBuilderForTesting(t, State_Idle).Transactions(txn).Build()

	// HeartbeatIntervalEvent should be handled successfully by all transaction states
	event := &common.HeartbeatIntervalEvent{}
	err := c.propagateEventToAllTransactions(ctx, event)
	assert.NoError(t, err, "heartbeat event should be handled successfully")
}

func TestCoordinator_PropagateEventToAllTransactions_StopsAtFirstErrorWhenMultipleTransactionsExist(t *testing.T) {
	ctx := t.Context()
	txn1, _ := transaction.NewTransactionBuilderForTesting(t, transaction.State_Pooled).Build()
	txn2, _ := transaction.NewTransactionBuilderForTesting(t, transaction.State_Assembling).Build()
	txn3, _ := transaction.NewTransactionBuilderForTesting(t, transaction.State_Dispatched).Build()
	c, _ := NewCoordinatorBuilderForTesting(t, State_Idle).Transactions(txn1, txn2, txn3).Build()

	// Propagate heartbeat event - all should handle it successfully
	event := &common.HeartbeatIntervalEvent{}
	err := c.propagateEventToAllTransactions(ctx, event)
	assert.NoError(t, err, "should successfully propagate to all transactions")
}

func TestCoordinator_PropagateEventToAllTransactions_HandlesEventPropagationWithManyTransactions(t *testing.T) {
	ctx := t.Context()
	numTransactions := 10
	txns := make([]transaction.CoordinatorTransaction, numTransactions)
	for i := 0; i < numTransactions; i++ {
		txns[i], _ = transaction.NewTransactionBuilderForTesting(t, transaction.State_Pooled).Build()
	}
	c, _ := NewCoordinatorBuilderForTesting(t, State_Idle).Transactions(txns...).Build()

	assert.Equal(t, numTransactions, len(c.transactionsByID), "should have correct number of transactions")

	event := &common.HeartbeatIntervalEvent{}
	err := c.propagateEventToAllTransactions(ctx, event)
	assert.NoError(t, err, "should successfully propagate event to all transactions")
}

func TestCoordinator_PropagateEventToAllTransactions_HandlesDifferentEventTypes(t *testing.T) {
	ctx := t.Context()
	txn, _ := transaction.NewTransactionBuilderForTesting(t, transaction.State_Pooled).Build()
	c, _ := NewCoordinatorBuilderForTesting(t, State_Idle).Transactions(txn).Build()

	event := &common.HeartbeatIntervalEvent{}
	err := c.propagateEventToAllTransactions(ctx, event)
	assert.NoError(t, err, "should handle HeartbeatIntervalEvent successfully")
}

func TestCoordinator_PropagateEventToAllTransactions_HandlesContextCancellationGracefully(t *testing.T) {
	ctx := t.Context()
	txn, _ := transaction.NewTransactionBuilderForTesting(t, transaction.State_Pooled).Build()
	c, _ := NewCoordinatorBuilderForTesting(t, State_Idle).Transactions(txn).Build()

	cancelledCtx, cancel := context.WithCancel(ctx)
	cancel()

	event := &common.HeartbeatIntervalEvent{}
	_ = c.propagateEventToAllTransactions(cancelledCtx, event)
	// Just verify it doesn't panic
}

func TestCoordinator_PropagateEventToAllTransactions_ProcessesTransactionsInMapIterationOrder(t *testing.T) {
	ctx := t.Context()
	txns := make([]transaction.CoordinatorTransaction, 5)
	for i := 0; i < 5; i++ {
		txns[i], _ = transaction.NewTransactionBuilderForTesting(t, transaction.State_Pooled).Build()
	}
	c, _ := NewCoordinatorBuilderForTesting(t, State_Idle).Transactions(txns...).Build()

	event := &common.HeartbeatIntervalEvent{}
	err := c.propagateEventToAllTransactions(ctx, event)
	assert.NoError(t, err, "should process all transactions regardless of order")
	assert.Equal(t, 5, len(c.transactionsByID), "all transactions should still be in map")
}

func TestCoordinator_PropagateEventToAllTransactions_ReturnsErrorImmediatelyWhenTransactionHandleEventFails(t *testing.T) {
	ctx := t.Context()
	txn1, _ := transaction.NewTransactionBuilderForTesting(t, transaction.State_Pooled).Build()
	txn2, _ := transaction.NewTransactionBuilderForTesting(t, transaction.State_Assembling).Build()
	c, _ := NewCoordinatorBuilderForTesting(t, State_Idle).Transactions(txn1, txn2).Build()

	event := &common.HeartbeatIntervalEvent{}
	err := c.propagateEventToAllTransactions(ctx, event)
	// With real transactions, HeartbeatIntervalEvent should be handled successfully
	assert.NoError(t, err, "heartbeat event should be handled successfully by all transaction states")
}

func TestCoordinator_PropagateEventToAllTransactions_IncrementsHeartbeatCounterForConfirmedTransaction(t *testing.T) {
	ctx := t.Context()
	mockGrapher := graphermocks.NewGrapher(t)
	txn, _ := transaction.NewTransactionBuilderForTesting(t, transaction.State_Confirmed).
		HeartbeatIntervalsSinceStateChange(4).Grapher(mockGrapher).Build()
	mockGrapher.EXPECT().Forget(mock.Anything, txn.GetID())
	c, _ := NewCoordinatorBuilderForTesting(t, State_Idle).Transactions(txn).Build()

	assert.Equal(t, transaction.State_Confirmed, txn.GetCurrentState(), "transaction should start in State_Confirmed")

	// Propagate heartbeat event
	event := &common.HeartbeatIntervalEvent{}
	err := c.propagateEventToAllTransactions(ctx, event)
	assert.NoError(t, err)

	// Transaction should have transitioned to State_Final (counter went from 4 to 5, which >= grace period of 5)
	assert.Equal(t, transaction.State_Final, txn.GetCurrentState(), "transaction should have transitioned to State_Final after heartbeat")
}

func TestCoordinator_PropagateEventToAllTransactions_IncrementsHeartbeatCounterForRevertedTransaction(t *testing.T) {
	ctx := t.Context()
	txn, _ := transaction.NewTransactionBuilderForTesting(t, transaction.State_Reverted).
		HeartbeatIntervalsSinceStateChange(4).Build()
	c, _ := NewCoordinatorBuilderForTesting(t, State_Idle).Transactions(txn).Build()

	assert.Equal(t, transaction.State_Reverted, txn.GetCurrentState(), "transaction should start in State_Reverted")

	// Propagate heartbeat event
	event := &common.HeartbeatIntervalEvent{}
	err := c.propagateEventToAllTransactions(ctx, event)
	assert.NoError(t, err)

	// Transaction should have transitioned to State_Final
	assert.Equal(t, transaction.State_Final, txn.GetCurrentState(), "transaction should have transitioned to State_Final after heartbeat")
}

func TestCoordinator_PropagateEventToAllTransactions_HandleEventReturnsError(t *testing.T) {
	ctx := t.Context()
	mockTxn := coordinatortransactionmocks.NewCoordinatorTransaction(t)
	txnID := uuid.New()
	expectedError := fmt.Errorf("handle event error")
	mockTxn.EXPECT().GetID().Return(txnID)
	mockTxn.EXPECT().HandleEvent(ctx, mock.AnythingOfType("*common.HeartbeatIntervalEvent")).Return(expectedError)
	c, _ := NewCoordinatorBuilderForTesting(t, State_Idle).Transactions(mockTxn).Build()

	event := &common.HeartbeatIntervalEvent{}
	err := c.propagateEventToAllTransactions(ctx, event)
	require.Error(t, err)
	assert.Equal(t, expectedError, err)
}

func TestCoordinator_WaitForDone_ReturnsEarlyWhenContextCancelled(t *testing.T) {
	builder := NewCoordinatorBuilderForTesting(t, State_Idle)
	ctx, cancel := context.WithCancel(t.Context())

	c, _ := builder.Build()
	require.NoError(t, c.Start(ctx))

	defer func() {
		cancel()
		c.WaitForDone(t.Context())
	}()

	// Create a context that is already cancelled — WaitForDone should return early via ctx.Done()
	ctx2, cancel2 := context.WithCancel(t.Context())
	cancel2()

	c.WaitForDone(ctx2)
}
