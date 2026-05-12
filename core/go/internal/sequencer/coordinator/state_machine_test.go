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
	"testing"

	"github.com/LFDT-Paladin/paladin/core/internal/sequencer/common"
	"github.com/LFDT-Paladin/paladin/core/internal/sequencer/coordinator/grapher"
	"github.com/LFDT-Paladin/paladin/core/internal/sequencer/coordinator/transaction"
	"github.com/LFDT-Paladin/paladin/core/internal/sequencer/statemachine"
	"github.com/LFDT-Paladin/paladin/core/mocks/coordinatortransactionmocks"
	"github.com/LFDT-Paladin/paladin/sdk/go/pkg/pldtypes"
	"github.com/LFDT-Paladin/paladin/toolkit/pkg/prototk"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// newDispatchedTxMock creates a minimal mock coordinator transaction in Dispatched state.
// GetCurrentState() uses Maybe() since the call count depends on which actions run.
func newDispatchedTxMock(t *testing.T) (*coordinatortransactionmocks.CoordinatorTransaction, uuid.UUID) {
	t.Helper()
	tx := coordinatortransactionmocks.NewCoordinatorTransaction(t)
	txID := uuid.New()
	tx.EXPECT().GetID().Return(txID).Maybe()
	tx.EXPECT().GetCurrentState().Return(transaction.State_Dispatched).Maybe()
	return tx, txID
}

func Test_queueEventInternal_QueuesPriorityEvent(t *testing.T) {
	builder := NewCoordinatorBuilderForTesting(t, State_Idle)
	ctx, cancel := context.WithCancel(t.Context())
	c, mocks := builder.Build()
	mocks.EngineIntegration.On("GetBlockHeight", mock.Anything).Return(int64(0), nil).Maybe()
	require.NoError(t, c.Start(ctx))
	defer func() {
		cancel()
		c.WaitForDone(t.Context())
	}()

	syncEvent := statemachine.NewSyncEvent()
	c.queueEventInternal(ctx, syncEvent)
	<-syncEvent.Done
	require.False(t, c.stateMachineEventLoop.IsStopped(), "event loop should still be running")
}

func Test_TryQueueEvent_QueuesToEventLoop(t *testing.T) {
	builder := NewCoordinatorBuilderForTesting(t, State_Idle)
	ctx, cancel := context.WithCancel(t.Context())
	c, mocks := builder.Build()
	mocks.EngineIntegration.On("GetBlockHeight", mock.Anything).Return(int64(0), nil).Maybe()
	require.NoError(t, c.Start(ctx))
	defer func() {
		cancel()
		c.WaitForDone(t.Context())
	}()

	event := &CoordinatorCreatedEvent{}
	ok := c.TryQueueEvent(ctx, event)
	require.True(t, ok, "TryQueueEvent should return true when event is queued")

	// Drain the event so the loop can process it and we can cleanly stop
	syncEvent := statemachine.NewSyncEvent()
	c.QueueEvent(ctx, syncEvent)
	<-syncEvent.Done
}

// ── Initial state ─────────────────────────────────────────────────────────────

// State_Initial receives CoordinatorCreated and transitions to Idle;
// action_SelectActiveCoordinator runs and sets currentActiveCoordinator from the pool.
func TestCoordinator_WhenCreated_TransitionsToIdle(t *testing.T) {
	ctx := t.Context()
	c, _ := NewCoordinatorBuilderForTesting(t, State_Initial).
		CoordinatorEndorserPool("node1", "node2").
		DomainContractConfig(&prototk.ContractConfig{
			CoordinatorSelection:          prototk.ContractConfig_COORDINATOR_ENDORSER,
			CoordinatorEndorserCandidates: []string{"id@node1", "id@node2"},
		}).
		Build()
	require.NoError(t, c.stateMachineEventLoop.ProcessEvent(ctx, &CoordinatorCreatedEvent{}))
	assert.Equal(t, State_Idle, c.GetCurrentState())
	assert.NotEmpty(t, c.currentActiveCoordinator, "action_SelectActiveCoordinator must set currentActiveCoordinator from pool")
}

// ── Idle state transitions ────────────────────────────────────────────────────

// A heartbeat from the current active coordinator causes Idle→Observing and resets the liveness counter.
func TestCoordinator_WhenIdle_TransitionsToObserving_OnHeartbeatFromCurrentActive(t *testing.T) {
	ctx := t.Context()
	c, _ := NewCoordinatorBuilderForTesting(t, State_Idle).
		NodeName("node1").
		CurrentActiveCoordinator("node2").
		Build()
	// Pass a recognisable coordinator state so we can confirm action_HeartbeatReceived ran.
	event := &common.HeartbeatReceivedEvent{
		From:                "node2",
		CoordinatorSnapshot: &common.CoordinatorSnapshot{CoordinatorState: State_Active},
	}
	require.NoError(t, c.stateMachineEventLoop.ProcessEvent(ctx, event))
	assert.Equal(t, State_Observing, c.GetCurrentState())
	// action_HeartbeatReceived sets c.activeCoordinatorState from the snapshot
	assert.Equal(t, State_Active, c.activeCoordinatorState)
}

// A heartbeat from an unrelated node fails the validator; Idle stays Idle and activeCoordinatorState is not updated.
func TestCoordinator_WhenIdle_StaysIdle_OnHeartbeatFromUnrelatedNode(t *testing.T) {
	ctx := t.Context()
	c, _ := NewCoordinatorBuilderForTesting(t, State_Idle).
		NodeName("node1").
		CurrentActiveCoordinator("node2").
		PreferredActiveCoordinator("node2").
		Build()
	event := &common.HeartbeatReceivedEvent{
		From:                "node3",
		CoordinatorSnapshot: &common.CoordinatorSnapshot{CoordinatorState: common.CoordinatorState_Active},
	}
	require.NoError(t, c.stateMachineEventLoop.ProcessEvent(ctx, event))
	assert.Equal(t, State_Idle, c.GetCurrentState())
	// validator failed → action_HeartbeatReceived never ran → activeCoordinatorState stays unset
	assert.Equal(t, common.CoordinatorState(0), c.activeCoordinatorState, "rejected heartbeat must not update activeCoordinatorState")
}

// When delegations arrive in Idle and this node IS the current coordinator, process and transition to Active.
func TestCoordinator_WhenIdleAndTransactionsDelegatedToSelf_TransitionsToActive(t *testing.T) {
	ctx := t.Context()
	c, _ := NewCoordinatorBuilderForTesting(t, State_Idle).
		NodeName("node1").
		CurrentActiveCoordinator("node1").
		Build()
	event := &TransactionsDelegatedEvent{
		FromNode:     "senderNode",
		Originator:   "sender@senderNode",
		DelegationID: "delegation-1",
	}
	require.NoError(t, c.stateMachineEventLoop.ProcessEvent(ctx, event))
	assert.Equal(t, State_Active, c.GetCurrentState())
	assert.NotEmpty(t, c.signingIdentity, "OnTransitionTo Active must set signing identity")
}

// ── Observing state transitions ───────────────────────────────────────────────

// When heartbeat intervals exceed the inactive grace period in Observing, transition to Idle.
func TestCoordinator_WhenObserving_TransitionsToIdle_OnHeartbeatIntervalInactiveGrace(t *testing.T) {
	ctx := t.Context()
	c, _ := NewCoordinatorBuilderForTesting(t, State_Observing).
		InactiveGracePeriod(3).
		HeartbeatIntervalsSinceLastReceive(2).
		Build()
	require.NoError(t, c.stateMachineEventLoop.ProcessEvent(ctx, &common.HeartbeatIntervalEvent{}))
	// action_IncrementHeartbeatIntervalCounts bumps counter to 3; guard_InactiveGracePeriodExceeded = true
	assert.Equal(t, State_Idle, c.GetCurrentState())
	assert.Equal(t, 3, c.heartbeatIntervalsSinceLastReceive, "counter must be at grace-period threshold after increment")
}

// When a new block-range epoch arrives and this node is the preferred coordinator, transition to Elect.
func TestCoordinator_WhenObserving_TransitionsToElect_OnNewBlock_WhenPreferredActive(t *testing.T) {
	ctx := t.Context()
	c, _ := NewCoordinatorBuilderForTesting(t, State_Observing).
		NodeName("node2").
		PreferredActiveCoordinator("node1").
		CurrentActiveCoordinator("node1").
		CurrentBlockHeight(100).
		CoordinatorSelectionBlockRange(50).
		CoordinatorEndorserPool("node1", "node2", "node3").
		DomainContractConfig(&prototk.ContractConfig{
			CoordinatorSelection: prototk.ContractConfig_COORDINATOR_ENDORSER,
		}).
		Build()
	// NewBlock at 150: epoch 100/50=2 → 150/50=3 — crosses boundary and selects node2 as preferred
	require.NoError(t, c.stateMachineEventLoop.ProcessEvent(ctx, &common.NewBlockEvent{BlockHeight: 150}))
	assert.Equal(t, State_Elect, c.GetCurrentState())
}

// An ActiveCoordinatorUnavailable event in Observing always transitions to Idle, regardless of mode.
// In SENDER mode action_CurrentActiveCoordinatorUnavailable is a no-op; currentActiveCoordinator is unchanged.
func TestCoordinator_WhenObserving_TransitionsToIdle_OnActiveCoordinatorUnavailable(t *testing.T) {
	ctx := t.Context()
	c, _ := NewCoordinatorBuilderForTesting(t, State_Observing).
		NodeName("node1").
		CurrentActiveCoordinator("node2").
		Build()
	require.NoError(t, c.stateMachineEventLoop.ProcessEvent(ctx, &ActiveCoordinatorUnavailableEvent{NewActiveCoordinator: "node3"}))
	assert.Equal(t, State_Idle, c.GetCurrentState())
	// SENDER mode: action_CurrentActiveCoordinatorUnavailable is a no-op; currentActiveCoordinator must not change
	assert.Equal(t, "node2", c.currentActiveCoordinator, "SENDER mode: current must be unchanged by unavailability event")
}

// ── Elect state transitions ───────────────────────────────────────────────────

// When the previous coordinator sends a Closing heartbeat, Elect → Active and action_ImportStatesAndLocks runs.
// action_ImportStatesAndLocks only imports confirmed locks (Transaction == nil, ConfirmedAtBlock set) and their
// associated output states. The grapher reflects the import and ExportStatesAndLocks returns them afterwards.
func TestCoordinator_WhenElectCompletesViaPreviousClosingHeartbeat_ImportsStateOnlyOnThatPath(t *testing.T) {
	ctx := t.Context()
	c, _ := NewCoordinatorBuilderForTesting(t, State_Elect).
		NodeName("node1").
		PreferredActiveCoordinator("node1").
		CurrentActiveCoordinator("node1").
		PreviousActiveCoordinatorNode("node2").
		Build()

	// Construct a confirmed lock + its output state so we can verify the grapher absorbed them.
	stateID := pldtypes.HexBytes{0x01, 0x02, 0x03, 0x04}
	confirmedAtBlock := uint64(99)
	lock := &grapher.StateLock{
		State:            stateID,
		ConfirmedAtBlock: &confirmedAtBlock,
	}
	outputState := &grapher.OutputState{
		AllowedNodes: []string{"node1"},
	}
	outputState.ID = stateID

	event := &common.HeartbeatReceivedEvent{
		From: "node2",
		CoordinatorSnapshot: &common.CoordinatorSnapshot{
			CoordinatorState: common.CoordinatorState_Closing,
			Locks:            []*grapher.StateLock{lock},
			OutputStates:     []*grapher.OutputState{outputState},
		},
	}
	require.NoError(t, c.stateMachineEventLoop.ProcessEvent(ctx, event))
	assert.Equal(t, State_Active, c.GetCurrentState())
	assert.NotEmpty(t, c.signingIdentity, "OnTransitionTo Active must set signing identity")
	assert.Equal(t, common.CoordinatorState_Closing, c.activeCoordinatorState)
	// action_ImportStatesAndLocks ran: the grapher must now hold the imported state and lock.
	exported, err := c.grapher.ExportStatesAndLocks(ctx, "node1")
	require.NoError(t, err)
	assert.Len(t, exported.OutputState, 1, "imported output state must be visible to node1")
	assert.Len(t, exported.LockedState, 1, "imported confirmed lock must be present in grapher")
}

// When the inactive grace period expires in Elect (no closing heartbeat), Elect → Active directly.
// action_ImportStatesAndLocks does NOT run on this path — no HeartbeatReceivedEvent is involved,
// so the grapher remains empty.
func TestCoordinator_WhenElectCompletesViaInactiveGrace_DoesNotImportStateLikeClosingHeartbeatPath(t *testing.T) {
	ctx := t.Context()
	c, _ := NewCoordinatorBuilderForTesting(t, State_Elect).
		NodeName("node1").
		PreferredActiveCoordinator("node1").
		CurrentActiveCoordinator("node1").
		HeartbeatIntervalsSinceStateChange(2).
		InactiveGracePeriod(3).
		Build()
	// action_IncrementHeartbeatIntervalCounts bumps heartbeatIntervalsSinceStateChange to 3; grace expired
	require.NoError(t, c.stateMachineEventLoop.ProcessEvent(ctx, &common.HeartbeatIntervalEvent{}))
	assert.Equal(t, State_Active, c.GetCurrentState())
	assert.NotEmpty(t, c.signingIdentity, "OnTransitionTo Active must set signing identity")
	// action_ImportStatesAndLocks did NOT run: no HeartbeatReceivedEvent on this path, grapher stays empty.
	exported, err := c.grapher.ExportStatesAndLocks(ctx, "node1")
	require.NoError(t, err)
	assert.Empty(t, exported.OutputState, "no states must be imported on inactive-grace path")
	assert.Empty(t, exported.LockedState, "no locks must be imported on inactive-grace path")
}

// A heartbeat from the previous coordinator that is NOT yet Closing keeps the Elect state.
// action_HeartbeatReceived still fires and updates activeCoordinatorState.
func TestCoordinator_WhenElect_StaysElect_OnHeartbeatFromPreviousCoordinatorNotYetClosing(t *testing.T) {
	ctx := t.Context()
	c, _ := NewCoordinatorBuilderForTesting(t, State_Elect).
		NodeName("node1").
		PreferredActiveCoordinator("node1").
		CurrentActiveCoordinator("node1").
		PreviousActiveCoordinatorNode("prev").
		Build()
	event := &common.HeartbeatReceivedEvent{
		From: "prev",
		CoordinatorSnapshot: &common.CoordinatorSnapshot{
			CoordinatorState: common.CoordinatorState_Flush, // NOT Closing
		},
	}
	require.NoError(t, c.stateMachineEventLoop.ProcessEvent(ctx, event))
	assert.Equal(t, State_Elect, c.GetCurrentState())
	// guard_ActiveCoordinatorFlushComplete is false (Flush ≠ Closing); no transition
	// action_HeartbeatReceived ran and updated activeCoordinatorState from the snapshot
	assert.Equal(t, common.CoordinatorState_Flush, c.activeCoordinatorState)
}

// A new block-range epoch in Elect where this node is NO LONGER the current coordinator transitions to Observing.
func TestCoordinator_WhenElect_TransitionsToObserving_OnNewBlock_WhenNoLongerCurrentCoordinator(t *testing.T) {
	ctx := t.Context()
	c, _ := NewCoordinatorBuilderForTesting(t, State_Elect).
		NodeName("node1").
		PreferredActiveCoordinator("node1").
		CurrentActiveCoordinator("node1").
		CurrentBlockHeight(100).
		CoordinatorSelectionBlockRange(50).
		DomainContractConfig(&prototk.ContractConfig{
			CoordinatorSelection: prototk.ContractConfig_COORDINATOR_ENDORSER,
		}).
		Build()
	require.NoError(t, c.stateMachineEventLoop.ProcessEvent(ctx, &common.NewBlockEvent{BlockHeight: 150}))
	// guard_IsCurrentActiveCoordinator: "node1" ≠ "node2" → false → GuardNot true → Observing
	assert.Equal(t, State_Observing, c.GetCurrentState())
	assert.Equal(t, uint64(150), c.currentBlockHeight, "action_UpdateBlockHeight must have run")
}

// ── Active state transitions ──────────────────────────────────────────────────

// When no transactions are inflight in Active and a heartbeat interval fires, transition to Idle.
// action_SendHeartbeat fires as part of the HeartbeatInterval handler before the Idle transition.
func TestCoordinator_WhenActive_TransitionsToIdle_OnHeartbeatInterval_WhenNoInflight(t *testing.T) {
	ctx := t.Context()
	c, mocks := NewCoordinatorBuilderForTesting(t, State_Active).
		NodeName("node1").
		CurrentActiveCoordinator("node1").
		OriginatorNodePool("node2"). // gives action_SendHeartbeat a recipient
		Build()
	require.NoError(t, c.stateMachineEventLoop.ProcessEvent(ctx, &common.HeartbeatIntervalEvent{}))
	// guard_HasTransactionsInflight = false (no txns); GuardNot(HasTransactionsInflight) = true
	assert.Equal(t, State_Idle, c.GetCurrentState())
	// action_SendHeartbeat ran during the Active HeartbeatInterval handler
	assert.True(t, mocks.SentMessageRecorder.HasSentHeartbeat(), "action_SendHeartbeat must fire in Active HeartbeatInterval")
}

// A new-epoch NewBlock with a dispatched (inflight) transaction → Flush.
func TestCoordinator_WhenActiveAndEpochChangesWithInflightDispatched_TransitionsToFlush(t *testing.T) {
	ctx := t.Context()
	txDispatched, _ := newDispatchedTxMock(t)
	c, _ := NewCoordinatorBuilderForTesting(t, State_Active).
		NodeName("node1").
		CurrentActiveCoordinator("node1").
		CurrentBlockHeight(100).
		CoordinatorSelectionBlockRange(50).
		Transactions(txDispatched).
		Build()
	require.NoError(t, c.stateMachineEventLoop.ProcessEvent(ctx, &common.NewBlockEvent{BlockHeight: 150}))
	assert.Equal(t, State_Flush, c.GetCurrentState())
}

// A new-epoch NewBlock with a pooled (not-yet-dispatched) transaction and this node still current coordinator → re-enters Active.
// action_CleanUpTransactionsNotYetDispatched removes transactions in State_Pooled from transactionsByID and
// pooledTransactions (cleanUpTransaction calls removeTransactionFromPool). guard_FlushComplete then returns true,
// and the node is still current, so the machine re-enters Active for signing key rotation.
// action_SelectTransaction on OnTransitionTo fires but finds the pool empty — the cleaned-up transaction will
// be re-delegated from the originator.
func TestCoordinator_WhenActiveAndEpochChangesWithNotYetDispatchedTxsAndStillCurrentCoordinator_CleansUpAndReentersActive(t *testing.T) {
	ctx := t.Context()
	pooledTx := coordinatortransactionmocks.NewCoordinatorTransaction(t)
	pooledTxID := uuid.New()
	pooledTx.EXPECT().GetID().Return(pooledTxID).Maybe()
	pooledTx.EXPECT().GetCurrentState().Return(transaction.State_Pooled).Maybe()

	prevIdentity := ""
	c, _ := NewCoordinatorBuilderForTesting(t, State_Active).
		NodeName("node2").
		CurrentActiveCoordinator("node2").
		CurrentBlockHeight(100).
		CoordinatorSelectionBlockRange(50).
		CoordinatorEndorserPool("node1", "node2", "node3").
		PooledTransactions(pooledTx). // adds to both transactionsByID and pooledTransactions
		DomainContractConfig(&prototk.ContractConfig{
			CoordinatorSelection: prototk.ContractConfig_COORDINATOR_ENDORSER,
		}).
		Build()
	prevIdentity = c.signingIdentity
	require.Equal(t, 1, len(c.transactionsByID), "pooled tx must be registered before event")
	require.Equal(t, 1, len(c.pooledTransactions), "pooled tx must be in pool queue before event")
	require.NoError(t, c.stateMachineEventLoop.ProcessEvent(ctx, &common.NewBlockEvent{BlockHeight: 150}))
	assert.Equal(t, State_Active, c.GetCurrentState())
	// action_CleanUpTransactionsNotYetDispatched removed the pooled tx from both maps
	assert.Equal(t, 0, len(c.transactionsByID), "not-yet-dispatched tx must be removed from transactionsByID on epoch change")
	assert.Equal(t, 0, len(c.pooledTransactions), "not-yet-dispatched tx must be removed from pooledTransactions on epoch change")
	// OnTransitionTo Active fires action_NewSigningIdentity — identity must be refreshed
	assert.NotEmpty(t, c.signingIdentity)
	assert.NotEqual(t, prevIdentity, c.signingIdentity, "signing identity must be rotated on Active re-entry")
}

// A new-epoch NewBlock with no inflight txns and this node is NOT current coordinator → Closing.
// action_CleanUpTransactionsNotYetDispatched removes the pooled transaction first; guard_FlushComplete then
// returns true (no Ready_For_Dispatch/Dispatched txns remain), so the machine transitions to Closing.
func TestCoordinator_WhenActiveAndEpochChangesWithNotYetDispatchedTxsAndNotCurrentCoordinator_CleansUpAndTransitionsToClosing(t *testing.T) {
	ctx := t.Context()
	pooledTx := coordinatortransactionmocks.NewCoordinatorTransaction(t)
	pooledTxID := uuid.New()
	pooledTx.EXPECT().GetID().Return(pooledTxID).Maybe()
	pooledTx.EXPECT().GetCurrentState().Return(transaction.State_Pooled).Maybe()

	c, _ := NewCoordinatorBuilderForTesting(t, State_Active).
		NodeName("node1").
		CurrentActiveCoordinator("node1").
		CurrentBlockHeight(100).
		CoordinatorSelectionBlockRange(50).
		CoordinatorEndorserPool("node1", "node2", "node3").
		Transactions(pooledTx).
		DomainContractConfig(&prototk.ContractConfig{
			CoordinatorSelection: prototk.ContractConfig_COORDINATOR_ENDORSER,
		}).
		Build()
	require.Equal(t, 1, len(c.transactionsByID), "pooled tx must be registered before event")
	require.NoError(t, c.stateMachineEventLoop.ProcessEvent(ctx, &common.NewBlockEvent{BlockHeight: 150}))
	assert.Equal(t, State_Closing, c.GetCurrentState())
	assert.Equal(t, uint64(150), c.currentBlockHeight, "action_UpdateBlockHeight must have run")
	// action_CleanUpTransactionsNotYetDispatched removed the pooled transaction from memory
	assert.Equal(t, 0, len(c.transactionsByID), "pooled tx must be cleaned up on epoch change")
}

// A fallback Active coordinator receives an Active heartbeat from the preferred node with inflight txns → Flush.
func TestCoordinator_WhenFallbackActiveAndPreferredSendsActiveHeartbeat_TransitionsToFlush_WhenInflight(t *testing.T) {
	ctx := t.Context()
	txDispatched, _ := newDispatchedTxMock(t)
	c, _ := NewCoordinatorBuilderForTesting(t, State_Active).
		NodeName("node1").
		PreferredActiveCoordinator("node2").
		CurrentActiveCoordinator("node1"). // "node1" is acting as fallback
		Transactions(txDispatched).
		Build()
	event := &common.HeartbeatReceivedEvent{
		From: "node2",
		CoordinatorSnapshot: &common.CoordinatorSnapshot{
			CoordinatorState: common.CoordinatorState_Active,
		},
	}
	require.NoError(t, c.stateMachineEventLoop.ProcessEvent(ctx, event))
	assert.Equal(t, State_Flush, c.GetCurrentState())
}

// A fallback Active coordinator receives an Active heartbeat from the preferred node with no inflight txns → Closing.
func TestCoordinator_WhenFallbackActiveAndPreferredSendsActiveHeartbeat_TransitionsToClosing_WhenNoInflight(t *testing.T) {
	ctx := t.Context()
	c, _ := NewCoordinatorBuilderForTesting(t, State_Active).
		NodeName("node1").
		PreferredActiveCoordinator("node2").
		CurrentActiveCoordinator("node1").
		Build()
	event := &common.HeartbeatReceivedEvent{
		From: "node2",
		CoordinatorSnapshot: &common.CoordinatorSnapshot{
			CoordinatorState: common.CoordinatorState_Active,
		},
	}
	require.NoError(t, c.stateMachineEventLoop.ProcessEvent(ctx, event))
	assert.Equal(t, State_Closing, c.GetCurrentState())
}

// Entering Active via any path fires action_NewSigningIdentity and action_SelectTransaction.
// With a pooled transaction present, action_SelectTransaction pops it and calls HandleEvent(SelectedEvent).
// The Elect→Active path via a closing heartbeat does not run action_CleanUpTransactionsNotYetDispatched,
// so the pooled transaction survives and is selected.
func TestCoordinator_WhenEnteringActive_RefreshesSigningIdentityAndSelectsTransactions(t *testing.T) {
	ctx := t.Context()
	pooledTx := coordinatortransactionmocks.NewCoordinatorTransaction(t)
	pooledTxID := uuid.New()
	pooledTx.EXPECT().GetID().Return(pooledTxID).Maybe()
	pooledTx.EXPECT().GetCurrentState().Return(transaction.State_Pooled).Maybe()
	pooledTx.EXPECT().HandleEvent(mock.Anything, mock.AnythingOfType("*transaction.SelectedEvent")).Return(nil).Once()

	c, _ := NewCoordinatorBuilderForTesting(t, State_Elect).
		NodeName("node1").
		PreferredActiveCoordinator("node1").
		CurrentActiveCoordinator("node1").
		PreviousActiveCoordinatorNode("node2").
		PooledTransactions(pooledTx).
		Build()
	require.NoError(t, c.stateMachineEventLoop.ProcessEvent(ctx, &common.HeartbeatReceivedEvent{
		From: "node2",
		CoordinatorSnapshot: &common.CoordinatorSnapshot{
			CoordinatorState: common.CoordinatorState_Closing,
		},
	}))
	assert.Equal(t, State_Active, c.GetCurrentState())
	assert.NotEmpty(t, c.signingIdentity)
	// mock expectation on pooledTx.HandleEvent(SelectedEvent) verified by testify
}

// ── Flush state transitions ───────────────────────────────────────────────────

// When the last inflight transaction finalises in Flush and this node is still current, transition to Active.
func TestCoordinator_WhenFlushCompletesAndStillCurrentCoordinator_TransitionsToActive(t *testing.T) {
	ctx := t.Context()
	txDispatched, txID := newDispatchedTxMock(t)
	c, _ := NewCoordinatorBuilderForTesting(t, State_Flush).
		NodeName("node1").
		CurrentActiveCoordinator("node1").
		Transactions(txDispatched).
		Build()
	event := &common.TransactionStateTransitionEvent[transaction.State]{
		TransactionID: txID,
		From:          transaction.State_Dispatched,
		To:            transaction.State_Final,
	}
	require.NoError(t, c.stateMachineEventLoop.ProcessEvent(ctx, event))
	assert.Equal(t, State_Active, c.GetCurrentState())
	assert.NotEmpty(t, c.signingIdentity, "OnTransitionTo Active must set signing identity")
}

// When the last inflight transaction finalises in Flush and another node is now current, transition to Closing.
func TestCoordinator_WhenFlushCompletesAndNotCurrentCoordinator_TransitionsToClosing(t *testing.T) {
	ctx := t.Context()
	txDispatched, txID := newDispatchedTxMock(t)
	c, _ := NewCoordinatorBuilderForTesting(t, State_Flush).
		NodeName("node1").
		CurrentActiveCoordinator("node2"). // another node is now current
		Transactions(txDispatched).
		Build()
	event := &common.TransactionStateTransitionEvent[transaction.State]{
		TransactionID: txID,
		From:          transaction.State_Dispatched,
		To:            transaction.State_Final,
	}
	require.NoError(t, c.stateMachineEventLoop.ProcessEvent(ctx, event))
	assert.Equal(t, State_Closing, c.GetCurrentState())
}

// A NewBlock epoch crossing in Flush updates block height and re-runs coordinator selection, but stays in Flush.
// action_SelectActiveCoordinator fires and re-computes preferred/current from the pool.
func TestCoordinator_WhenFlushingAndNewEpochArrives_UpdatesHeightAndSelectionButStaysFlush(t *testing.T) {
	ctx := t.Context()
	txDispatched, _ := newDispatchedTxMock(t)
	c, _ := NewCoordinatorBuilderForTesting(t, State_Flush).
		NodeName("node1").
		CurrentActiveCoordinator("node1").
		CurrentBlockHeight(100).
		CoordinatorSelectionBlockRange(50).
		CoordinatorEndorserPool("node1", "node2", "node3").
		Transactions(txDispatched).
		DomainContractConfig(&prototk.ContractConfig{
			CoordinatorSelection: prototk.ContractConfig_COORDINATOR_ENDORSER,
		}).
		Build()
	require.NoError(t, c.stateMachineEventLoop.ProcessEvent(ctx, &common.NewBlockEvent{BlockHeight: 150}))
	assert.Equal(t, State_Flush, c.GetCurrentState())
	assert.Equal(t, uint64(150), c.currentBlockHeight)
	assert.Equal(t, "node2", c.preferredActiveCoordinator, "action_SelectActiveCoordinator must update preferredActiveCoordinator")
}

// ActiveCoordinatorUnavailable in Flush updates current coordinator but does not change state.
func TestCoordinator_WhenFlushing_ActiveCoordinatorUnavailable_UpdatesCurrentStaysFlush(t *testing.T) {
	ctx := t.Context()
	txDispatched, _ := newDispatchedTxMock(t)
	// node1 is flushing; the epoch already rolled and node2 became the new current coordinator.
	// action_CurrentActiveCoordinatorUnavailable only updates when nodeName != currentActiveCoordinator,
	// so currentActiveCoordinator must be node2 (not node1) for the update to fire.
	c, _ := NewCoordinatorBuilderForTesting(t, State_Flush).
		NodeName("node1").
		DomainContractConfig(&prototk.ContractConfig{
			CoordinatorSelection:          prototk.ContractConfig_COORDINATOR_ENDORSER,
			CoordinatorEndorserCandidates: []string{"id@node1", "id@node2", "id@node3"},
		}).
		CurrentActiveCoordinator("node2").
		PreferredActiveCoordinator("node2").
		Transactions(txDispatched).
		Build()
	require.NoError(t, c.stateMachineEventLoop.ProcessEvent(ctx, &ActiveCoordinatorUnavailableEvent{
		NewActiveCoordinator: "node3",
	}))
	assert.Equal(t, State_Flush, c.GetCurrentState())
	assert.Equal(t, "node3", c.currentActiveCoordinator)
}

// ── Closing state transitions ─────────────────────────────────────────────────

// On entering Closing via an epoch NewBlock (no inflight, not current), action_SendHeartbeat fires immediately.
func TestCoordinator_WhenClosingStarts_EmitsImmediateHeartbeat(t *testing.T) {
	ctx := t.Context()
	// node1 is the fallback active, node2 is current after epoch change
	// OriginatorNodePool ensures sendHeartbeat has someone to notify
	c, mocks := NewCoordinatorBuilderForTesting(t, State_Active).
		NodeName("node1").
		CurrentActiveCoordinator("node2").
		OriginatorNodePool("node2").
		CurrentBlockHeight(100).
		CoordinatorSelectionBlockRange(50).
		Build()
	require.NoError(t, c.stateMachineEventLoop.ProcessEvent(ctx, &common.NewBlockEvent{BlockHeight: 150}))
	assert.Equal(t, State_Closing, c.GetCurrentState())
	assert.True(t, mocks.SentMessageRecorder.HasSentHeartbeat(), "OnTransitionTo Closing must emit an immediate heartbeat")
}

// After the closing grace period expires with a fresh heartbeat seen, transition to Observing.
func TestCoordinator_WhenClosingGraceExpires_WithNewActiveHeartbeatSeen_TransitionsToObserving(t *testing.T) {
	ctx := t.Context()
	c, _ := NewCoordinatorBuilderForTesting(t, State_Closing).
		ClosingGracePeriod(1).
		HeartbeatIntervalsSinceStateChange(0).
		HeartbeatIntervalsSinceLastReceive(0). // recent heartbeat seen
		InactiveGracePeriod(5).
		Build()
	require.NoError(t, c.stateMachineEventLoop.ProcessEvent(ctx, &common.HeartbeatIntervalEvent{}))
	// heartbeatIntervalsSinceStateChange → 1; closingGracePeriodExpired = 1>=1 true
	// heartbeatIntervalsSinceLastReceive = 0; inactiveGracePeriodExceeded = 0>=5 false
	assert.Equal(t, State_Observing, c.GetCurrentState())
}

// After the closing grace period expires and no heartbeat has been seen, transition to Idle.
func TestCoordinator_WhenClosingGraceExpires_WithoutNewActiveHeartbeat_TransitionsToIdle(t *testing.T) {
	ctx := t.Context()
	c, _ := NewCoordinatorBuilderForTesting(t, State_Closing).
		ClosingGracePeriod(1).
		HeartbeatIntervalsSinceStateChange(0).
		HeartbeatIntervalsSinceLastReceive(5). // no heartbeat seen; counter already at grace
		InactiveGracePeriod(5).
		Build()
	require.NoError(t, c.stateMachineEventLoop.ProcessEvent(ctx, &common.HeartbeatIntervalEvent{}))
	// heartbeatIntervalsSinceStateChange → 1; closingGracePeriodExpired = 1>=1 true
	// heartbeatIntervalsSinceLastReceive = 5 (not incremented by this action); inactiveGracePeriodExceeded = 5>=5 true
	assert.Equal(t, State_Idle, c.GetCurrentState())
}

// In Closing, a NewBlock epoch that re-selects this node as current with heartbeats recently seen → Elect.
func TestCoordinator_WhenClosing_NewBlockReBecomesPreferred_TransitionsToElect(t *testing.T) {
	ctx := t.Context()
	// HeartbeatIntervalsSinceStateChange < InactiveGracePeriod: inactive grace NOT expired → Elect
	c, _ := NewCoordinatorBuilderForTesting(t, State_Closing).
		NodeName("node2").
		CurrentActiveCoordinator("node1").
		CurrentBlockHeight(100).
		CoordinatorSelectionBlockRange(50).
		HeartbeatIntervalsSinceStateChange(0).
		InactiveGracePeriod(5).
		CoordinatorEndorserPool("node1", "node2", "node3").
		DomainContractConfig(&prototk.ContractConfig{
			CoordinatorSelection: prototk.ContractConfig_COORDINATOR_ENDORSER,
		}).
		Build()
	require.NoError(t, c.stateMachineEventLoop.ProcessEvent(ctx, &common.NewBlockEvent{BlockHeight: 150}))
	// guard_IsCurrentActiveCoordinator = true; guard_InactiveGracePeriodExpiredSinceStateChange = 0>=5 false
	assert.Equal(t, State_Elect, c.GetCurrentState())
}

// In Closing, a NewBlock epoch that re-selects this node as current + inactive grace expired + inflight txns → Active.
func TestCoordinator_WhenClosing_NewBlockReBecomesCurrentWithInflight_TransitionsToActive(t *testing.T) {
	ctx := t.Context()
	txDispatched, _ := newDispatchedTxMock(t)
	c, _ := NewCoordinatorBuilderForTesting(t, State_Closing).
		NodeName("node2").
		CurrentActiveCoordinator("node1").
		CurrentBlockHeight(100).
		CoordinatorSelectionBlockRange(50).
		HeartbeatIntervalsSinceStateChange(4).
		InactiveGracePeriod(3).
		CoordinatorEndorserPool("node1", "node2", "node3").
		Transactions(txDispatched).
		DomainContractConfig(&prototk.ContractConfig{
			CoordinatorSelection: prototk.ContractConfig_COORDINATOR_ENDORSER,
		}).
		Build()
	require.NoError(t, c.stateMachineEventLoop.ProcessEvent(ctx, &common.NewBlockEvent{BlockHeight: 150}))
	// guard_IsCurrentActiveCoordinator = true; guard_InactiveGracePeriodExpiredSinceStateChange = 4>=3 true
	// guard_HasTransactionsInflight = true → Active
	assert.Equal(t, State_Active, c.GetCurrentState())
	assert.NotEmpty(t, c.signingIdentity)
}

// In Closing, a NewBlock epoch that re-selects this node as current + inactive grace expired + no inflight → Idle.
func TestCoordinator_WhenClosing_NewBlockReBecomesCurrentNoInflight_TransitionsToIdle(t *testing.T) {
	ctx := t.Context()
	c, _ := NewCoordinatorBuilderForTesting(t, State_Closing).
		NodeName("node2").
		CurrentActiveCoordinator("node2").
		PreferredActiveCoordinator("node1").
		CurrentBlockHeight(100).
		CoordinatorSelectionBlockRange(50).
		HeartbeatIntervalsSinceStateChange(4).
		InactiveGracePeriod(3).
		CoordinatorEndorserPool("node1", "node2", "node3").
		DomainContractConfig(&prototk.ContractConfig{
			CoordinatorSelection: prototk.ContractConfig_COORDINATOR_ENDORSER,
		}).
		Build()

	require.NoError(t, c.stateMachineEventLoop.ProcessEvent(ctx, &common.NewBlockEvent{BlockHeight: 150}))
	assert.Equal(t, State_Idle, c.GetCurrentState())
	assert.Equal(t, uint64(150), c.currentBlockHeight, "action_UpdateBlockHeight must have run")
}

// In Closing, ActiveCoordinatorUnavailable that makes this node current + inflight txns → Active.
func TestCoordinator_WhenClosing_ActiveCoordinatorUnavailable_ReBecomesCurrentWithInflight_TransitionsToActive(t *testing.T) {
	ctx := t.Context()
	txDispatched, _ := newDispatchedTxMock(t)
	c, _ := NewCoordinatorBuilderForTesting(t, State_Closing).
		NodeName("node1").
		DomainContractConfig(&prototk.ContractConfig{
			CoordinatorSelection: prototk.ContractConfig_COORDINATOR_ENDORSER,
		}).
		CurrentActiveCoordinator("node2").
		PreferredActiveCoordinator("node2").
		Transactions(txDispatched).
		Build()
	require.NoError(t, c.stateMachineEventLoop.ProcessEvent(ctx, &ActiveCoordinatorUnavailableEvent{
		NewActiveCoordinator: "node1",
	}))
	// action_CurrentActiveCoordinatorUnavailable sets current to "node1"
	// guard_IsCurrentActiveCoordinator = true; guard_HasTransactionsInflight = true → Active
	assert.Equal(t, State_Active, c.GetCurrentState())
	assert.NotEmpty(t, c.signingIdentity)
}

// In Closing, ActiveCoordinatorUnavailable that makes this node current + no inflight txns → Idle.
func TestCoordinator_WhenClosing_ActiveCoordinatorUnavailable_BecomesCurrentNoInflight_TransitionsToIdle(t *testing.T) {
	ctx := t.Context()
	c, _ := NewCoordinatorBuilderForTesting(t, State_Closing).
		NodeName("node1").
		DomainContractConfig(&prototk.ContractConfig{
			CoordinatorSelection: prototk.ContractConfig_COORDINATOR_ENDORSER,
		}).
		CurrentActiveCoordinator("node2").
		PreferredActiveCoordinator("node2").
		Build()
	require.NoError(t, c.stateMachineEventLoop.ProcessEvent(ctx, &ActiveCoordinatorUnavailableEvent{
		NewActiveCoordinator: "node1",
	}))
	assert.Equal(t, State_Idle, c.GetCurrentState())
	assert.Equal(t, "node1", c.currentActiveCoordinator, "action_CurrentActiveCoordinatorUnavailable must update current to this node")
}
