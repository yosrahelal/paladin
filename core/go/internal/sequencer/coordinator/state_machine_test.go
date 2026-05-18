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
// GetCurrentState() and GetSnapshot() use Maybe() since call counts depend on which actions run.
func newDispatchedTxMock(t *testing.T) (*coordinatortransactionmocks.CoordinatorTransaction, uuid.UUID) {
	t.Helper()
	tx := coordinatortransactionmocks.NewCoordinatorTransaction(t)
	txID := uuid.New()
	tx.EXPECT().GetID().Return(txID).Maybe()
	tx.EXPECT().GetCurrentState().Return(transaction.State_Dispatched).Maybe()
	// GetSnapshot is called by action_SendHeartbeat when building the coordinator heartbeat payload.
	tx.EXPECT().GetSnapshot(mock.Anything).Return(nil, &common.SnapshotDispatchedTransaction{
		SnapshotPooledTransaction: common.SnapshotPooledTransaction{ID: txID},
	}, nil).Maybe()
	// HandleEvent is called by action_PropagateHeartbeatIntervalToTransactions on each heartbeat tick.
	tx.EXPECT().HandleEvent(mock.Anything, mock.AnythingOfType("*common.HeartbeatIntervalEvent")).Return(nil).Maybe()
	// HasDispatchedPublicTransaction is called by action_NudgeDispatchLoop to track in-flight counts.
	tx.EXPECT().HasDispatchedPublicTransaction().Return(true).Maybe()
	// GetOriginatorNode is called by updateOriginatorActivity in STATIC/SENDER modes.
	tx.EXPECT().GetOriginatorNode().Return("originator-node").Maybe()
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
// action_CalculateCoordinatorPriorities runs and computes the initial priority list.
func TestCoordinator_WhenCreated_TransitionsToIdle(t *testing.T) {
	ctx := t.Context()
	c, _ := NewCoordinatorBuilderForTesting(t, State_Initial).
		EndorserCandidates("node1", "node2").
		CoordinatorSelectionMode(prototk.ContractConfig_COORDINATOR_ENDORSER).
		Build()
	require.NoError(t, c.stateMachineEventLoop.ProcessEvent(ctx, &CoordinatorCreatedEvent{}))
	assert.Equal(t, State_Idle, c.GetCurrentState())
	assert.NotEmpty(t, c.coordinatorPriorityList, "action_CalculateCoordinatorPriorities must populate the priority list")
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
		FromNode:            "node2",
		CoordinatorSnapshot: &common.CoordinatorSnapshot{CoordinatorState: State_Active},
	}
	require.NoError(t, c.stateMachineEventLoop.ProcessEvent(ctx, event))
	assert.Equal(t, State_Observing, c.GetCurrentState())
	assert.Equal(t, "node2", c.currentActiveCoordinator)
}

// A heartbeat from a node in Closing state is completely ignored in Idle because the event-level
// validator_IsHeartbeatSenderLive rejects non-live senders before any actions run. Neither
// currentActiveCoordinator nor the state machine state change.
func TestCoordinator_WhenIdle_StaysIdle_OnHeartbeatFromNodeInNonActiveState(t *testing.T) {
	ctx := t.Context()
	c, _ := NewCoordinatorBuilderForTesting(t, State_Idle).
		NodeName("node1").
		CurrentActiveCoordinator("node1").
		Build()
	event := &common.HeartbeatReceivedEvent{
		FromNode:            "node3",
		CoordinatorSnapshot: &common.CoordinatorSnapshot{CoordinatorState: common.CoordinatorState_Closing},
	}
	require.NoError(t, c.stateMachineEventLoop.ProcessEvent(ctx, event))
	assert.Equal(t, State_Idle, c.GetCurrentState())
	assert.Equal(t, "node1", c.currentActiveCoordinator, "non-live heartbeat must leave currentActiveCoordinator unchanged")
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
	assert.NotEmpty(t, c.signingIdentity.value, "OnTransitionTo Active must set signing identity")
}

// A new-epoch NewBlock in Idle fires action_CalculateCoordinatorPriorities (recomputes priority list)
// and action_UpdateBlockHeight. No state transition — Idle does not have an epoch-change exit condition.
func TestCoordinator_WhenIdle_NewBlock_NewEpoch_UpdatesPriorityListAndStaysIdle(t *testing.T) {
	ctx := t.Context()
	c, _ := NewCoordinatorBuilderForTesting(t, State_Idle).
		NodeName("node1").
		CurrentActiveCoordinator("node1").
		CurrentBlockHeight(100).
		CoordinatorSelectionBlockRange(50).
		EndorserCandidates("node1", "node2", "node3").
		CoordinatorSelectionMode(prototk.ContractConfig_COORDINATOR_ENDORSER).
		Build()
	require.NoError(t, c.stateMachineEventLoop.ProcessEvent(ctx, &common.NewBlockEvent{BlockHeight: 150}))
	assert.Equal(t, State_Idle, c.GetCurrentState())
	assert.Equal(t, uint64(150), c.currentBlockHeight, "action_UpdateBlockHeight must have run")
	assert.NotEmpty(t, c.coordinatorPriorityList, "priority list must be populated by action_CalculateCoordinatorPriorities")
}

// A same-epoch NewBlock in Idle fires only action_UpdateBlockHeight; action_CalculateCoordinatorPriorities
// is guarded by guard_IsOnEpochBoundary and must NOT run, so the priority list stays empty.
func TestCoordinator_WhenIdle_NewBlock_NotNewEpoch_UpdatesBlockHeightAndStaysIdle(t *testing.T) {
	ctx := t.Context()
	c, _ := NewCoordinatorBuilderForTesting(t, State_Idle).
		NodeName("node1").
		CurrentBlockHeight(100).
		CoordinatorSelectionBlockRange(50).
		EndorserCandidates("node1", "node2", "node3").
		CoordinatorSelectionMode(prototk.ContractConfig_COORDINATOR_ENDORSER).
		Build()
	// Block 120 is in the same epoch as 100 (both in epoch 100/50 = 2), so guard_IsOnEpochBoundary = false.
	require.NoError(t, c.stateMachineEventLoop.ProcessEvent(ctx, &common.NewBlockEvent{BlockHeight: 120}))
	assert.Equal(t, State_Idle, c.GetCurrentState())
	assert.Equal(t, uint64(120), c.currentBlockHeight, "action_UpdateBlockHeight must have run")
	assert.Empty(t, c.coordinatorPriorityList, "action_CalculateCoordinatorPriorities must NOT run within the same epoch")
}

// ── Observing state transitions ───────────────────────────────────────────────

// When heartbeat intervals exceed the inactive grace period in Observing, the coordinator transitions to Idle.
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

// When a new block-range epoch arrives in Observing, action_CalculateCoordinatorPriorities recomputes
// the priority list. The state stays Observing — epoch changes do not trigger a transition to Elect;
// only a delegation request can move Observing → Elect.
func TestCoordinator_WhenObserving_NewBlock_UpdatesPriorityListAndStaysObserving(t *testing.T) {
	ctx := t.Context()
	c, _ := NewCoordinatorBuilderForTesting(t, State_Observing).
		NodeName("node2").
		CurrentActiveCoordinator("node1").
		CurrentBlockHeight(100).
		CoordinatorSelectionBlockRange(50).
		EndorserCandidates("node1", "node2", "node3").
		CoordinatorSelectionMode(prototk.ContractConfig_COORDINATOR_ENDORSER).
		Build()
	// NewBlock at 150: epoch 100/50=2 → 150/50=3 — crosses boundary; action_CalculateCoordinatorPriorities fires
	require.NoError(t, c.stateMachineEventLoop.ProcessEvent(ctx, &common.NewBlockEvent{BlockHeight: 150}))
	// No transition to Elect — epoch change alone does not initiate a handover.
	assert.Equal(t, State_Observing, c.GetCurrentState())
	assert.Equal(t, uint64(150), c.currentBlockHeight, "action_UpdateBlockHeight must have run")
	assert.NotEmpty(t, c.coordinatorPriorityList, "priority list must be populated by action_CalculateCoordinatorPriorities")
}

// A HeartbeatInterval in Observing within the inactive grace period increments the counter but does
// not trigger a transition to Idle.
func TestCoordinator_WhenObserving_HeartbeatInterval_WithinGrace_IncrementsCounterAndStaysObserving(t *testing.T) {
	ctx := t.Context()
	c, _ := NewCoordinatorBuilderForTesting(t, State_Observing).
		HeartbeatIntervalsSinceLastReceive(1).
		InactiveGracePeriod(3).
		Build()
	require.NoError(t, c.stateMachineEventLoop.ProcessEvent(ctx, &common.HeartbeatIntervalEvent{}))
	// Counter bumps to 2; guard_InactiveGracePeriodExceeded = (2 >= 3) = false → stays Observing.
	assert.Equal(t, State_Observing, c.GetCurrentState())
	assert.Equal(t, 2, c.heartbeatIntervalsSinceLastReceive, "counter must be incremented")
}

// When a delegation request arrives in Observing and this node is higher priority than the current
// active coordinator, it processes the delegations and transitions to Elect to initiate a handover.
func TestCoordinator_WhenObserving_DelegatedTransactions_HigherPriority_TransitionsToElect(t *testing.T) {
	ctx := t.Context()
	c, mocks := NewCoordinatorBuilderForTesting(t, State_Observing).
		NodeName("node1").
		CurrentActiveCoordinator("node2"). // node1 is higher priority than node2
		CoordinatorPriorityList("node1", "node2", "node3").
		WithMockTransportWriter().
		Build()
	// action_ProcessDelegatedTransactions sends an acknowledgment.
	mocks.TransportWriter.EXPECT().SendDelegationRequestAcknowledgment(mock.Anything, "originator-node", "del-1", mock.Anything, mock.Anything, mock.Anything).Return(nil)
	// OnTransitionTo Elect fires action_SendHandoverRequest.
	mocks.TransportWriter.EXPECT().SendHandoverRequest(mock.Anything, "node2", mock.Anything).Return(nil)

	require.NoError(t, c.stateMachineEventLoop.ProcessEvent(ctx, &TransactionsDelegatedEvent{
		FromNode:     "originator-node",
		Originator:   "sender@originator-node",
		DelegationID: "del-1",
	}))
	// guard_IsHigherPriorityThanCurrentActive = true (node1 at index 0 < node2 at index 1) → Elect.
	assert.Equal(t, State_Elect, c.GetCurrentState())
}

// When a delegation request arrives in Observing and this node is lower priority than the current
// active coordinator, it rejects the delegation (sending the active coordinator's identity back) and
// stays Observing.
func TestCoordinator_WhenObserving_DelegatedTransactions_LowerPriority_RejectsAndStaysObserving(t *testing.T) {
	ctx := t.Context()
	c, mocks := NewCoordinatorBuilderForTesting(t, State_Observing).
		NodeName("node3").
		CurrentActiveCoordinator("node1"). // node3 is lower priority than node1
		CoordinatorPriorityList("node1", "node2", "node3").
		WithMockTransportWriter().
		Build()
	// action_RejectDelegationRequest sends a rejection naming the current active coordinator.
	mocks.TransportWriter.EXPECT().SendDelegationRequestRejection(mock.Anything, "originator-node", "del-1", mock.Anything, "node1").Return(nil)

	require.NoError(t, c.stateMachineEventLoop.ProcessEvent(ctx, &TransactionsDelegatedEvent{
		FromNode:     "originator-node",
		Originator:   "sender@originator-node",
		DelegationID: "del-1",
	}))
	// guard_IsHigherPriorityThanCurrentActive = false (node3 at index 2 > node1 at index 0) → stays Observing.
	assert.Equal(t, State_Observing, c.GetCurrentState())
}

// A same-epoch NewBlock in Observing fires only action_UpdateBlockHeight; action_CalculateCoordinatorPriorities
// is guarded by guard_IsOnEpochBoundary and must NOT run.
func TestCoordinator_WhenObserving_NewBlock_NotNewEpoch_UpdatesBlockHeightAndStaysObserving(t *testing.T) {
	ctx := t.Context()
	c, _ := NewCoordinatorBuilderForTesting(t, State_Observing).
		CurrentBlockHeight(100).
		CoordinatorSelectionBlockRange(50).
		Build()
	// Block 120 is in the same epoch as 100 → guard_IsOnEpochBoundary = false.
	require.NoError(t, c.stateMachineEventLoop.ProcessEvent(ctx, &common.NewBlockEvent{BlockHeight: 120}))
	assert.Equal(t, State_Observing, c.GetCurrentState())
	assert.Equal(t, uint64(120), c.currentBlockHeight)
	assert.Empty(t, c.coordinatorPriorityList, "action_CalculateCoordinatorPriorities must NOT run within the same epoch")
}

// ── Elect state transitions ───────────────────────────────────────────────────

// When the active coordinator acknowledges the handover by entering Closing_Flush, Elect → Prepared.
// action_ClearTimeoutSchedules must run so the timers are not left armed while in Prepared.
func TestCoordinator_WhenElect_ActiveCoordinatorStartsFlushing_TransitionsToPrepared(t *testing.T) {
	ctx := t.Context()
	c, _ := NewCoordinatorBuilderForTesting(t, State_Elect).
		NodeName("node1").
		CurrentActiveCoordinator("node2").
		Build()

	event := &common.HeartbeatReceivedEvent{
		FromNode: "node2",
		CoordinatorSnapshot: &common.CoordinatorSnapshot{
			CoordinatorState: common.CoordinatorState_Closing_Flush,
		},
	}
	require.NoError(t, c.stateMachineEventLoop.ProcessEvent(ctx, event))
	assert.Equal(t, State_Prepared, c.GetCurrentState(), "Closing_Flush heartbeat from current active must drive Elect → Prepared")
	// action_ClearTimeoutSchedules ran on the Elect → Prepared transition.
	assert.Nil(t, c.cancelRequestTimeout, "request timeout must be cleared on Elect exit")
	assert.Nil(t, c.cancelStateTimeout, "state timeout must be cleared on Elect exit")
}

// When the outgoing coordinator sends a Closing heartbeat from State_Prepared, the coordinator transitions
// to Active and action_ImportStatesAndLocks runs. action_ImportStatesAndLocks only imports confirmed locks
// (Transaction == nil, ConfirmedAtBlock set) and their associated output states.
func TestCoordinator_WhenPreparedReceivesClosingHeartbeat_TransitionsToActiveAndImportsState(t *testing.T) {
	ctx := t.Context()
	// Start in Prepared — this is the state after the outgoing coordinator acknowledged the handover
	// (Elect → Prepared) and is now completing its flush.
	c, _ := NewCoordinatorBuilderForTesting(t, State_Prepared).
		NodeName("node1").
		CurrentActiveCoordinator("node2"). // node2 is the outgoing coordinator we're waiting on
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
		FromNode: "node2",
		CoordinatorSnapshot: &common.CoordinatorSnapshot{
			CoordinatorState: common.CoordinatorState_Closing,
			Locks:            []*grapher.StateLock{lock},
			OutputStates:     []*grapher.OutputState{outputState},
		},
	}
	require.NoError(t, c.stateMachineEventLoop.ProcessEvent(ctx, event))
	assert.Equal(t, State_Active, c.GetCurrentState())
	assert.NotEmpty(t, c.signingIdentity.value, "OnTransitionTo Active must set signing identity")
	// action_ImportStatesAndLocks ran: the grapher must now hold the imported state and lock.
	exported, err := c.grapher.ExportStatesAndLocks(ctx, "node1")
	require.NoError(t, err)
	assert.Len(t, exported.OutputState, 1, "imported output state must be visible to node1")
	assert.Len(t, exported.LockedState, 1, "imported confirmed lock must be present in grapher")
}

// action_ProcessConfirmedTransactionsFromSnapshot removes any locally-held transactions that were
// already confirmed by the outgoing coordinator. This prevents redundant re-submission after the
// handover completes and the new coordinator becomes Active.
func TestCoordinator_WhenPreparedReceivesClosingHeartbeat_ConfirmedTransactionsInSnapshot_CleanedUp(t *testing.T) {
	ctx := t.Context()

	// Seed a pooled transaction that is recorded as confirmed in the outgoing coordinator's snapshot.
	confirmedTx := coordinatortransactionmocks.NewCoordinatorTransaction(t)
	confirmedTxID := uuid.New()
	confirmedTx.EXPECT().GetID().Return(confirmedTxID).Maybe()
	confirmedTx.EXPECT().GetCurrentState().Return(transaction.State_Pooled).Maybe()
	confirmedTx.EXPECT().GetSnapshot(mock.Anything).Return(&common.SnapshotPooledTransaction{ID: confirmedTxID}, nil, nil).Maybe()

	c, _ := NewCoordinatorBuilderForTesting(t, State_Prepared).
		NodeName("node1").
		CurrentActiveCoordinator("node2").
		PooledTransactions(confirmedTx).
		Build()

	event := &common.HeartbeatReceivedEvent{
		FromNode: "node2",
		CoordinatorSnapshot: &common.CoordinatorSnapshot{
			CoordinatorState: common.CoordinatorState_Closing,
			ConfirmedTransactions: []*common.SnapshotConfirmedTransaction{
				{SnapshotDispatchedTransaction: common.SnapshotDispatchedTransaction{
					SnapshotPooledTransaction: common.SnapshotPooledTransaction{ID: confirmedTxID},
				}},
			},
		},
	}
	require.NoError(t, c.stateMachineEventLoop.ProcessEvent(ctx, event))
	assert.Equal(t, State_Active, c.GetCurrentState())
	// action_ProcessConfirmedTransactionsFromSnapshot must have cleaned up the confirmed transaction.
	assert.NotContains(t, c.transactionsByID, confirmedTxID, "confirmed transaction must be removed from transactionsByID")
}

// When the state timeout fires in Elect, the coordinator gives up waiting and becomes Active directly.
// action_ImportStatesAndLocks does NOT run on this path — no HeartbeatReceivedEvent is involved,
// so the grapher remains empty.
func TestCoordinator_WhenElectStateTimeoutFires_TransitionsToActive(t *testing.T) {
	ctx := t.Context()
	c, _ := NewCoordinatorBuilderForTesting(t, State_Elect).
		NodeName("node1").
		CurrentActiveCoordinator("node2").
		Build()
	// Firing the state-timeout event simulates the wall-clock timer expiring.
	require.NoError(t, c.stateMachineEventLoop.ProcessEvent(ctx, &StateTimeoutIntervalEvent{}))
	assert.Equal(t, State_Active, c.GetCurrentState())
	assert.NotEmpty(t, c.signingIdentity.value, "OnTransitionTo Active must set signing identity")
	// action_ClearTimeoutSchedules ran on exit; both cancel funcs must be nil.
	assert.Nil(t, c.cancelRequestTimeout, "request timeout must be cleared on Elect exit")
	assert.Nil(t, c.cancelStateTimeout, "state timeout must be cleared on Elect exit")
	// action_ImportStatesAndLocks did NOT run: no HeartbeatReceivedEvent on this path, grapher stays empty.
	exported, err := c.grapher.ExportStatesAndLocks(ctx, "node1")
	require.NoError(t, err)
	assert.Empty(t, exported.OutputState, "no states must be imported on state-timeout path")
	assert.Empty(t, exported.LockedState, "no locks must be imported on state-timeout path")
}

// When the request timeout fires in Elect, the pending IdempotentRequest is nudged (re-sent if its
// own timeout has elapsed) and the coordinator stays in Elect. The request timer is NOT re-armed by
// the nudge — that is the responsibility of action_SendHandoverRequest on Elect entry.
func TestCoordinator_WhenElectRequestTimeoutFires_NudgesHandoverRequest(t *testing.T) {
	ctx := t.Context()
	c, mocks := NewCoordinatorBuilderForTesting(t, State_Elect).
		NodeName("node1").
		CurrentActiveCoordinator("node2").
		WithMockTransportWriter().
		Build()
	// Simulate Elect entry: sendHandoverRequest creates the pending request. A freshly constructed
	// IdempotentRequest has requestTime == nil, so its first Nudge() always sends immediately.
	mocks.TransportWriter.EXPECT().SendHandoverRequest(mock.Anything, "node2", mock.Anything).Return(nil).Once()
	c.pendingHandoverRequest = common.NewIdempotentRequest(ctx, c.clock, c.requestTimeout, func(ctx context.Context, _ uuid.UUID) error {
		return c.transportWriter.SendHandoverRequest(ctx, c.currentActiveCoordinator, c.contractAddress)
	})

	require.NoError(t, c.stateMachineEventLoop.ProcessEvent(ctx, &RequestTimeoutIntervalEvent{}))
	assert.Equal(t, State_Elect, c.GetCurrentState(), "request timeout must not change state")
	// action_NudgeHandoverRequest does NOT re-arm the request timer.
	assert.Nil(t, c.cancelRequestTimeout, "request timeout must not be re-armed by nudge")
}

// A heartbeat from the current coordinator while still in Active state keeps the Elect state:
// the coordinator has not started flushing yet, so guard_ActiveCoordinatorStartedFlushing is false.
// action_HeartbeatReceived fires and updates activeCoordinatorState.
func TestCoordinator_WhenElect_StaysElect_OnHeartbeatFromCurrentCoordinator_WhenStillActive(t *testing.T) {
	ctx := t.Context()
	c, _ := NewCoordinatorBuilderForTesting(t, State_Elect).
		NodeName("node1").
		CurrentActiveCoordinator("prev"). // the outgoing coordinator
		Build()
	event := &common.HeartbeatReceivedEvent{
		FromNode: "prev",
		CoordinatorSnapshot: &common.CoordinatorSnapshot{
			CoordinatorState: common.CoordinatorState_Active, // still Active — not flushing yet
		},
	}
	require.NoError(t, c.stateMachineEventLoop.ProcessEvent(ctx, event))
	assert.Equal(t, State_Elect, c.GetCurrentState())
	// guard_ActiveCoordinatorStartedFlushing is false (Active is not Flush/Closing); no transition.
}

// When a higher-priority node is detected in Elect, the coordinator steps back to Observing.
// action_ClearTimeoutSchedules must run as part of the transition so timers are not left armed.
func TestCoordinator_WhenElect_HigherPriorityHeartbeat_TransitionsToObserving(t *testing.T) {
	ctx := t.Context()
	c, _ := NewCoordinatorBuilderForTesting(t, State_Elect).
		NodeName("node2").
		CurrentActiveCoordinator("node3"). // node3 is who we asked to hand over
		CoordinatorPriorityList("node1", "node2", "node3").
		Build()

	// Heartbeat from node1 (higher priority, Active) — sets receivedHigherPriorityActiveHeartbeat.
	event := &common.HeartbeatReceivedEvent{
		FromNode: "node1",
		CoordinatorSnapshot: &common.CoordinatorSnapshot{
			CoordinatorState: common.CoordinatorState_Active,
		},
	}
	require.NoError(t, c.stateMachineEventLoop.ProcessEvent(ctx, event))
	assert.Equal(t, State_Observing, c.GetCurrentState(), "higher-priority active heartbeat must drive Elect → Observing")
	// action_ClearTimeoutSchedules ran on the Elect → Observing transition.
	assert.Nil(t, c.cancelRequestTimeout, "request timeout must be cleared on Elect exit")
	assert.Nil(t, c.cancelStateTimeout, "state timeout must be cleared on Elect exit")
}

// A new block-range epoch in Elect updates the priority list and block height but keeps the state as Elect.
// Epoch changes do not trigger transitions in Elect; the node continues waiting for the outgoing coordinator
// to start flushing (or for the handover timeout to expire).
func TestCoordinator_WhenElect_NewBlock_UpdatesPriorityListAndStaysElect(t *testing.T) {
	ctx := t.Context()
	c, _ := NewCoordinatorBuilderForTesting(t, State_Elect).
		NodeName("node1").
		CurrentActiveCoordinator("prev").
		CurrentBlockHeight(100).
		CoordinatorSelectionBlockRange(50).
		EndorserCandidates("node1", "node2", "node3").
		CoordinatorSelectionMode(prototk.ContractConfig_COORDINATOR_ENDORSER).
		Build()
	require.NoError(t, c.stateMachineEventLoop.ProcessEvent(ctx, &common.NewBlockEvent{BlockHeight: 150}))
	// No transition — epoch change has no exit condition in Elect.
	assert.Equal(t, State_Elect, c.GetCurrentState())
	assert.Equal(t, uint64(150), c.currentBlockHeight, "action_UpdateBlockHeight must have run")
	// action_CalculateCoordinatorPriorities updated the priority list
	assert.NotEmpty(t, c.coordinatorPriorityList)
}

// HeartbeatInterval in Elect fires action_PropagateHeartbeatIntervalToTransactions and
// action_SendHeartbeat; no exit condition for heartbeat intervals exists so the state stays Elect.
func TestCoordinator_WhenElect_HeartbeatInterval_PropagatesAndSendsHeartbeatAndStaysElect(t *testing.T) {
	ctx := t.Context()
	c, mocks := NewCoordinatorBuilderForTesting(t, State_Elect).
		NodeName("node1").
		CurrentActiveCoordinator("node2").
		EndorserCandidates("node2"). // gives action_SendHeartbeat a recipient
		CoordinatorSelectionMode(prototk.ContractConfig_COORDINATOR_ENDORSER).
		Build()
	require.NoError(t, c.stateMachineEventLoop.ProcessEvent(ctx, &common.HeartbeatIntervalEvent{}))
	assert.Equal(t, State_Elect, c.GetCurrentState())
	assert.True(t, mocks.SentMessageRecorder.HasSentHeartbeat(), "action_SendHeartbeat must fire in Elect HeartbeatInterval")
}

// Delegations arriving in Elect are accepted so originators are not bounced during handover.
// action_ProcessDelegatedTransactions acknowledges the delegation; no state transition occurs.
func TestCoordinator_WhenElect_DelegatedTransactions_AcceptsAndStaysElect(t *testing.T) {
	ctx := t.Context()
	c, _ := NewCoordinatorBuilderForTesting(t, State_Elect).
		NodeName("node1").
		CurrentActiveCoordinator("node2").
		Build()
	require.NoError(t, c.stateMachineEventLoop.ProcessEvent(ctx, &TransactionsDelegatedEvent{
		FromNode:     "originator-node",
		Originator:   "sender@originator-node",
		DelegationID: "del-1",
	}))
	assert.Equal(t, State_Elect, c.GetCurrentState())
}

// A HandoverRequest from a higher-priority node in Elect with dispatched transactions inflight
// cleans up non-dispatched work and transitions to Closing_Flush to drain dispatched transactions.
func TestCoordinator_WhenElect_HandoverRequest_HigherPriority_HasDispatched_TransitionsToClosingFlush(t *testing.T) {
	ctx := t.Context()
	txDispatched, _ := newDispatchedTxMock(t)
	c, _ := NewCoordinatorBuilderForTesting(t, State_Elect).
		NodeName("node2").
		CurrentActiveCoordinator("node3").
		CoordinatorPriorityList("node1", "node2", "node3").
		EndorserCandidates("node3"). // for OnTransitionTo Closing_Flush heartbeat
		CoordinatorSelectionMode(prototk.ContractConfig_COORDINATOR_ENDORSER).
		Transactions(txDispatched).
		Build()
	require.NoError(t, c.stateMachineEventLoop.ProcessEvent(ctx, &HandoverRequestEvent{
		FromNode: "node1",
	}))
	// validator_IsHandoverRequestFromHigherPriorityCoordinator: IsHigherPriority(list, "node1", "node2") = true
	// guard_HasUnconfirmedDispatchedTransactions = true → Closing_Flush
	assert.Equal(t, State_Closing_Flush, c.GetCurrentState())
	assert.Equal(t, "node1", c.currentActiveCoordinator, "action_UpdateActiveCoordinator must record the requesting node")
}

// A HandoverRequest from a higher-priority node in Elect with no dispatched transactions
// transitions directly to Closing.
func TestCoordinator_WhenElect_HandoverRequest_HigherPriority_NoDispatched_TransitionsToClosing(t *testing.T) {
	ctx := t.Context()
	c, _ := NewCoordinatorBuilderForTesting(t, State_Elect).
		NodeName("node2").
		CurrentActiveCoordinator("node3").
		CoordinatorPriorityList("node1", "node2", "node3").
		EndorserCandidates("node3"). // for OnTransitionTo Closing heartbeat
		CoordinatorSelectionMode(prototk.ContractConfig_COORDINATOR_ENDORSER).
		Build()
	require.NoError(t, c.stateMachineEventLoop.ProcessEvent(ctx, &HandoverRequestEvent{
		FromNode: "node1",
	}))
	// guard_HasUnconfirmedDispatchedTransactions = false → Closing
	assert.Equal(t, State_Closing, c.GetCurrentState())
	assert.Equal(t, "node1", c.currentActiveCoordinator, "action_UpdateActiveCoordinator must record the requesting node")
}

// A TransactionStateTransition to Final in Elect runs action_CleanUpTransaction to remove the
// transaction from memory; the coordinator stays in Elect.
func TestCoordinator_WhenElect_TransactionStateTransition_ToFinal_CleansUpAndStaysElect(t *testing.T) {
	ctx := t.Context()
	txFinal := coordinatortransactionmocks.NewCoordinatorTransaction(t)
	txID := uuid.New()
	txFinal.EXPECT().GetID().Return(txID).Maybe()
	txFinal.EXPECT().GetCurrentState().Return(transaction.State_Final).Maybe()
	c, _ := NewCoordinatorBuilderForTesting(t, State_Elect).
		NodeName("node1").
		CurrentActiveCoordinator("node2").
		Transactions(txFinal).
		Build()
	require.Equal(t, 1, len(c.transactionsByID))
	require.NoError(t, c.stateMachineEventLoop.ProcessEvent(ctx, &common.TransactionStateTransitionEvent[transaction.State]{
		TransactionID: txID,
		ToState:       transaction.State_Final,
	}))
	assert.Equal(t, State_Elect, c.GetCurrentState())
	assert.Empty(t, c.transactionsByID, "action_CleanUpTransaction must remove the finalised transaction")
}

// When a higher-priority heartbeat arrives in Elect and only Confirmed (not Dispatched) transactions
// remain after action_CleanUpTransactionsNotYetDispatched, the coordinator moves to Closing.
func TestCoordinator_WhenElect_HigherPriorityHeartbeat_HasInflightNoDispatched_TransitionsToClosing(t *testing.T) {
	ctx := t.Context()
	txConfirmed := coordinatortransactionmocks.NewCoordinatorTransaction(t)
	txID := uuid.New()
	txConfirmed.EXPECT().GetID().Return(txID).Maybe()
	txConfirmed.EXPECT().GetCurrentState().Return(transaction.State_Confirmed).Maybe()
	// GetSnapshot is called by action_SendHeartbeat in OnTransitionTo Closing.
	txConfirmed.EXPECT().GetSnapshot(mock.Anything).Return(nil, nil, nil).Maybe()
	c, _ := NewCoordinatorBuilderForTesting(t, State_Elect).
		NodeName("node2").
		CurrentActiveCoordinator("node3").
		CoordinatorPriorityList("node1", "node2", "node3").
		EndorserCandidates("node3"). // for OnTransitionTo Closing heartbeat
		CoordinatorSelectionMode(prototk.ContractConfig_COORDINATOR_ENDORSER).
		Transactions(txConfirmed).
		Build()
	require.NoError(t, c.stateMachineEventLoop.ProcessEvent(ctx, &common.HeartbeatReceivedEvent{
		FromNode: "node1",
		CoordinatorSnapshot: &common.CoordinatorSnapshot{
			CoordinatorState: common.CoordinatorState_Active,
		},
	}))
	// Confirmed txns survive action_CleanUpTransactionsNotYetDispatched (Confirmed is excluded).
	// guard_HasTransactionsInflight = true, guard_HasUnconfirmedDispatchedTransactions = false → Closing.
	assert.Equal(t, State_Closing, c.GetCurrentState())
}

// When a higher-priority heartbeat arrives in Elect and there are dispatched transactions inflight,
// the coordinator moves to Closing_Flush to drain them before handing over.
func TestCoordinator_WhenElect_HigherPriorityHeartbeat_HasInflightAndDispatched_TransitionsToClosingFlush(t *testing.T) {
	ctx := t.Context()
	txDispatched, _ := newDispatchedTxMock(t)
	c, _ := NewCoordinatorBuilderForTesting(t, State_Elect).
		NodeName("node2").
		CurrentActiveCoordinator("node3").
		CoordinatorPriorityList("node1", "node2", "node3").
		EndorserCandidates("node3"). // for OnTransitionTo Closing_Flush heartbeat
		CoordinatorSelectionMode(prototk.ContractConfig_COORDINATOR_ENDORSER).
		Transactions(txDispatched).
		Build()
	require.NoError(t, c.stateMachineEventLoop.ProcessEvent(ctx, &common.HeartbeatReceivedEvent{
		FromNode: "node1",
		CoordinatorSnapshot: &common.CoordinatorSnapshot{
			CoordinatorState: common.CoordinatorState_Active,
		},
	}))
	// guard_HasTransactionsInflight = true, guard_HasUnconfirmedDispatchedTransactions = true → Closing_Flush.
	assert.Equal(t, State_Closing_Flush, c.GetCurrentState())
}

// ── Prepared state transitions ────────────────────────────────────────────────

// HeartbeatInterval in Prepared within the inactive grace period increments the liveness counter
// and sends a heartbeat; no transition occurs until the grace period is exceeded.
func TestCoordinator_WhenPrepared_HeartbeatInterval_WithinGrace_SendsHeartbeatAndStaysPrepared(t *testing.T) {
	ctx := t.Context()
	c, mocks := NewCoordinatorBuilderForTesting(t, State_Prepared).
		NodeName("node1").
		CurrentActiveCoordinator("node2").
		HeartbeatIntervalsSinceLastReceive(0).
		InactiveGracePeriod(3).      // after increment: 1 < 3 → no transition
		EndorserCandidates("node2"). // for action_SendHeartbeat
		CoordinatorSelectionMode(prototk.ContractConfig_COORDINATOR_ENDORSER).
		Build()
	require.NoError(t, c.stateMachineEventLoop.ProcessEvent(ctx, &common.HeartbeatIntervalEvent{}))
	assert.Equal(t, State_Prepared, c.GetCurrentState())
	assert.Equal(t, 1, c.heartbeatIntervalsSinceLastReceive)
	assert.True(t, mocks.SentMessageRecorder.HasSentHeartbeat(), "action_SendHeartbeat must fire in Prepared HeartbeatInterval")
}

// HeartbeatInterval in Prepared when the inactive grace period is exceeded means the outgoing
// coordinator has gone silent; the node gives up waiting and becomes the active coordinator.
func TestCoordinator_WhenPrepared_HeartbeatInterval_GraceExceeded_TransitionsToActive(t *testing.T) {
	ctx := t.Context()
	c, _ := NewCoordinatorBuilderForTesting(t, State_Prepared).
		NodeName("node1").
		CurrentActiveCoordinator("node2").
		HeartbeatIntervalsSinceLastReceive(2).
		InactiveGracePeriod(3). // after increment: 3 >= 3 → Active
		Build()
	require.NoError(t, c.stateMachineEventLoop.ProcessEvent(ctx, &common.HeartbeatIntervalEvent{}))
	// guard_InactiveGracePeriodExceeded = true → transitions to Active
	assert.Equal(t, State_Active, c.GetCurrentState())
}

// A Closing_Flush heartbeat from the current active coordinator in Prepared resets the
// liveness counter so the timeout does not expire prematurely; no state transition occurs.
func TestCoordinator_WhenPrepared_HeartbeatReceived_ClosingFlushFromCurrentActive_ResetsCounterAndStaysPrepared(t *testing.T) {
	ctx := t.Context()
	c, _ := NewCoordinatorBuilderForTesting(t, State_Prepared).
		NodeName("node1").
		CurrentActiveCoordinator("node2").
		HeartbeatIntervalsSinceLastReceive(5).
		InactiveGracePeriod(3).
		Build()
	require.NoError(t, c.stateMachineEventLoop.ProcessEvent(ctx, &common.HeartbeatReceivedEvent{
		FromNode: "node2",
		CoordinatorSnapshot: &common.CoordinatorSnapshot{
			CoordinatorState: common.CoordinatorState_Closing_Flush,
		},
	}))
	// ValidatorOr(IsFromCurrentActive AND IsClosingFlush, IsFromHigherPriority) → true
	// → action_ResetHeartbeatIntervalsSinceLastReceive fires; no transition.
	assert.Equal(t, State_Prepared, c.GetCurrentState())
	assert.Equal(t, 0, c.heartbeatIntervalsSinceLastReceive, "action_ResetHeartbeatIntervalsSinceLastReceive must clear the counter")
}

// A higher-priority live heartbeat in Prepared with no transactions inflight causes the node
// to stand down and transition to Observing.
func TestCoordinator_WhenPrepared_HeartbeatReceived_HigherPriority_NoInflight_TransitionsToObserving(t *testing.T) {
	ctx := t.Context()
	c, _ := NewCoordinatorBuilderForTesting(t, State_Prepared).
		NodeName("node2").
		CurrentActiveCoordinator("node3").
		CoordinatorPriorityList("node1", "node2", "node3").
		Build()
	require.NoError(t, c.stateMachineEventLoop.ProcessEvent(ctx, &common.HeartbeatReceivedEvent{
		FromNode: "node1",
		CoordinatorSnapshot: &common.CoordinatorSnapshot{
			CoordinatorState: common.CoordinatorState_Active,
		},
	}))
	// guard_HasTransactionsInflight = false → GuardNot = true → Observing
	assert.Equal(t, State_Observing, c.GetCurrentState())
	assert.Nil(t, c.cancelRequestTimeout, "action_ClearTimeoutSchedules must run on Prepared → Observing")
	assert.Nil(t, c.cancelStateTimeout, "action_ClearTimeoutSchedules must run on Prepared → Observing")
}

// A higher-priority live heartbeat in Prepared with inflight (Confirmed) but no dispatched
// transactions causes action_CleanUpTransactionsNotYetDispatched to preserve Confirmed txns and
// the coordinator to move to Closing.
func TestCoordinator_WhenPrepared_HeartbeatReceived_HigherPriority_HasInflightNoDispatched_TransitionsToClosing(t *testing.T) {
	ctx := t.Context()
	txConfirmed := coordinatortransactionmocks.NewCoordinatorTransaction(t)
	txID := uuid.New()
	txConfirmed.EXPECT().GetID().Return(txID).Maybe()
	txConfirmed.EXPECT().GetCurrentState().Return(transaction.State_Confirmed).Maybe()
	// GetSnapshot is called by action_SendHeartbeat in OnTransitionTo Closing.
	txConfirmed.EXPECT().GetSnapshot(mock.Anything).Return(nil, nil, nil).Maybe()
	c, _ := NewCoordinatorBuilderForTesting(t, State_Prepared).
		NodeName("node2").
		CurrentActiveCoordinator("node3").
		CoordinatorPriorityList("node1", "node2", "node3").
		EndorserCandidates("node3"). // for OnTransitionTo Closing heartbeat
		CoordinatorSelectionMode(prototk.ContractConfig_COORDINATOR_ENDORSER).
		Transactions(txConfirmed).
		Build()
	require.NoError(t, c.stateMachineEventLoop.ProcessEvent(ctx, &common.HeartbeatReceivedEvent{
		FromNode: "node1",
		CoordinatorSnapshot: &common.CoordinatorSnapshot{
			CoordinatorState: common.CoordinatorState_Active,
		},
	}))
	// action_CleanUpTransactionsNotYetDispatched preserves Confirmed txns.
	// guard_HasTransactionsInflight = true, guard_HasUnconfirmedDispatchedTransactions = false → Closing.
	assert.Equal(t, State_Closing, c.GetCurrentState())
}

// A higher-priority live heartbeat in Prepared with dispatched transactions inflight causes
// the node to move to Closing_Flush to drain dispatched transactions before standing down.
func TestCoordinator_WhenPrepared_HeartbeatReceived_HigherPriority_HasInflightAndDispatched_TransitionsToClosingFlush(t *testing.T) {
	ctx := t.Context()
	txDispatched, _ := newDispatchedTxMock(t)
	c, _ := NewCoordinatorBuilderForTesting(t, State_Prepared).
		NodeName("node2").
		CurrentActiveCoordinator("node3").
		CoordinatorPriorityList("node1", "node2", "node3").
		EndorserCandidates("node3"). // for OnTransitionTo Closing_Flush heartbeat
		CoordinatorSelectionMode(prototk.ContractConfig_COORDINATOR_ENDORSER).
		Transactions(txDispatched).
		Build()
	require.NoError(t, c.stateMachineEventLoop.ProcessEvent(ctx, &common.HeartbeatReceivedEvent{
		FromNode: "node1",
		CoordinatorSnapshot: &common.CoordinatorSnapshot{
			CoordinatorState: common.CoordinatorState_Active,
		},
	}))
	// guard_HasTransactionsInflight = true, guard_HasUnconfirmedDispatchedTransactions = true → Closing_Flush.
	assert.Equal(t, State_Closing_Flush, c.GetCurrentState())
}

// A HandoverRequest from a higher-priority node in Prepared with dispatched transactions
// transitions to Closing_Flush.
func TestCoordinator_WhenPrepared_HandoverRequest_HigherPriority_HasDispatched_TransitionsToClosingFlush(t *testing.T) {
	ctx := t.Context()
	txDispatched, _ := newDispatchedTxMock(t)
	c, _ := NewCoordinatorBuilderForTesting(t, State_Prepared).
		NodeName("node2").
		CurrentActiveCoordinator("node3").
		CoordinatorPriorityList("node1", "node2", "node3").
		EndorserCandidates("node3"). // for OnTransitionTo Closing_Flush heartbeat
		CoordinatorSelectionMode(prototk.ContractConfig_COORDINATOR_ENDORSER).
		Transactions(txDispatched).
		Build()
	require.NoError(t, c.stateMachineEventLoop.ProcessEvent(ctx, &HandoverRequestEvent{
		FromNode: "node1",
	}))
	// guard_HasUnconfirmedDispatchedTransactions = true → Closing_Flush
	assert.Equal(t, State_Closing_Flush, c.GetCurrentState())
	assert.Equal(t, "node1", c.currentActiveCoordinator, "action_UpdateActiveCoordinator must record the requesting node")
}

// A HandoverRequest from a higher-priority node in Prepared with no dispatched transactions
// transitions directly to Closing.
func TestCoordinator_WhenPrepared_HandoverRequest_HigherPriority_NoDispatched_TransitionsToClosing(t *testing.T) {
	ctx := t.Context()
	c, _ := NewCoordinatorBuilderForTesting(t, State_Prepared).
		NodeName("node2").
		CurrentActiveCoordinator("node3").
		CoordinatorPriorityList("node1", "node2", "node3").
		EndorserCandidates("node3"). // for OnTransitionTo Closing heartbeat
		CoordinatorSelectionMode(prototk.ContractConfig_COORDINATOR_ENDORSER).
		Build()
	require.NoError(t, c.stateMachineEventLoop.ProcessEvent(ctx, &HandoverRequestEvent{
		FromNode: "node1",
	}))
	// guard_HasUnconfirmedDispatchedTransactions = false → Closing
	assert.Equal(t, State_Closing, c.GetCurrentState())
	assert.Equal(t, "node1", c.currentActiveCoordinator, "action_UpdateActiveCoordinator must record the requesting node")
}

// Delegations arriving in Prepared are accepted so originators are not bounced while waiting
// for the outgoing coordinator to complete flushing. State stays Prepared.
func TestCoordinator_WhenPrepared_DelegatedTransactions_AcceptsAndStaysPrepared(t *testing.T) {
	ctx := t.Context()
	c, _ := NewCoordinatorBuilderForTesting(t, State_Prepared).
		NodeName("node1").
		CurrentActiveCoordinator("node2").
		Build()
	require.NoError(t, c.stateMachineEventLoop.ProcessEvent(ctx, &TransactionsDelegatedEvent{
		FromNode:     "originator-node",
		Originator:   "sender@originator-node",
		DelegationID: "del-2",
	}))
	assert.Equal(t, State_Prepared, c.GetCurrentState())
}

// A new-epoch NewBlock in Prepared runs action_UpdateBlockHeight and action_CalculateCoordinatorPriorities;
// no state transition occurs.
func TestCoordinator_WhenPrepared_NewBlock_NewEpoch_UpdatesPriorityListAndStaysPrepared(t *testing.T) {
	ctx := t.Context()
	c, _ := NewCoordinatorBuilderForTesting(t, State_Prepared).
		NodeName("node1").
		CurrentActiveCoordinator("node2").
		CurrentBlockHeight(100).
		CoordinatorSelectionBlockRange(50).
		EndorserCandidates("node1", "node2", "node3").
		CoordinatorSelectionMode(prototk.ContractConfig_COORDINATOR_ENDORSER).
		Build()
	require.NoError(t, c.stateMachineEventLoop.ProcessEvent(ctx, &common.NewBlockEvent{BlockHeight: 150}))
	assert.Equal(t, State_Prepared, c.GetCurrentState())
	assert.Equal(t, uint64(150), c.currentBlockHeight, "action_UpdateBlockHeight must have run")
	assert.NotEmpty(t, c.coordinatorPriorityList, "action_CalculateCoordinatorPriorities must have run")
}

// A TransactionStateTransition to Final in Prepared runs action_CleanUpTransaction and stays Prepared.
func TestCoordinator_WhenPrepared_TransactionStateTransition_ToFinal_CleansUpAndStaysPrepared(t *testing.T) {
	ctx := t.Context()
	txFinal := coordinatortransactionmocks.NewCoordinatorTransaction(t)
	txID := uuid.New()
	txFinal.EXPECT().GetID().Return(txID).Maybe()
	txFinal.EXPECT().GetCurrentState().Return(transaction.State_Final).Maybe()
	c, _ := NewCoordinatorBuilderForTesting(t, State_Prepared).
		NodeName("node1").
		CurrentActiveCoordinator("node2").
		Transactions(txFinal).
		Build()
	require.Equal(t, 1, len(c.transactionsByID))
	require.NoError(t, c.stateMachineEventLoop.ProcessEvent(ctx, &common.TransactionStateTransitionEvent[transaction.State]{
		TransactionID: txID,
		ToState:       transaction.State_Final,
	}))
	assert.Equal(t, State_Prepared, c.GetCurrentState())
	assert.Empty(t, c.transactionsByID, "action_CleanUpTransaction must remove the finalised transaction")
}

// ── Active state transitions ──────────────────────────────────────────────────

// When no transactions are inflight in Active and a heartbeat interval fires, transition to Idle.
// action_SendHeartbeat fires as part of the HeartbeatInterval handler before the Idle transition.
func TestCoordinator_WhenActive_TransitionsToIdle_OnHeartbeatInterval_WhenNoInflight(t *testing.T) {
	ctx := t.Context()
	c, mocks := NewCoordinatorBuilderForTesting(t, State_Active).
		NodeName("node1").
		CurrentActiveCoordinator("node1").
		EndorserCandidates("node2"). // gives action_SendHeartbeat a recipient
		CoordinatorSelectionMode(prototk.ContractConfig_COORDINATOR_ENDORSER).
		Build()
	require.NoError(t, c.stateMachineEventLoop.ProcessEvent(ctx, &common.HeartbeatIntervalEvent{}))
	// guard_HasTransactionsInflight = false (no txns); GuardNot(HasTransactionsInflight) = true
	assert.Equal(t, State_Idle, c.GetCurrentState())
	// action_SendHeartbeat ran during the Active HeartbeatInterval handler
	assert.True(t, mocks.SentMessageRecorder.HasSentHeartbeat(), "action_SendHeartbeat must fire in Active HeartbeatInterval")
}

// A new-epoch NewBlock where the signing identity has been used and a dispatched transaction is still
// in-flight → Active_Flush. The signing identity must be rotated but we cannot do it in place
// because dispatched transactions have not settled yet.
func TestCoordinator_WhenActiveAndEpochChangesWithSigningUsedAndInflightDispatched_TransitionsToActiveFLush(t *testing.T) {
	ctx := t.Context()
	txDispatched, _ := newDispatchedTxMock(t)
	c, _ := NewCoordinatorBuilderForTesting(t, State_Active).
		NodeName("node1").
		CurrentActiveCoordinator("node1").
		CurrentBlockHeight(100).
		CoordinatorSelectionBlockRange(50).
		SigningIdentityUsed(true). // a transaction used the signing identity since the last rotation
		Transactions(txDispatched).
		Build()
	require.NoError(t, c.stateMachineEventLoop.ProcessEvent(ctx, &common.NewBlockEvent{BlockHeight: 150}))
	// guard_SigningIdentityUsed = true, guard_FlushComplete = false → key-rotation Active_Flush
	assert.Equal(t, State_Active_Flush, c.GetCurrentState())
}

// A new-epoch NewBlock where the signing identity was used and there are no dispatched transactions (only
// pooled ones) → key is rotated in place without a state transition. guard_FlushComplete returns true because
// pooled transactions (State_Pooled) are not past the point of no return. The pooled transaction remains in
// the pool; it will pick up the new signing identity when it is eventually dispatched.
func TestCoordinator_WhenActiveAndEpochChangesWithSigningUsedAndOnlyPooledTxs_RotatesKeyInPlace(t *testing.T) {
	ctx := t.Context()
	pooledTx := coordinatortransactionmocks.NewCoordinatorTransaction(t)
	pooledTxID := uuid.New()
	pooledTx.EXPECT().GetID().Return(pooledTxID).Maybe()
	pooledTx.EXPECT().GetCurrentState().Return(transaction.State_Pooled).Maybe()

	c, _ := NewCoordinatorBuilderForTesting(t, State_Active).
		NodeName("node2").
		CurrentActiveCoordinator("node2").
		CurrentBlockHeight(100).
		CoordinatorSelectionBlockRange(50).
		SigningIdentityUsed(true). // a transaction retrieved the signing identity since the last rotation
		PooledTransactions(pooledTx).
		CoordinatorSelectionMode(prototk.ContractConfig_COORDINATOR_ENDORSER).
		Build()
	prevIdentity := c.signingIdentity.value
	require.Equal(t, 1, len(c.transactionsByID), "pooled tx must be registered before event")
	require.NoError(t, c.stateMachineEventLoop.ProcessEvent(ctx, &common.NewBlockEvent{BlockHeight: 150}))
	// guard_SigningIdentityUsed = true, guard_FlushComplete = true → action_NewSigningIdentity (in-place rotation)
	assert.Equal(t, State_Active, c.GetCurrentState(), "key-rotation does not change state when flush is already complete")
	// action_NewSigningIdentity rotated the key in place
	assert.NotEqual(t, prevIdentity, c.signingIdentity.value, "signing identity must be refreshed on epoch boundary when used")
	// The pooled transaction stays in the pool: transaction selection is independent of key rotation.
	// When it is eventually dispatched it will call getCoordinatorSigningIdentity and receive the new key.
	assert.Equal(t, 1, len(c.transactionsByID), "transaction must remain registered after in-place key rotation")
	assert.Equal(t, 1, len(c.pooledTransactions), "pooled transaction stays in pool; selection is not triggered by key rotation")
}

// A new-epoch NewBlock where the signing identity was NOT used → the key is still rotated in place
// (rotation happens on every epoch boundary regardless of use) and no state transition occurs.
func TestCoordinator_WhenActiveAndEpochChanges_SigningNotUsed_StaysActiveAndRotatesKey(t *testing.T) {
	ctx := t.Context()
	c, _ := NewCoordinatorBuilderForTesting(t, State_Active).
		NodeName("node1").
		CurrentActiveCoordinator("node1").
		CurrentBlockHeight(100).
		CoordinatorSelectionBlockRange(50).
		EndorserCandidates("node1", "node2", "node3").
		CoordinatorSelectionMode(prototk.ContractConfig_COORDINATOR_ENDORSER).
		Build()
	prevIdentity := c.signingIdentity.value
	require.NoError(t, c.stateMachineEventLoop.ProcessEvent(ctx, &common.NewBlockEvent{BlockHeight: 150}))
	assert.Equal(t, State_Active, c.GetCurrentState())
	// Key is rotated on every epoch boundary, even when it was not used
	assert.NotEqual(t, prevIdentity, c.signingIdentity.value, "signing identity must be rotated on every epoch boundary")
	// action_CalculateCoordinatorPriorities updated the priority list
	assert.NotEmpty(t, c.coordinatorPriorityList, "priority list must be populated")
	assert.Equal(t, uint64(150), c.currentBlockHeight, "block height must be updated")
}

// Active preemption via a higher-priority heartbeat: action_CleanUpTransactionsNotYetDispatched removes
// pooled transactions, then the coordinator transitions to Closing_Flush. This is the correct step-down path —
// Active does NOT transition directly to Closing; it first drains any dispatched transactions.
func TestCoordinator_WhenActive_HigherPriorityHeartbeat_CleansUpPooledAndTransitionsToClosingFlush(t *testing.T) {
	ctx := t.Context()
	pooledTx := coordinatortransactionmocks.NewCoordinatorTransaction(t)
	pooledTxID := uuid.New()
	pooledTx.EXPECT().GetID().Return(pooledTxID).Maybe()
	pooledTx.EXPECT().GetCurrentState().Return(transaction.State_Pooled).Maybe()

	c, _ := NewCoordinatorBuilderForTesting(t, State_Active).
		NodeName("node3"). // node3 is lower priority than node1
		CurrentActiveCoordinator("node3").
		EndorserCandidates("node1", "node2", "node3").
		CoordinatorSelectionMode(prototk.ContractConfig_COORDINATOR_ENDORSER).
		PooledTransactions(pooledTx).
		CoordinatorPriorityList("node1", "node2", "node3").
		Build()
	require.Equal(t, 1, len(c.transactionsByID), "pooled tx must be registered before event")
	// node1 sends an Active heartbeat while node3 is coordinating → preemption
	require.NoError(t, c.stateMachineEventLoop.ProcessEvent(ctx, &common.HeartbeatReceivedEvent{
		FromNode: "node1",
		CoordinatorSnapshot: &common.CoordinatorSnapshot{
			CoordinatorState: common.CoordinatorState_Active,
		},
	}))
	// action_CleanUpTransactionsNotYetDispatched removed the pooled transaction
	assert.Equal(t, State_Closing_Flush, c.GetCurrentState())
	assert.Equal(t, uint64(0), uint64(len(c.transactionsByID)), "pooled txns must be cleaned up on preemption")
}

// Entering Active via any path fires action_NewSigningIdentity and action_SelectTransaction.
// When transitioning from Prepared → Active via the outgoing coordinator's Closing heartbeat,
// action_SelectTransaction pops pooled transactions and calls HandleEvent(SelectedEvent).
// The Prepared→Active path does not run action_CleanUpTransactionsNotYetDispatched so pooled
// transactions survive and are immediately selected.
func TestCoordinator_WhenPreparedTransitionsToActive_RefreshesSigningIdentityAndSelectsPooledTransactions(t *testing.T) {
	ctx := t.Context()
	pooledTx := coordinatortransactionmocks.NewCoordinatorTransaction(t)
	pooledTxID := uuid.New()
	pooledTx.EXPECT().GetID().Return(pooledTxID).Maybe()
	pooledTx.EXPECT().GetCurrentState().Return(transaction.State_Pooled).Maybe()
	pooledTx.EXPECT().HandleEvent(mock.Anything, mock.AnythingOfType("*transaction.SelectedEvent")).Return(nil).Once()

	c, _ := NewCoordinatorBuilderForTesting(t, State_Prepared).
		NodeName("node1").
		CurrentActiveCoordinator("node2"). // node2 is the outgoing coordinator
		PooledTransactions(pooledTx).
		Build()
	require.NoError(t, c.stateMachineEventLoop.ProcessEvent(ctx, &common.HeartbeatReceivedEvent{
		FromNode: "node2",
		CoordinatorSnapshot: &common.CoordinatorSnapshot{
			CoordinatorState: common.CoordinatorState_Closing,
		},
	}))
	assert.Equal(t, State_Active, c.GetCurrentState())
	assert.NotEmpty(t, c.signingIdentity.value)
	// mock expectation on pooledTx.HandleEvent(SelectedEvent) verified by testify
}

// HeartbeatInterval in Active when there are transactions inflight sends a heartbeat but does
// not transition to Idle because guard_HasTransactionsInflight = true.
func TestCoordinator_WhenActive_HeartbeatInterval_WithInflight_SendsHeartbeatAndStaysActive(t *testing.T) {
	ctx := t.Context()
	txDispatched, _ := newDispatchedTxMock(t)
	c, mocks := NewCoordinatorBuilderForTesting(t, State_Active).
		NodeName("node1").
		CurrentActiveCoordinator("node1").
		EndorserCandidates("node2"). // for action_SendHeartbeat
		CoordinatorSelectionMode(prototk.ContractConfig_COORDINATOR_ENDORSER).
		Transactions(txDispatched).
		Build()
	require.NoError(t, c.stateMachineEventLoop.ProcessEvent(ctx, &common.HeartbeatIntervalEvent{}))
	// guard_HasTransactionsInflight = true → GuardNot = false → no Idle transition
	assert.Equal(t, State_Active, c.GetCurrentState())
	assert.True(t, mocks.SentMessageRecorder.HasSentHeartbeat(), "action_SendHeartbeat must fire in Active HeartbeatInterval")
}

// A HeartbeatReceived event from a lower-priority node fails the validator and is ignored.
// The coordinator stays Active with no state change.
func TestCoordinator_WhenActive_HeartbeatReceived_NotHigherPriority_IgnoresAndStaysActive(t *testing.T) {
	ctx := t.Context()
	c, _ := NewCoordinatorBuilderForTesting(t, State_Active).
		NodeName("node1").
		CurrentActiveCoordinator("node1").
		CoordinatorPriorityList("node1", "node2", "node3").
		Build()
	// node2 has lower priority than node1 (higher index); validator fails → event ignored
	require.NoError(t, c.stateMachineEventLoop.ProcessEvent(ctx, &common.HeartbeatReceivedEvent{
		FromNode: "node2",
		CoordinatorSnapshot: &common.CoordinatorSnapshot{
			CoordinatorState: common.CoordinatorState_Active,
		},
	}))
	assert.Equal(t, State_Active, c.GetCurrentState())
}

// A HandoverRequest from a higher-priority node in Active with dispatched transactions stops the
// dispatch loop, cleans up non-dispatched work, and transitions to Closing_Flush.
func TestCoordinator_WhenActive_HandoverRequest_HigherPriority_HasDispatched_TransitionsToClosingFlush(t *testing.T) {
	ctx := t.Context()
	txDispatched, _ := newDispatchedTxMock(t)
	c, _ := NewCoordinatorBuilderForTesting(t, State_Active).
		NodeName("node2").
		CurrentActiveCoordinator("node2").
		CoordinatorPriorityList("node1", "node2", "node3").
		EndorserCandidates("node1"). // for OnTransitionTo Closing_Flush heartbeat
		CoordinatorSelectionMode(prototk.ContractConfig_COORDINATOR_ENDORSER).
		Transactions(txDispatched).
		Build()
	require.NoError(t, c.stateMachineEventLoop.ProcessEvent(ctx, &HandoverRequestEvent{
		FromNode: "node1",
	}))
	// guard_HasUnconfirmedDispatchedTransactions = true → Closing_Flush
	assert.Equal(t, State_Closing_Flush, c.GetCurrentState())
	assert.Equal(t, "node1", c.currentActiveCoordinator, "action_UpdateActiveCoordinator must record the requesting node")
}

// A HandoverRequest from a higher-priority node in Active with no dispatched transactions
// transitions directly to Closing.
func TestCoordinator_WhenActive_HandoverRequest_HigherPriority_NoDispatched_TransitionsToClosing(t *testing.T) {
	ctx := t.Context()
	c, _ := NewCoordinatorBuilderForTesting(t, State_Active).
		NodeName("node2").
		CurrentActiveCoordinator("node2").
		CoordinatorPriorityList("node1", "node2", "node3").
		EndorserCandidates("node1"). // for OnTransitionTo Closing heartbeat
		CoordinatorSelectionMode(prototk.ContractConfig_COORDINATOR_ENDORSER).
		Build()
	require.NoError(t, c.stateMachineEventLoop.ProcessEvent(ctx, &HandoverRequestEvent{
		FromNode: "node1",
	}))
	// guard_HasUnconfirmedDispatchedTransactions = false → Closing
	assert.Equal(t, State_Closing, c.GetCurrentState())
	assert.Equal(t, "node1", c.currentActiveCoordinator, "action_UpdateActiveCoordinator must record the requesting node")
}

// Delegations arriving in Active are processed by action_ProcessDelegatedTransactions; state stays Active.
func TestCoordinator_WhenActive_DelegatedTransactions_AcceptsAndStaysActive(t *testing.T) {
	ctx := t.Context()
	c, _ := NewCoordinatorBuilderForTesting(t, State_Active).
		NodeName("node1").
		CurrentActiveCoordinator("node1").
		Build()
	require.NoError(t, c.stateMachineEventLoop.ProcessEvent(ctx, &TransactionsDelegatedEvent{
		FromNode:     "originator-node",
		Originator:   "sender@originator-node",
		DelegationID: "del-3",
	}))
	assert.Equal(t, State_Active, c.GetCurrentState())
}

// A NewBlock within the same epoch (not a new block-range epoch) runs action_UpdateBlockHeight
// only; no priority recalculation and no state transition.
func TestCoordinator_WhenActive_NewBlock_NotNewEpoch_UpdatesBlockHeightOnlyAndStaysActive(t *testing.T) {
	ctx := t.Context()
	c, _ := NewCoordinatorBuilderForTesting(t, State_Active).
		NodeName("node1").
		CurrentActiveCoordinator("node1").
		CurrentBlockHeight(100).
		CoordinatorSelectionBlockRange(50). // epoch = 100/50 = 2
		Build()
	prevPriorityList := c.coordinatorPriorityList
	// BlockHeight 120 is in the same epoch as 100 (120/50 = 2 == 100/50 = 2)
	require.NoError(t, c.stateMachineEventLoop.ProcessEvent(ctx, &common.NewBlockEvent{BlockHeight: 120}))
	assert.Equal(t, State_Active, c.GetCurrentState())
	assert.Equal(t, uint64(120), c.currentBlockHeight, "action_UpdateBlockHeight must have run")
	assert.Equal(t, prevPriorityList, c.coordinatorPriorityList, "priority list must not change within an epoch")
}

// A TransactionStateTransition from Dispatched to Pooled (revert) when there is a transaction
// currently assembling fires action_cancelCurrentlyAssemblingTransaction before re-pooling.
func TestCoordinator_WhenActive_TransactionStateTransition_DispatchedToPooled_WithAssembling_CancelsAssembling(t *testing.T) {
	ctx := t.Context()
	txAssembling := coordinatortransactionmocks.NewCoordinatorTransaction(t)
	txAssemblingID := uuid.New()
	txAssembling.EXPECT().GetID().Return(txAssemblingID).Maybe()
	txAssembling.EXPECT().GetCurrentState().Return(transaction.State_Assembling).Maybe()
	// action_cancelCurrentlyAssemblingTransaction sends AssembleCancelledEvent to the assembling tx.
	txAssembling.EXPECT().HandleEvent(mock.Anything, mock.AnythingOfType("*transaction.AssembleCancelledEvent")).Return(nil).Once()

	txDispatched, txDispatchedID := newDispatchedTxMock(t)
	c, _ := NewCoordinatorBuilderForTesting(t, State_Active).
		NodeName("node1").
		CurrentActiveCoordinator("node1").
		Transactions(txAssembling, txDispatched).
		Build()
	require.NoError(t, c.stateMachineEventLoop.ProcessEvent(ctx, &common.TransactionStateTransitionEvent[transaction.State]{
		TransactionID: txDispatchedID,
		FromState:     transaction.State_Dispatched,
		ToState:       transaction.State_Pooled,
	}))
	// action_cancelCurrentlyAssemblingTransaction fired — testify verifies the .Once() expectation.
	// action_SelectTransaction is suppressed because guard_HasTransactionAssembling was still true.
	assert.Equal(t, State_Active, c.GetCurrentState())
}

// A TransactionStateTransition to Pooled (no assembling transaction present) runs action_PoolTransaction
// which adds the transaction back to the pool, then action_SelectTransaction immediately picks it up.
func TestCoordinator_WhenActive_TransactionStateTransition_ToPooled_PoolsAndSelectsTransaction(t *testing.T) {
	ctx := t.Context()
	txReverting := coordinatortransactionmocks.NewCoordinatorTransaction(t)
	txID := uuid.New()
	txReverting.EXPECT().GetID().Return(txID).Maybe()
	txReverting.EXPECT().GetCurrentState().Return(transaction.State_Dispatched).Maybe()
	txReverting.EXPECT().GetSnapshot(mock.Anything).Return(nil, &common.SnapshotDispatchedTransaction{
		SnapshotPooledTransaction: common.SnapshotPooledTransaction{ID: txID},
	}, nil).Maybe()
	// action_NudgeDispatchLoop calls HasDispatchedPublicTransaction on each dispatched transaction.
	txReverting.EXPECT().HasDispatchedPublicTransaction().Return(true).Maybe()
	// action_SelectTransaction will call HandleEvent(SelectedEvent) after pooling.
	txReverting.EXPECT().HandleEvent(mock.Anything, mock.AnythingOfType("*transaction.SelectedEvent")).Return(nil).Once()
	c, _ := NewCoordinatorBuilderForTesting(t, State_Active).
		NodeName("node1").
		CurrentActiveCoordinator("node1").
		Transactions(txReverting).
		Build()
	require.Equal(t, 0, len(c.pooledTransactions))
	require.NoError(t, c.stateMachineEventLoop.ProcessEvent(ctx, &common.TransactionStateTransitionEvent[transaction.State]{
		TransactionID: txID,
		ToState:       transaction.State_Pooled,
	}))
	// action_PoolTransaction added it to pool; action_SelectTransaction immediately selected it.
	assert.Equal(t, State_Active, c.GetCurrentState())
}

// A TransactionStateTransition to ReadyForDispatch runs action_QueueTransactionForDispatch
// which places the transaction onto the dispatch channel.
func TestCoordinator_WhenActive_TransactionStateTransition_ToReadyForDispatch_QueuesForDispatch(t *testing.T) {
	ctx := t.Context()
	txReady := coordinatortransactionmocks.NewCoordinatorTransaction(t)
	txID := uuid.New()
	txReady.EXPECT().GetID().Return(txID).Maybe()
	txReady.EXPECT().GetCurrentState().Return(transaction.State_Ready_For_Dispatch).Maybe()
	c, _ := NewCoordinatorBuilderForTesting(t, State_Active).
		NodeName("node1").
		CurrentActiveCoordinator("node1").
		Transactions(txReady).
		Build()
	require.Equal(t, 0, len(c.dispatchQueue))
	require.NoError(t, c.stateMachineEventLoop.ProcessEvent(ctx, &common.TransactionStateTransitionEvent[transaction.State]{
		TransactionID: txID,
		ToState:       transaction.State_Ready_For_Dispatch,
	}))
	// action_QueueTransactionForDispatch placed the tx on the dispatch channel.
	assert.Equal(t, State_Active, c.GetCurrentState())
	assert.Equal(t, 1, len(c.dispatchQueue), "transaction must be queued for dispatch")
}

// A TransactionStateTransition to Final in Active runs action_CleanUpTransaction; state stays Active.
func TestCoordinator_WhenActive_TransactionStateTransition_ToFinal_CleansUpAndStaysActive(t *testing.T) {
	ctx := t.Context()
	txFinal := coordinatortransactionmocks.NewCoordinatorTransaction(t)
	txID := uuid.New()
	txFinal.EXPECT().GetID().Return(txID).Maybe()
	txFinal.EXPECT().GetCurrentState().Return(transaction.State_Final).Maybe()
	c, _ := NewCoordinatorBuilderForTesting(t, State_Active).
		NodeName("node1").
		CurrentActiveCoordinator("node1").
		Transactions(txFinal).
		Build()
	require.Equal(t, 1, len(c.transactionsByID))
	require.NoError(t, c.stateMachineEventLoop.ProcessEvent(ctx, &common.TransactionStateTransitionEvent[transaction.State]{
		TransactionID: txID,
		ToState:       transaction.State_Final,
	}))
	assert.Equal(t, State_Active, c.GetCurrentState())
	assert.Empty(t, c.transactionsByID, "action_CleanUpTransaction must remove the finalised transaction")
}

// A TransactionStateTransition to Evicted in Active runs action_CleanUpTransaction; state stays Active.
func TestCoordinator_WhenActive_TransactionStateTransition_ToEvicted_CleansUpAndStaysActive(t *testing.T) {
	ctx := t.Context()
	txEvicted := coordinatortransactionmocks.NewCoordinatorTransaction(t)
	txID := uuid.New()
	txEvicted.EXPECT().GetID().Return(txID).Maybe()
	txEvicted.EXPECT().GetCurrentState().Return(transaction.State_Evicted).Maybe()
	c, _ := NewCoordinatorBuilderForTesting(t, State_Active).
		NodeName("node1").
		CurrentActiveCoordinator("node1").
		Transactions(txEvicted).
		Build()
	require.Equal(t, 1, len(c.transactionsByID))
	require.NoError(t, c.stateMachineEventLoop.ProcessEvent(ctx, &common.TransactionStateTransitionEvent[transaction.State]{
		TransactionID: txID,
		ToState:       transaction.State_Evicted,
	}))
	assert.Equal(t, State_Active, c.GetCurrentState())
	assert.Empty(t, c.transactionsByID, "action_CleanUpTransaction must remove the evicted transaction")
}

// ── Active_Flush and Closing_Flush state transitions ──────────────────────────

// When the last inflight transaction finalises in Active_Flush, the coordinator (still active)
// transitions back to Active and rotates its signing key.
func TestCoordinator_WhenActiveFLushCompletesAndStillCurrentCoordinator_TransitionsToActive(t *testing.T) {
	ctx := t.Context()
	txDispatched, txID := newDispatchedTxMock(t)
	c, _ := NewCoordinatorBuilderForTesting(t, State_Active_Flush).
		NodeName("node1").
		CurrentActiveCoordinator("node1").
		Transactions(txDispatched).
		Build()
	event := &common.TransactionStateTransitionEvent[transaction.State]{
		TransactionID: txID,
		FromState:     transaction.State_Dispatched,
		ToState:       transaction.State_Final,
	}
	require.NoError(t, c.stateMachineEventLoop.ProcessEvent(ctx, event))
	assert.Equal(t, State_Active, c.GetCurrentState())
	assert.NotEmpty(t, c.signingIdentity.value, "OnTransitionTo Active must set signing identity")
}

// When the last inflight transaction finalises in Closing_Flush, the coordinator transitions to Closing.
func TestCoordinator_WhenClosingFlushCompletesAndNotCurrentCoordinator_TransitionsToClosing(t *testing.T) {
	ctx := t.Context()
	txDispatched, txID := newDispatchedTxMock(t)
	c, _ := NewCoordinatorBuilderForTesting(t, State_Closing_Flush).
		NodeName("node1").
		CurrentActiveCoordinator("node2"). // another node is now current
		Transactions(txDispatched).
		Build()
	event := &common.TransactionStateTransitionEvent[transaction.State]{
		TransactionID: txID,
		FromState:     transaction.State_Dispatched,
		ToState:       transaction.State_Final,
	}
	require.NoError(t, c.stateMachineEventLoop.ProcessEvent(ctx, event))
	assert.Equal(t, State_Closing, c.GetCurrentState())
}

// A NewBlock epoch crossing in Active_Flush updates block height and recomputes the priority list,
// but stays in Active_Flush.
func TestCoordinator_WhenActiveFlushing_AndNewEpochArrives_UpdatesHeightAndPriorityListButStaysActiveFLush(t *testing.T) {
	ctx := t.Context()
	txDispatched, _ := newDispatchedTxMock(t)
	c, _ := NewCoordinatorBuilderForTesting(t, State_Active_Flush).
		NodeName("node1").
		CurrentActiveCoordinator("node1").
		CurrentBlockHeight(100).
		CoordinatorSelectionBlockRange(50).
		EndorserCandidates("node1", "node2", "node3").
		CoordinatorSelectionMode(prototk.ContractConfig_COORDINATOR_ENDORSER).
		Transactions(txDispatched).
		Build()
	require.NoError(t, c.stateMachineEventLoop.ProcessEvent(ctx, &common.NewBlockEvent{BlockHeight: 150}))
	assert.Equal(t, State_Active_Flush, c.GetCurrentState())
	assert.Equal(t, uint64(150), c.currentBlockHeight)
	assert.NotEmpty(t, c.coordinatorPriorityList, "action_CalculateCoordinatorPriorities must recompute the priority list")
}

// HeartbeatInterval in Active_Flush propagates to transactions and sends a heartbeat;
// there is no exit condition for heartbeat intervals in this state.
func TestCoordinator_WhenActiveFLush_HeartbeatInterval_SendsHeartbeatAndStaysActiveFLush(t *testing.T) {
	ctx := t.Context()
	txDispatched, _ := newDispatchedTxMock(t)
	c, mocks := NewCoordinatorBuilderForTesting(t, State_Active_Flush).
		NodeName("node1").
		CurrentActiveCoordinator("node1").
		EndorserCandidates("node2"). // for action_SendHeartbeat
		CoordinatorSelectionMode(prototk.ContractConfig_COORDINATOR_ENDORSER).
		Transactions(txDispatched).
		Build()
	require.NoError(t, c.stateMachineEventLoop.ProcessEvent(ctx, &common.HeartbeatIntervalEvent{}))
	assert.Equal(t, State_Active_Flush, c.GetCurrentState())
	assert.True(t, mocks.SentMessageRecorder.HasSentHeartbeat(), "action_SendHeartbeat must fire in Active_Flush HeartbeatInterval")
}

// A higher-priority live heartbeat received in Active_Flush causes the coordinator to step down
// to Closing_Flush, updating the active coordinator, clearing timeouts, and cleaning up non-dispatched work.
func TestCoordinator_WhenActiveFLush_HigherPriorityHeartbeat_TransitionsToClosingFlush(t *testing.T) {
	ctx := t.Context()
	txDispatched, _ := newDispatchedTxMock(t)
	c, _ := NewCoordinatorBuilderForTesting(t, State_Active_Flush).
		NodeName("node2").
		CurrentActiveCoordinator("node2").
		CoordinatorPriorityList("node1", "node2", "node3").
		EndorserCandidates("node1"). // for OnTransitionTo Closing_Flush heartbeat
		CoordinatorSelectionMode(prototk.ContractConfig_COORDINATOR_ENDORSER).
		Transactions(txDispatched).
		Build()
	require.NoError(t, c.stateMachineEventLoop.ProcessEvent(ctx, &common.HeartbeatReceivedEvent{
		FromNode: "node1",
		CoordinatorSnapshot: &common.CoordinatorSnapshot{
			CoordinatorState: common.CoordinatorState_Active,
		},
	}))
	assert.Equal(t, State_Closing_Flush, c.GetCurrentState())
	assert.Equal(t, "node1", c.currentActiveCoordinator, "action_UpdateActiveCoordinator must record the new active node")
}

// A HandoverRequest from a higher-priority node in Active_Flush with dispatched transactions
// transitions to Closing_Flush.
func TestCoordinator_WhenActiveFLush_HandoverRequest_HigherPriority_HasDispatched_TransitionsToClosingFlush(t *testing.T) {
	ctx := t.Context()
	txDispatched, _ := newDispatchedTxMock(t)
	c, _ := NewCoordinatorBuilderForTesting(t, State_Active_Flush).
		NodeName("node2").
		CurrentActiveCoordinator("node2").
		CoordinatorPriorityList("node1", "node2", "node3").
		EndorserCandidates("node1"). // for OnTransitionTo Closing_Flush heartbeat
		CoordinatorSelectionMode(prototk.ContractConfig_COORDINATOR_ENDORSER).
		Transactions(txDispatched).
		Build()
	require.NoError(t, c.stateMachineEventLoop.ProcessEvent(ctx, &HandoverRequestEvent{
		FromNode: "node1",
	}))
	assert.Equal(t, State_Closing_Flush, c.GetCurrentState())
	assert.Equal(t, "node1", c.currentActiveCoordinator, "action_UpdateActiveCoordinator must record the requesting node")
}

// A HandoverRequest from a higher-priority node in Active_Flush with no dispatched transactions
// transitions directly to Closing.
func TestCoordinator_WhenActiveFLush_HandoverRequest_HigherPriority_NoDispatched_TransitionsToClosing(t *testing.T) {
	ctx := t.Context()
	c, _ := NewCoordinatorBuilderForTesting(t, State_Active_Flush).
		NodeName("node2").
		CurrentActiveCoordinator("node2").
		CoordinatorPriorityList("node1", "node2", "node3").
		EndorserCandidates("node1"). // for OnTransitionTo Closing heartbeat
		CoordinatorSelectionMode(prototk.ContractConfig_COORDINATOR_ENDORSER).
		Build()
	require.NoError(t, c.stateMachineEventLoop.ProcessEvent(ctx, &HandoverRequestEvent{
		FromNode: "node1",
	}))
	assert.Equal(t, State_Closing, c.GetCurrentState())
	assert.Equal(t, "node1", c.currentActiveCoordinator, "action_UpdateActiveCoordinator must record the requesting node")
}

// Delegations arriving in Active_Flush are accepted; the coordinator is still active, just draining.
func TestCoordinator_WhenActiveFLush_DelegatedTransactions_AcceptsAndStaysActiveFLush(t *testing.T) {
	ctx := t.Context()
	c, _ := NewCoordinatorBuilderForTesting(t, State_Active_Flush).
		NodeName("node1").
		CurrentActiveCoordinator("node1").
		Build()
	require.NoError(t, c.stateMachineEventLoop.ProcessEvent(ctx, &TransactionsDelegatedEvent{
		FromNode:     "originator-node",
		Originator:   "sender@originator-node",
		DelegationID: "del-4",
	}))
	assert.Equal(t, State_Active_Flush, c.GetCurrentState())
}

// A TransactionStateTransition from Dispatched to Pooled with an assembling transaction present
// cancels the assembling transaction; the coordinator stays in Active_Flush because a second
// dispatched transaction is still in flight.
func TestCoordinator_WhenActiveFLush_TransactionStateTransition_DispatchedToPooled_WithAssembling_StaysActiveFLush(t *testing.T) {
	ctx := t.Context()
	txAssembling := coordinatortransactionmocks.NewCoordinatorTransaction(t)
	txAssemblingID := uuid.New()
	txAssembling.EXPECT().GetID().Return(txAssemblingID).Maybe()
	txAssembling.EXPECT().GetCurrentState().Return(transaction.State_Assembling).Maybe()
	txAssembling.EXPECT().HandleEvent(mock.Anything, mock.AnythingOfType("*transaction.AssembleCancelledEvent")).Return(nil).Once()

	txDispatched1, txDispatched1ID := newDispatchedTxMock(t)
	txDispatched2, _ := newDispatchedTxMock(t)
	c, _ := NewCoordinatorBuilderForTesting(t, State_Active_Flush).
		NodeName("node1").
		CurrentActiveCoordinator("node1").
		Transactions(txAssembling, txDispatched1, txDispatched2).
		Build()
	require.NoError(t, c.stateMachineEventLoop.ProcessEvent(ctx, &common.TransactionStateTransitionEvent[transaction.State]{
		TransactionID: txDispatched1ID,
		FromState:     transaction.State_Dispatched,
		ToState:       transaction.State_Pooled,
	}))
	// txDispatched2 still in memory → guard_HasUnconfirmedDispatchedTransactions = true → stays Active_Flush.
	assert.Equal(t, State_Active_Flush, c.GetCurrentState())
}

// A TransactionStateTransition to ReadyForDispatch in Active_Flush queues the transaction for dispatch;
// remaining dispatched transactions keep the coordinator in Active_Flush.
func TestCoordinator_WhenActiveFLush_TransactionStateTransition_ToReadyForDispatch_QueuesAndStaysActiveFLush(t *testing.T) {
	ctx := t.Context()
	txDispatched, _ := newDispatchedTxMock(t)
	txReady := coordinatortransactionmocks.NewCoordinatorTransaction(t)
	txReadyID := uuid.New()
	txReady.EXPECT().GetID().Return(txReadyID).Maybe()
	txReady.EXPECT().GetCurrentState().Return(transaction.State_Ready_For_Dispatch).Maybe()
	c, _ := NewCoordinatorBuilderForTesting(t, State_Active_Flush).
		NodeName("node1").
		CurrentActiveCoordinator("node1").
		Transactions(txDispatched, txReady).
		Build()
	require.Equal(t, 0, len(c.dispatchQueue))
	require.NoError(t, c.stateMachineEventLoop.ProcessEvent(ctx, &common.TransactionStateTransitionEvent[transaction.State]{
		TransactionID: txReadyID,
		ToState:       transaction.State_Ready_For_Dispatch,
	}))
	// txDispatched still in memory → stays Active_Flush; txReady was queued for dispatch.
	assert.Equal(t, State_Active_Flush, c.GetCurrentState())
	assert.Equal(t, 1, len(c.dispatchQueue), "action_QueueTransactionForDispatch must enqueue the transaction")
}

// A TransactionStateTransition to Evicted in Active_Flush removes the transaction; remaining dispatched
// transactions keep the coordinator in Active_Flush.
func TestCoordinator_WhenActiveFLush_TransactionStateTransition_ToEvicted_CleansUpAndStaysActiveFLush(t *testing.T) {
	ctx := t.Context()
	txDispatched1, txDispatched1ID := newDispatchedTxMock(t)
	txDispatched2, _ := newDispatchedTxMock(t)
	c, _ := NewCoordinatorBuilderForTesting(t, State_Active_Flush).
		NodeName("node1").
		CurrentActiveCoordinator("node1").
		Transactions(txDispatched1, txDispatched2).
		Build()
	require.Equal(t, 2, len(c.transactionsByID))
	require.NoError(t, c.stateMachineEventLoop.ProcessEvent(ctx, &common.TransactionStateTransitionEvent[transaction.State]{
		TransactionID: txDispatched1ID,
		ToState:       transaction.State_Evicted,
	}))
	// txDispatched2 still in memory → guard_HasUnconfirmedDispatchedTransactions = true → stays Active_Flush.
	assert.Equal(t, State_Active_Flush, c.GetCurrentState())
	assert.Equal(t, 1, len(c.transactionsByID), "action_CleanUpTransaction must remove the evicted transaction")
}

// A TransactionStateTransition to Final in Active_Flush removes the transaction but a second
// dispatched transaction keeps the coordinator in Active_Flush (not enough to trigger the → Active transition).
func TestCoordinator_WhenActiveFLush_TransactionStateTransition_ToFinal_WithMoreDispatched_StaysActiveFLush(t *testing.T) {
	ctx := t.Context()
	txDispatched1, txDispatched1ID := newDispatchedTxMock(t)
	txDispatched2, _ := newDispatchedTxMock(t)
	c, _ := NewCoordinatorBuilderForTesting(t, State_Active_Flush).
		NodeName("node1").
		CurrentActiveCoordinator("node1").
		Transactions(txDispatched1, txDispatched2).
		Build()
	require.Equal(t, 2, len(c.transactionsByID))
	require.NoError(t, c.stateMachineEventLoop.ProcessEvent(ctx, &common.TransactionStateTransitionEvent[transaction.State]{
		TransactionID: txDispatched1ID,
		ToState:       transaction.State_Final,
	}))
	// txDispatched2 still dispatched → stays Active_Flush.
	assert.Equal(t, State_Active_Flush, c.GetCurrentState())
	assert.Equal(t, 1, len(c.transactionsByID))
}

// A NewBlock within the same epoch in Active_Flush updates only the block height.
func TestCoordinator_WhenActiveFLush_NewBlock_NotNewEpoch_UpdatesBlockHeightAndStaysActiveFLush(t *testing.T) {
	ctx := t.Context()
	txDispatched, _ := newDispatchedTxMock(t)
	c, _ := NewCoordinatorBuilderForTesting(t, State_Active_Flush).
		NodeName("node1").
		CurrentActiveCoordinator("node1").
		CurrentBlockHeight(100).
		CoordinatorSelectionBlockRange(50). // epoch = 100/50 = 2
		Transactions(txDispatched).
		Build()
	prevPriorityList := c.coordinatorPriorityList
	// BlockHeight 120 is in the same epoch as 100 (120/50 = 2)
	require.NoError(t, c.stateMachineEventLoop.ProcessEvent(ctx, &common.NewBlockEvent{BlockHeight: 120}))
	assert.Equal(t, State_Active_Flush, c.GetCurrentState())
	assert.Equal(t, uint64(120), c.currentBlockHeight, "action_UpdateBlockHeight must have run")
	assert.Equal(t, prevPriorityList, c.coordinatorPriorityList, "priority list must not change within an epoch")
}

// ── Closing_Flush state transitions ──────────────────────────────────────────

// On entering Closing_Flush, OnTransitionTo fires action_SendHeartbeat immediately so any waiting
// Elect node sees the flush acknowledgement without waiting for the next heartbeat interval.
func TestCoordinator_WhenEnteringClosingFlush_OnTransitionTo_SendsImmediateHeartbeat(t *testing.T) {
	ctx := t.Context()
	txDispatched, _ := newDispatchedTxMock(t)
	c, mocks := NewCoordinatorBuilderForTesting(t, State_Active).
		NodeName("node2").
		CurrentActiveCoordinator("node2").
		CoordinatorPriorityList("node1", "node2", "node3").
		EndorserCandidates("node1").
		CoordinatorSelectionMode(prototk.ContractConfig_COORDINATOR_ENDORSER).
		Transactions(txDispatched).
		Build()
	// Trigger transition Active → Closing_Flush via a higher-priority heartbeat.
	require.NoError(t, c.stateMachineEventLoop.ProcessEvent(ctx, &common.HeartbeatReceivedEvent{
		FromNode: "node1",
		CoordinatorSnapshot: &common.CoordinatorSnapshot{
			CoordinatorState: common.CoordinatorState_Active,
		},
	}))
	assert.Equal(t, State_Closing_Flush, c.GetCurrentState())
	// OnTransitionTo Closing_Flush fires action_SendHeartbeat immediately.
	assert.True(t, mocks.SentMessageRecorder.HasSentHeartbeat(), "OnTransitionTo Closing_Flush must emit an immediate heartbeat")
}

// HeartbeatInterval in Closing_Flush increments the state-change counter and sends a heartbeat;
// there is no exit condition for heartbeat intervals in this state.
func TestCoordinator_WhenClosingFlush_HeartbeatInterval_IncrementsCounterAndSendsHeartbeat(t *testing.T) {
	ctx := t.Context()
	txDispatched, _ := newDispatchedTxMock(t)
	c, mocks := NewCoordinatorBuilderForTesting(t, State_Closing_Flush).
		NodeName("node1").
		CurrentActiveCoordinator("node2").
		EndorserCandidates("node2"). // for action_SendHeartbeat
		CoordinatorSelectionMode(prototk.ContractConfig_COORDINATOR_ENDORSER).
		HeartbeatIntervalsSinceStateChange(0).
		Transactions(txDispatched).
		Build()
	require.NoError(t, c.stateMachineEventLoop.ProcessEvent(ctx, &common.HeartbeatIntervalEvent{}))
	assert.Equal(t, State_Closing_Flush, c.GetCurrentState())
	assert.Equal(t, 1, c.heartbeatIntervalsSinceStateChange)
	assert.True(t, mocks.SentMessageRecorder.HasSentHeartbeat())
}

// A HeartbeatReceived from a live sender in Closing_Flush resets the liveness counter.
func TestCoordinator_WhenClosingFlush_HeartbeatReceived_FromLiveSender_ResetsCounterAndStaysClosingFlush(t *testing.T) {
	ctx := t.Context()
	txDispatched, _ := newDispatchedTxMock(t)
	c, _ := NewCoordinatorBuilderForTesting(t, State_Closing_Flush).
		NodeName("node1").
		CurrentActiveCoordinator("node2").
		HeartbeatIntervalsSinceLastReceive(5).
		Transactions(txDispatched).
		Build()
	require.NoError(t, c.stateMachineEventLoop.ProcessEvent(ctx, &common.HeartbeatReceivedEvent{
		FromNode: "node2",
		CoordinatorSnapshot: &common.CoordinatorSnapshot{
			CoordinatorState: common.CoordinatorState_Active,
		},
	}))
	assert.Equal(t, State_Closing_Flush, c.GetCurrentState())
	assert.Equal(t, 0, c.heartbeatIntervalsSinceLastReceive, "action_ResetHeartbeatIntervalsSinceLastReceive must clear the counter")
}

// When a delegation arrives in Closing_Flush and this node is now higher priority than the current
// active coordinator, it processes the delegation and transitions to Elect.
func TestCoordinator_WhenClosingFlush_DelegatedTransactions_HigherPriority_TransitionsToElect(t *testing.T) {
	ctx := t.Context()
	txDispatched, _ := newDispatchedTxMock(t)
	c, mocks := NewCoordinatorBuilderForTesting(t, State_Closing_Flush).
		NodeName("node1").
		CurrentActiveCoordinator("node2"). // node1 re-selected as higher priority
		CoordinatorPriorityList("node1", "node2", "node3").
		EndorserCandidates("node1", "node2", "node3").
		CoordinatorSelectionMode(prototk.ContractConfig_COORDINATOR_ENDORSER).
		WithMockTransportWriter().
		Transactions(txDispatched).
		Build()
	mocks.TransportWriter.EXPECT().SendDelegationRequestAcknowledgment(mock.Anything, "originator-node", "del-1", mock.Anything, mock.Anything, mock.Anything).Return(nil)
	mocks.TransportWriter.EXPECT().SendHandoverRequest(mock.Anything, "node2", mock.Anything).Return(nil)
	require.NoError(t, c.stateMachineEventLoop.ProcessEvent(ctx, &TransactionsDelegatedEvent{
		FromNode:     "originator-node",
		Originator:   "sender@originator-node",
		DelegationID: "del-1",
	}))
	assert.Equal(t, State_Elect, c.GetCurrentState())
}

// When a delegation arrives in Closing_Flush and this node is lower priority, it is rejected.
func TestCoordinator_WhenClosingFlush_DelegatedTransactions_LowerPriority_RejectsAndStaysClosingFlush(t *testing.T) {
	ctx := t.Context()
	txDispatched, _ := newDispatchedTxMock(t)
	c, mocks := NewCoordinatorBuilderForTesting(t, State_Closing_Flush).
		NodeName("node3"). // lower priority than node1
		CurrentActiveCoordinator("node1").
		CoordinatorPriorityList("node1", "node2", "node3").
		WithMockTransportWriter().
		Transactions(txDispatched).
		Build()
	mocks.TransportWriter.EXPECT().SendDelegationRequestRejection(mock.Anything, "originator-node", "del-2", mock.Anything, "node1").Return(nil)
	require.NoError(t, c.stateMachineEventLoop.ProcessEvent(ctx, &TransactionsDelegatedEvent{
		FromNode:     "originator-node",
		Originator:   "sender@originator-node",
		DelegationID: "del-2",
	}))
	assert.Equal(t, State_Closing_Flush, c.GetCurrentState())
}

// A TransactionStateTransition from Dispatched to a retryable state (not Confirmed or Reverted)
// cleans up that transaction; remaining dispatched transactions keep the state as Closing_Flush.
func TestCoordinator_WhenClosingFlush_TransactionStateTransition_DispatchedToRetryable_CleansUpAndStaysClosingFlush(t *testing.T) {
	ctx := t.Context()
	txDispatched1, txDispatched1ID := newDispatchedTxMock(t)
	txDispatched2, _ := newDispatchedTxMock(t)
	c, _ := NewCoordinatorBuilderForTesting(t, State_Closing_Flush).
		NodeName("node1").
		CurrentActiveCoordinator("node2").
		Transactions(txDispatched1, txDispatched2).
		Build()
	require.Equal(t, 2, len(c.transactionsByID))
	// From=Dispatched, To=Pooled is retryable (not Confirmed/Reverted) → action_CleanUpTransaction fires.
	require.NoError(t, c.stateMachineEventLoop.ProcessEvent(ctx, &common.TransactionStateTransitionEvent[transaction.State]{
		TransactionID: txDispatched1ID,
		FromState:     transaction.State_Dispatched,
		ToState:       transaction.State_Pooled,
	}))
	// txDispatched2 still dispatched → guard_HasUnconfirmedDispatchedTransactions = true → stays Closing_Flush.
	assert.Equal(t, State_Closing_Flush, c.GetCurrentState())
	assert.Equal(t, 1, len(c.transactionsByID), "action_CleanUpTransaction must remove the retryable transaction")
}

// A TransactionStateTransition to Final in Closing_Flush removes the transaction; a second dispatched
// transaction keeps the coordinator in Closing_Flush.
func TestCoordinator_WhenClosingFlush_TransactionStateTransition_ToFinal_WithMoreDispatched_StaysClosingFlush(t *testing.T) {
	ctx := t.Context()
	txDispatched1, txDispatched1ID := newDispatchedTxMock(t)
	txDispatched2, _ := newDispatchedTxMock(t)
	c, _ := NewCoordinatorBuilderForTesting(t, State_Closing_Flush).
		NodeName("node1").
		CurrentActiveCoordinator("node2").
		Transactions(txDispatched1, txDispatched2).
		Build()
	require.Equal(t, 2, len(c.transactionsByID))
	require.NoError(t, c.stateMachineEventLoop.ProcessEvent(ctx, &common.TransactionStateTransitionEvent[transaction.State]{
		TransactionID: txDispatched1ID,
		ToState:       transaction.State_Final,
	}))
	// txDispatched2 still dispatched → stays Closing_Flush.
	assert.Equal(t, State_Closing_Flush, c.GetCurrentState())
	assert.Equal(t, 1, len(c.transactionsByID))
}

// A NewBlock in Closing_Flush updates the block height and, on epoch boundary, the priority list.
func TestCoordinator_WhenClosingFlush_NewBlock_UpdatesBlockHeightAndStaysClosingFlush(t *testing.T) {
	ctx := t.Context()
	txDispatched, _ := newDispatchedTxMock(t)
	c, _ := NewCoordinatorBuilderForTesting(t, State_Closing_Flush).
		NodeName("node1").
		CurrentActiveCoordinator("node2").
		CurrentBlockHeight(100).
		CoordinatorSelectionBlockRange(50).
		EndorserCandidates("node1", "node2", "node3").
		CoordinatorSelectionMode(prototk.ContractConfig_COORDINATOR_ENDORSER).
		Transactions(txDispatched).
		Build()
	require.NoError(t, c.stateMachineEventLoop.ProcessEvent(ctx, &common.NewBlockEvent{BlockHeight: 150}))
	assert.Equal(t, State_Closing_Flush, c.GetCurrentState())
	assert.Equal(t, uint64(150), c.currentBlockHeight, "action_UpdateBlockHeight must have run")
	assert.NotEmpty(t, c.coordinatorPriorityList, "action_CalculateCoordinatorPriorities must have run on epoch boundary")
}

// ── Closing state transitions ─────────────────────────────────────────────────

// On entering Closing from Closing_Flush (flush complete + not current coordinator), OnTransitionTo fires
// action_SendHeartbeat immediately so any waiting Prepared node sees the flush-complete signal without
// waiting for the next heartbeat interval.
func TestCoordinator_WhenClosingFlushCompletesAndNotCurrentCoordinator_EnteringClosingEmitsImmediateHeartbeat(t *testing.T) {
	ctx := t.Context()
	txDispatched, txID := newDispatchedTxMock(t)
	c, mocks := NewCoordinatorBuilderForTesting(t, State_Closing_Flush).
		NodeName("node1").
		CurrentActiveCoordinator("node2"). // another node is now active; node1 is stepping down
		EndorserCandidates("node2").       // gives action_SendHeartbeat a recipient
		CoordinatorSelectionMode(prototk.ContractConfig_COORDINATOR_ENDORSER).
		Transactions(txDispatched).
		Build()
	// Finalising the last dispatched transaction triggers guard_FlushComplete = true and
	// !guard_IsCurrentActiveCoordinator → transition to Closing, where OnTransitionTo fires action_SendHeartbeat.
	require.NoError(t, c.stateMachineEventLoop.ProcessEvent(ctx, &common.TransactionStateTransitionEvent[transaction.State]{
		TransactionID: txID,
		FromState:     transaction.State_Dispatched,
		ToState:       transaction.State_Final,
	}))
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

// A NewBlock epoch in Closing updates the priority list and block height but does not trigger a state
// transition. The Closing state exits only via HeartbeatInterval (closing/inactive grace) or a new
// delegation request. Epoch changes alone cannot drive Closing → Elect/Active/Idle.
func TestCoordinator_WhenClosing_NewBlock_UpdatesPriorityListAndStaysClosing(t *testing.T) {
	ctx := t.Context()
	c, _ := NewCoordinatorBuilderForTesting(t, State_Closing).
		NodeName("node2").
		CurrentActiveCoordinator("node1").
		CurrentBlockHeight(100).
		CoordinatorSelectionBlockRange(50).
		EndorserCandidates("node1", "node2", "node3").
		CoordinatorSelectionMode(prototk.ContractConfig_COORDINATOR_ENDORSER).
		Build()
	require.NoError(t, c.stateMachineEventLoop.ProcessEvent(ctx, &common.NewBlockEvent{BlockHeight: 150}))
	// No transition — epoch change alone has no exit condition in Closing.
	assert.Equal(t, State_Closing, c.GetCurrentState())
	assert.Equal(t, uint64(150), c.currentBlockHeight, "action_UpdateBlockHeight must have run")
	// action_CalculateCoordinatorPriorities re-ran and updated the priority list
	assert.NotEmpty(t, c.coordinatorPriorityList, "priority list must be populated")
}

// When a delegation request arrives in Closing and this node is now higher priority than the current active
// (epoch may have re-selected it), the coordinator initiates a handover and transitions to Elect.
func TestCoordinator_WhenClosing_DelegationRequest_HigherPriorityThanCurrentActive_TransitionsToElect(t *testing.T) {
	ctx := t.Context()
	c, mocks := NewCoordinatorBuilderForTesting(t, State_Closing).
		NodeName("node1").
		CurrentActiveCoordinator("node2"). // node1 is now higher priority
		CoordinatorPriorityList("node1", "node2", "node3").
		EndorserCandidates("node1", "node2", "node3").
		CoordinatorSelectionMode(prototk.ContractConfig_COORDINATOR_ENDORSER).
		WithMockTransportWriter().
		Build()
	// action_ProcessDelegatedTransactions always sends an acknowledgment (even for empty transaction lists).
	mocks.TransportWriter.EXPECT().SendDelegationRequestAcknowledgment(mock.Anything, "originator-node", "del-1", mock.Anything, mock.Anything, mock.Anything).Return(nil)
	mocks.TransportWriter.EXPECT().SendHandoverRequest(mock.Anything, "node2", mock.Anything).Return(nil)

	require.NoError(t, c.stateMachineEventLoop.ProcessEvent(ctx, &TransactionsDelegatedEvent{
		FromNode:     "originator-node",
		Originator:   "sender@originator-node",
		DelegationID: "del-1",
	}))
	// guard_IsHigherPriorityThanCurrentActive = true (node1 < node2) → Elect
	assert.Equal(t, State_Elect, c.GetCurrentState())
	assert.Equal(t, "node2", c.currentActiveCoordinator, "currentActiveCoordinator unchanged; node2 is who we sent handover to")
}

// A HeartbeatReceived from a live sender in Closing resets the liveness counter and updates the
// current active coordinator field; no state transition occurs.
func TestCoordinator_WhenClosing_HeartbeatReceived_FromLiveSender_ResetsCounterAndUpdatesCoordinator(t *testing.T) {
	ctx := t.Context()
	c, _ := NewCoordinatorBuilderForTesting(t, State_Closing).
		NodeName("node1").
		CurrentActiveCoordinator("node2").
		HeartbeatIntervalsSinceLastReceive(5).
		Build()
	require.NoError(t, c.stateMachineEventLoop.ProcessEvent(ctx, &common.HeartbeatReceivedEvent{
		FromNode: "node2",
		CoordinatorSnapshot: &common.CoordinatorSnapshot{
			CoordinatorState: common.CoordinatorState_Active,
		},
	}))
	assert.Equal(t, State_Closing, c.GetCurrentState())
	assert.Equal(t, 0, c.heartbeatIntervalsSinceLastReceive, "action_ResetHeartbeatIntervalsSinceLastReceive must clear the counter")
	assert.Equal(t, "node2", c.currentActiveCoordinator, "action_UpdateActiveCoordinator must record the sender")
}

// HeartbeatInterval in Closing before the closing grace period expires sends a heartbeat and stays
// Closing; the transition guards require grace to be expired before moving to Idle/Observing.
func TestCoordinator_WhenClosing_HeartbeatInterval_GraceNotExpired_SendsHeartbeatAndStaysClosing(t *testing.T) {
	ctx := t.Context()
	c, mocks := NewCoordinatorBuilderForTesting(t, State_Closing).
		ClosingGracePeriod(5).
		HeartbeatIntervalsSinceStateChange(0). // after increment: 1 < 5 → grace not expired
		HeartbeatIntervalsSinceLastReceive(0).
		InactiveGracePeriod(3).
		EndorserCandidates("node2"). // for action_SendHeartbeat
		CoordinatorSelectionMode(prototk.ContractConfig_COORDINATOR_ENDORSER).
		Build()
	require.NoError(t, c.stateMachineEventLoop.ProcessEvent(ctx, &common.HeartbeatIntervalEvent{}))
	assert.Equal(t, State_Closing, c.GetCurrentState())
	assert.Equal(t, 1, c.heartbeatIntervalsSinceStateChange)
	assert.True(t, mocks.SentMessageRecorder.HasSentHeartbeat())
}

// A delegation in Closing when this node is lower priority and the active coordinator is still
// live (inactive grace not exceeded) causes a rejection; state stays Closing.
func TestCoordinator_WhenClosing_DelegatedTransactions_LowerPriority_ActiveCoordinatorLive_Rejects(t *testing.T) {
	ctx := t.Context()
	c, mocks := NewCoordinatorBuilderForTesting(t, State_Closing).
		NodeName("node3").
		CurrentActiveCoordinator("node1").
		CoordinatorPriorityList("node1", "node2", "node3").
		HeartbeatIntervalsSinceLastReceive(0).
		InactiveGracePeriod(5). // 0 < 5 → not exceeded
		WithMockTransportWriter().
		Build()
	mocks.TransportWriter.EXPECT().SendDelegationRequestRejection(mock.Anything, "originator-node", "del-3", mock.Anything, "node1").Return(nil)
	require.NoError(t, c.stateMachineEventLoop.ProcessEvent(ctx, &TransactionsDelegatedEvent{
		FromNode:     "originator-node",
		Originator:   "sender@originator-node",
		DelegationID: "del-3",
	}))
	// GuardNot(IsHigherPriority) AND GuardNot(InactiveGraceExceeded) → action_RejectDelegationRequest fires.
	assert.Equal(t, State_Closing, c.GetCurrentState())
}

// A delegation in Closing when this node is lower priority but the active coordinator has gone
// silent (inactive grace exceeded) causes the node to take over and transition to Active.
func TestCoordinator_WhenClosing_DelegatedTransactions_LowerPriority_ActiveCoordinatorGone_TransitionsToActive(t *testing.T) {
	ctx := t.Context()
	c, _ := NewCoordinatorBuilderForTesting(t, State_Closing).
		NodeName("node3").
		CurrentActiveCoordinator("node1").
		CoordinatorPriorityList("node1", "node2", "node3").
		HeartbeatIntervalsSinceLastReceive(5).
		InactiveGracePeriod(5). // 5 >= 5 → exceeded
		Build()
	require.NoError(t, c.stateMachineEventLoop.ProcessEvent(ctx, &TransactionsDelegatedEvent{
		FromNode:     "originator-node",
		Originator:   "sender@originator-node",
		DelegationID: "del-4",
	}))
	// GuardNot(IsHigherPriority) AND InactiveGraceExceeded → transitions to Active.
	assert.Equal(t, State_Active, c.GetCurrentState())
}

// A TransactionStateTransition to Final in Closing removes the transaction; the coordinator stays Closing.
func TestCoordinator_WhenClosing_TransactionStateTransition_ToFinal_CleansUpAndStaysClosing(t *testing.T) {
	ctx := t.Context()
	txFinal := coordinatortransactionmocks.NewCoordinatorTransaction(t)
	txID := uuid.New()
	txFinal.EXPECT().GetID().Return(txID).Maybe()
	txFinal.EXPECT().GetCurrentState().Return(transaction.State_Final).Maybe()
	c, _ := NewCoordinatorBuilderForTesting(t, State_Closing).
		NodeName("node1").
		CurrentActiveCoordinator("node2").
		Transactions(txFinal).
		Build()
	require.Equal(t, 1, len(c.transactionsByID))
	require.NoError(t, c.stateMachineEventLoop.ProcessEvent(ctx, &common.TransactionStateTransitionEvent[transaction.State]{
		TransactionID: txID,
		ToState:       transaction.State_Final,
	}))
	assert.Equal(t, State_Closing, c.GetCurrentState())
	assert.Empty(t, c.transactionsByID, "action_CleanUpTransaction must remove the finalised transaction")
}

// preProcessEvent filters out heartbeat events that originate from the coordinator's own node,
// preventing the coordinator from reacting to its own broadcasts.
func TestCoordinator_PreProcessEvent_OwnHeartbeat_IsFilteredOut(t *testing.T) {
	ctx := t.Context()
	// The coordinator is in Observing state so a non-self heartbeat would normally update the
	// current-active-coordinator field.  A self-originated heartbeat must be silently dropped.
	c, _ := NewCoordinatorBuilderForTesting(t, State_Observing).
		NodeName("node1").
		CurrentActiveCoordinator("node2").
		CoordinatorPriorityList("node1", "node2").
		Build()

	selfHeartbeat := &common.HeartbeatReceivedEvent{
		FromNode: "node1", // own node name — must be filtered
		CoordinatorSnapshot: &common.CoordinatorSnapshot{
			CoordinatorState: common.CoordinatorState_Active,
		},
	}
	require.NoError(t, c.stateMachineEventLoop.ProcessEvent(ctx, selfHeartbeat))

	// The event was filtered before reaching the state machine, so the state must be unchanged
	// and currentActiveCoordinator must not have been updated to "node1".
	assert.Equal(t, State_Observing, c.GetCurrentState(), "own heartbeat must not trigger a state transition")
	assert.Equal(t, "node2", c.currentActiveCoordinator, "own heartbeat must not update currentActiveCoordinator")
}
