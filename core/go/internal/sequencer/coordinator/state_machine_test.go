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
		OriginatorNodePool("node1", "node2").
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
	assert.Equal(t, "node2", c.currentActiveCoordinator)
}

// A heartbeat from a node in Closing state is completely ignored in Idle because the event-level
// validator_IsHeartbeatSenderLive rejects non-live senders before any actions run. Neither
// activeCoordinatorState nor the state machine state change.
func TestCoordinator_WhenIdle_StaysIdle_OnHeartbeatFromNodeInNonActiveState(t *testing.T) {
	ctx := t.Context()
	c, _ := NewCoordinatorBuilderForTesting(t, State_Idle).
		NodeName("node1").
		Build()
	event := &common.HeartbeatReceivedEvent{
		From:                "node3",
		CoordinatorSnapshot: &common.CoordinatorSnapshot{CoordinatorState: common.CoordinatorState_Closing},
	}
	require.NoError(t, c.stateMachineEventLoop.ProcessEvent(ctx, event))
	assert.Equal(t, State_Idle, c.GetCurrentState())
	assert.Equal(t, "", c.currentActiveCoordinator, "non-live heartbeat must leave currentActiveCoordinator unchanged (zero value)")
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

// When a new block-range epoch arrives in Observing, action_CalculateCoordinatorPriorities updates the priority
// list and currentActiveCoordinator. The state stays Observing — epoch changes do not trigger a transition to
// Elect; only a delegation request can move Observing → Elect.
func TestCoordinator_WhenObserving_NewBlock_UpdatesPriorityListAndStaysObserving(t *testing.T) {
	ctx := t.Context()
	c, _ := NewCoordinatorBuilderForTesting(t, State_Observing).
		NodeName("node2").
		CurrentActiveCoordinator("node1").
		CurrentBlockHeight(100).
		CoordinatorSelectionBlockRange(50).
		OriginatorNodePool("node1", "node2", "node3").
		DomainContractConfig(&prototk.ContractConfig{
			CoordinatorSelection: prototk.ContractConfig_COORDINATOR_ENDORSER,
		}).
		Build()
	// NewBlock at 150: epoch 100/50=2 → 150/50=3 — crosses boundary; action_CalculateCoordinatorPriorities fires
	require.NoError(t, c.stateMachineEventLoop.ProcessEvent(ctx, &common.NewBlockEvent{BlockHeight: 150}))
	// No transition to Elect — epoch change alone does not initiate a handover.
	assert.Equal(t, State_Observing, c.GetCurrentState())
	assert.Equal(t, uint64(150), c.currentBlockHeight, "action_UpdateBlockHeight must have run")
	// action_CalculateCoordinatorPriorities updated currentActiveCoordinator from the new priority list
	assert.NotEmpty(t, c.coordinatorPriorityList, "priority list must be populated by action_CalculateCoordinatorPriorities")
	assert.Equal(t, c.coordinatorPriorityList[0], c.currentActiveCoordinator)
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
		From: "node2",
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
	// action_ImportStatesAndLocks ran: the grapher must now hold the imported state and lock.
	exported, err := c.grapher.ExportStatesAndLocks(ctx, "node1")
	require.NoError(t, err)
	assert.Len(t, exported.OutputState, 1, "imported output state must be visible to node1")
	assert.Len(t, exported.LockedState, 1, "imported confirmed lock must be present in grapher")
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
	assert.NotEmpty(t, c.signingIdentity, "OnTransitionTo Active must set signing identity")
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
		From: "prev",
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
		Build()
	// Seed priority list: node1 has higher priority than node2, so node1 should preempt.
	c.coordinatorPriorityList = []string{"node1", "node2", "node3"}

	// Heartbeat from node1 (higher priority, Active) — sets receivedHigherPriorityActiveHeartbeat.
	event := &common.HeartbeatReceivedEvent{
		From: "node1",
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
		OriginatorNodePool("node1", "node2", "node3").
		DomainContractConfig(&prototk.ContractConfig{
			CoordinatorSelection: prototk.ContractConfig_COORDINATOR_ENDORSER,
		}).
		Build()
	require.NoError(t, c.stateMachineEventLoop.ProcessEvent(ctx, &common.NewBlockEvent{BlockHeight: 150}))
	// No transition — epoch change has no exit condition in Elect.
	assert.Equal(t, State_Elect, c.GetCurrentState())
	assert.Equal(t, uint64(150), c.currentBlockHeight, "action_UpdateBlockHeight must have run")
	// action_CalculateCoordinatorPriorities updated the priority list
	assert.NotEmpty(t, c.coordinatorPriorityList)
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
// memory (its getCoordinatorSigningIdentity callback will return the new identity at dispatch time).
func TestCoordinator_WhenActiveAndEpochChangesWithSigningUsedAndOnlyPooledTxs_RotatesKeyInPlace(t *testing.T) {
	ctx := t.Context()
	pooledTx := coordinatortransactionmocks.NewCoordinatorTransaction(t)
	pooledTxID := uuid.New()
	pooledTx.EXPECT().GetID().Return(pooledTxID).Maybe()
	pooledTx.EXPECT().GetCurrentState().Return(transaction.State_Pooled).Maybe()
	// action_SelectTransaction pops the pooled transaction and sends it a SelectedEvent.
	pooledTx.EXPECT().HandleEvent(mock.Anything, mock.AnythingOfType("*transaction.SelectedEvent")).Return(nil)

	c, _ := NewCoordinatorBuilderForTesting(t, State_Active).
		NodeName("node2").
		CurrentActiveCoordinator("node2").
		CurrentBlockHeight(100).
		CoordinatorSelectionBlockRange(50).
		SigningIdentityUsed(true). // a transaction retrieved the signing identity since the last rotation
		PooledTransactions(pooledTx).
		DomainContractConfig(&prototk.ContractConfig{
			CoordinatorSelection: prototk.ContractConfig_COORDINATOR_ENDORSER,
		}).
		Build()
	prevIdentity := c.signingIdentity
	require.Equal(t, 1, len(c.transactionsByID), "pooled tx must be registered before event")
	require.NoError(t, c.stateMachineEventLoop.ProcessEvent(ctx, &common.NewBlockEvent{BlockHeight: 150}))
	// guard_SigningIdentityUsed = true, guard_FlushComplete = true → action_NewSigningIdentity (in-place rotation)
	assert.Equal(t, State_Active, c.GetCurrentState(), "key-rotation does not change state when flush is already complete")
	// action_NewSigningIdentity rotated the key in place
	assert.NotEqual(t, prevIdentity, c.signingIdentity, "signing identity must be refreshed on epoch boundary when used")
	// The transaction was promoted to assembling by action_SelectTransaction (part of Active OnTransitionTo).
	// It remains registered in transactionsByID but is no longer in the pool.
	assert.Equal(t, 1, len(c.transactionsByID), "transaction must remain registered after in-place key rotation")
	assert.Equal(t, 0, len(c.pooledTransactions), "transaction leaves the pool when action_SelectTransaction picks it up for assembly")
}

// A new-epoch NewBlock where the signing identity was NOT used → priority list is updated but no key rotation
// and no state transition occurs. The coordinator stays Active with the same signing identity.
func TestCoordinator_WhenActiveAndEpochChanges_SigningNotUsed_StaysActiveWithSameIdentity(t *testing.T) {
	ctx := t.Context()
	c, _ := NewCoordinatorBuilderForTesting(t, State_Active).
		NodeName("node1").
		CurrentActiveCoordinator("node1").
		CurrentBlockHeight(100).
		CoordinatorSelectionBlockRange(50).
		OriginatorNodePool("node1", "node2", "node3").
		DomainContractConfig(&prototk.ContractConfig{
			CoordinatorSelection: prototk.ContractConfig_COORDINATOR_ENDORSER,
		}).
		Build()
	prevIdentity := c.signingIdentity
	require.NoError(t, c.stateMachineEventLoop.ProcessEvent(ctx, &common.NewBlockEvent{BlockHeight: 150}))
	// guard_SigningIdentityUsed = false → no key rotation, no Flush transition
	assert.Equal(t, State_Active, c.GetCurrentState())
	assert.Equal(t, prevIdentity, c.signingIdentity, "signing identity must not change when it was not used")
	// action_CalculateCoordinatorPriorities updated the priority list and currentActiveCoordinator
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
		OriginatorNodePool("node1", "node2", "node3").
		PooledTransactions(pooledTx).
		DomainContractConfig(&prototk.ContractConfig{
			CoordinatorSelection: prototk.ContractConfig_COORDINATOR_ENDORSER,
		}).
		Build()
	// Seed the priority list to establish node1 > node2 > node3
	c.coordinatorPriorityList = []string{"node1", "node2", "node3"}
	require.Equal(t, 1, len(c.transactionsByID), "pooled tx must be registered before event")
	// node1 sends an Active heartbeat while node3 is coordinating → preemption
	require.NoError(t, c.stateMachineEventLoop.ProcessEvent(ctx, &common.HeartbeatReceivedEvent{
		From: "node1",
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
		From: "node2",
		CoordinatorSnapshot: &common.CoordinatorSnapshot{
			CoordinatorState: common.CoordinatorState_Closing,
		},
	}))
	assert.Equal(t, State_Active, c.GetCurrentState())
	assert.NotEmpty(t, c.signingIdentity)
	// mock expectation on pooledTx.HandleEvent(SelectedEvent) verified by testify
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
		From:          transaction.State_Dispatched,
		To:            transaction.State_Final,
	}
	require.NoError(t, c.stateMachineEventLoop.ProcessEvent(ctx, event))
	assert.Equal(t, State_Active, c.GetCurrentState())
	assert.NotEmpty(t, c.signingIdentity, "OnTransitionTo Active must set signing identity")
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
		From:          transaction.State_Dispatched,
		To:            transaction.State_Final,
	}
	require.NoError(t, c.stateMachineEventLoop.ProcessEvent(ctx, event))
	assert.Equal(t, State_Closing, c.GetCurrentState())
}

// A NewBlock epoch crossing in Active_Flush updates block height and re-runs coordinator selection,
// but stays in Active_Flush.
func TestCoordinator_WhenActiveFlushing_AndNewEpochArrives_UpdatesHeightAndSelectionButStaysActiveFLush(t *testing.T) {
	ctx := t.Context()
	txDispatched, _ := newDispatchedTxMock(t)
	c, _ := NewCoordinatorBuilderForTesting(t, State_Active_Flush).
		NodeName("node1").
		CurrentActiveCoordinator("node1").
		CurrentBlockHeight(100).
		CoordinatorSelectionBlockRange(50).
		OriginatorNodePool("node1", "node2", "node3").
		Transactions(txDispatched).
		DomainContractConfig(&prototk.ContractConfig{
			CoordinatorSelection: prototk.ContractConfig_COORDINATOR_ENDORSER,
		}).
		Build()
	require.NoError(t, c.stateMachineEventLoop.ProcessEvent(ctx, &common.NewBlockEvent{BlockHeight: 150}))
	assert.Equal(t, State_Active_Flush, c.GetCurrentState())
	assert.Equal(t, uint64(150), c.currentBlockHeight)
	assert.Equal(t, "node2", c.currentActiveCoordinator, "action_SelectActiveCoordinator must update currentActiveCoordinator")
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
		OriginatorNodePool("node2").       // gives action_SendHeartbeat a recipient
		Transactions(txDispatched).
		Build()
	// Finalising the last dispatched transaction triggers guard_FlushComplete = true and
	// !guard_IsCurrentActiveCoordinator → transition to Closing, where OnTransitionTo fires action_SendHeartbeat.
	require.NoError(t, c.stateMachineEventLoop.ProcessEvent(ctx, &common.TransactionStateTransitionEvent[transaction.State]{
		TransactionID: txID,
		From:          transaction.State_Dispatched,
		To:            transaction.State_Final,
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
		OriginatorNodePool("node1", "node2", "node3").
		DomainContractConfig(&prototk.ContractConfig{
			CoordinatorSelection: prototk.ContractConfig_COORDINATOR_ENDORSER,
		}).
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
		OriginatorNodePool("node1", "node2", "node3").
		DomainContractConfig(&prototk.ContractConfig{
			CoordinatorSelection: prototk.ContractConfig_COORDINATOR_ENDORSER,
		}).
		WithMockTransportWriter().
		Build()
	// Seed the priority list so guard_IsHigherPriorityThanCurrentActive works
	c.coordinatorPriorityList = []string{"node1", "node2", "node3"}
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
