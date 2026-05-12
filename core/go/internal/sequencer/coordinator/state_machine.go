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

	"github.com/LFDT-Paladin/paladin/common/go/pkg/log"
	"github.com/LFDT-Paladin/paladin/core/internal/sequencer/common"
	"github.com/LFDT-Paladin/paladin/core/internal/sequencer/coordinator/transaction"
	"github.com/LFDT-Paladin/paladin/core/internal/sequencer/statemachine"
)

// State is a local alias for common.CoordinatorState
type State = common.CoordinatorState

// EventType is an alias for common.EventType
type EventType = common.EventType

const (
	State_Initial   = common.CoordinatorState_Initial   // Coordinator created but not yet selected an active coordinator
	State_Idle      = common.CoordinatorState_Idle      // Not acting as a coordinator and not aware of any other active coordinators
	State_Observing = common.CoordinatorState_Observing // Not acting as a coordinator but aware of another node acting as a coordinator
	State_Elect     = common.CoordinatorState_Elect     // Selected to take over from another coordinator but waiting to see the previous coordinator's flush point
	State_Active    = common.CoordinatorState_Active    // Have seen the flush point or have reason to believe the old coordinator has become unavailable; now assembling and submitting transactions
	State_Flush     = common.CoordinatorState_Flush     // Stopped assembling and dispatching transactions; continuing to submit already-dispatched transactions
	State_Closing   = common.CoordinatorState_Closing   // Have flushed and are continuing to send closing status heartbeats
)

const (
	Event_CoordinatorCreated EventType = iota + common.Event_HeartbeatReceived + 1
	Event_TransactionsDelegated
	Event_ActiveCoordinatorUnavailable
)

// Type aliases for the generic statemachine types, specialized for coordinator
type (
	Action           = statemachine.Action[*coordinator]
	Guard            = statemachine.Guard[*coordinator]
	Validator        = statemachine.Validator[*coordinator]
	ActionRule       = statemachine.ActionRule[*coordinator]
	Transition       = statemachine.Transition[State, *coordinator]
	EventHandler     = statemachine.EventHandler[State, *coordinator]
	StateDefinition  = statemachine.StateDefinition[State, *coordinator]
	StateDefinitions = statemachine.StateDefinitions[State, *coordinator]
)

// TODO AM: something to think about
// does a node who is endorsing in a privacy group but not submitting need a way to understand that the preferred active
// coordinator has become unavailable?
// I think the simplest way is to endorse everything that comes in? Are there knock on implications for this?

var stateDefinitionsMap = StateDefinitions{
	State_Initial: {
		Events: map[EventType]EventHandler{
			Event_CoordinatorCreated: {
				Actions:     []ActionRule{{Action: action_SelectActiveCoordinator}},
				Transitions: []Transition{{To: State_Idle}},
			},
		},
	},
	State_Idle: {
		Events: map[EventType]EventHandler{
			Event_TransactionsDelegated: {
				Actions: []ActionRule{{
					If:     guard_IsCurrentActiveCoordinator,
					Action: action_ProcessDelegatedTransactions,
				}, {
					If:     statemachine.GuardNot(guard_IsCurrentActiveCoordinator),
					Action: action_RejectDelegatedTransactions,
				}},
				Transitions: []Transition{{
					If: guard_IsCurrentActiveCoordinator,
					To: State_Active,
				}},
			},
		common.Event_HeartbeatReceived: {
			Validator: statemachine.ValidatorOr(
				validator_IsHeartbeatFromCurrentActiveCoordinator,
				validator_IsHeartbeatFromPreferredActiveCoordinator,
				validator_IsHeartbeatFromActiveWhenWeArePreferred,
			),
			Actions: []ActionRule{{Action: action_HeartbeatReceived}},
			Transitions: []Transition{{
				// Preferred coordinator awakens directly to Active — no handover needed.
				To: State_Active,
				If: guard_IsPreferredActiveCoordinator,
			}, {
				To: State_Observing,
			}},
		},
		common.Event_NewBlock: {
			Actions: []ActionRule{
				{
					Action: action_UpdateBlockHeight,
				},
				{
					Action: action_ExpireGrapherLocks,
				},
				{
					// If we have entered a new block range, action_SelectActiveCoordinator refreshes preferred/current.
					// We stay in Idle until delegated work arrives; then we accept if guard_IsCurrentActiveCoordinator.
					If:     guard_IsNewBlockRangeEpoch,
					Action: action_SelectActiveCoordinator,
				},
			},
		},
			common.Event_TransactionStateTransition: {
				Actions: []ActionRule{
					{
						// There is a small chance we have come here from State_Closing and still have transactions in terminal
						// states from the previous block range that we haven't cleaned up from memory yet, so we handle that here.
						// We need to keep heartbeating if we have these transactions in memory.
						Validator: validator_TransactionStateTransitionTo(transaction.State_Final),
						Action:    action_CleanUpTransaction,
					},
				},
			},
			Event_ActiveCoordinatorUnavailable: {
				Actions: []ActionRule{
					// Our originator must be trying to do something to detect this unavailability and select a new active coordinator.
					// We don't transition in response to this event but we will likely see a heartbeat or delegation request very soon.
					{Action: action_CurrentActiveCoordinatorUnavailable},
				},
			},
		},
	},
	State_Observing: {
		Events: map[EventType]EventHandler{
			Event_TransactionsDelegated: {
				Actions: []ActionRule{{Action: action_RejectDelegatedTransactions}},
			},
			common.Event_HeartbeatReceived: {
				Validator: statemachine.ValidatorOr(
					validator_IsHeartbeatFromCurrentActiveCoordinator,
					validator_IsHeartbeatFromPreferredActiveCoordinator,
				),
				Actions: []ActionRule{
					{Action: action_HeartbeatReceived},
					{Action: action_ResetHeartbeatIntervalsSinceLastReceive},
				},
			},
			common.Event_HeartbeatInterval: {
				Actions: []ActionRule{
					{Action: action_IncrementHeartbeatIntervalCounts},
				},
				Transitions: []Transition{{
					To: State_Idle,
					If: guard_InactiveGracePeriodExceeded,
				}},
			},
			common.Event_NewBlock: {
				Actions: []ActionRule{
					{
						Action: action_UpdateBlockHeight,
					},
					{
						Action: action_ExpireGrapherLocks,
					},
					{
						If:     guard_IsNewBlockRangeEpoch,
						Action: action_SelectActiveCoordinator,
					},
				},
				Transitions: []Transition{{
					To: State_Elect,
					If: guard_IsPreferredActiveCoordinator,
				}},
			},
			Event_ActiveCoordinatorUnavailable: {
				Actions: []ActionRule{
					{Action: action_CurrentActiveCoordinatorUnavailable},
				},
				// It should be impossible to receive this event in observing as our own inactive transition to
				// idle should happen in response to lack of heartbeats before the originator can queue this event
				// for us, but we include the path for completeness.
				// From idle we can
				// - accept delegations and move to active if we are the new active coordinator
				// - accept heartbeats and move to observing if we are not the new active coordinator
				Transitions: []Transition{{
					To: State_Idle,
				}},
			},
		},
	},
	State_Elect: {
		Events: map[EventType]EventHandler{
			Event_TransactionsDelegated: {
				Actions: []ActionRule{{Action: action_RejectDelegatedTransactions}},
			},
			common.Event_HeartbeatReceived: {
				Validator: validator_IsHeartbeatFromPreviousActiveCoordinator,
				Actions: []ActionRule{
					{Action: action_HeartbeatReceived},
					{Action: action_ResetHeartbeatIntervalsSinceLastReceive},
				},
				Transitions: []Transition{{
					To: State_Active,
					If: guard_ActiveCoordinatorFlushComplete,
					// Import confirmed locks and private state data from the closing heartbeat so
					// the new coordinator's grapher has the ahead-of-chain view it needs to assemble
					// new transactions correctly.
					Actions: []ActionRule{{Action: action_ImportStatesAndLocks}},
				}},
			},
			common.Event_TransactionStateTransition: {
				Actions: []ActionRule{
					{
						// There is a small chance we have come here from State_Closing and still have transactions in terminal
						// states from the previous block range that we haven't cleaned up from memory yet, so we handle that here.
						// We need to keep heartbeating if we have these transactions in memory.
						Validator: validator_TransactionStateTransitionTo(transaction.State_Final),
						Action:    action_CleanUpTransaction,
					},
				},
			},
			common.Event_HeartbeatInterval: {
				Actions: []ActionRule{
					{Action: action_IncrementHeartbeatIntervalCounts},
					{
						// Sending a heartbeat only if we have in memory transactions from a previous block range which hadn't yet
						// been cleaned up when we moved from State_Closing to State_Selected. This is very unlikely to occur, but
						// it is technically possible if we are configured with a small block range but a long closing grace period.
						Action: action_SendHeartbeat,
						If:     guard_HasTransactionsInflight,
					},
				},
				// If we stop receiving heartbeats from the previously active coordinator, we move to State_Active
				// without confirming that the flush is complete. There is a risk that the previous coordinator is actually
				// still submitting transactions and it is network issues causing us to not receive heartbeats. In this case
				// we will have state contention on the base ledger, but this should eventually be resolved with retries.
				Transitions: []Transition{{
					To: State_Active,
					If: guard_InactiveGracePeriodExpiredSinceStateChange,
				}},
			},
			common.Event_NewBlock: {
				Actions: []ActionRule{
					{
						Action: action_UpdateBlockHeight,
					},
					{
						Action: action_ExpireGrapherLocks,
					},
					{
						If:     guard_IsNewBlockRangeEpoch,
						Action: action_SelectActiveCoordinator,
					},
				},
				// This transition should only happen if we have either a very short block range, or the previous active
				// coordinator is taking a very long time to flush (e.g. dispatched transactions but base ledger is unavailble).
				Transitions: []Transition{{
					To: State_Observing,
					If: statemachine.GuardNot(guard_IsCurrentActiveCoordinator),
				}},
			},
		},
	},
	State_Active: {
		OnTransitionTo: []ActionRule{
			{Action: action_NewSigningIdentity},
			{Action: action_SelectTransaction},
		},
		Events: map[EventType]EventHandler{
			common.Event_HeartbeatInterval: {
				Actions: []ActionRule{
					{Action: action_IncrementHeartbeatIntervalsSinceStateChange},
					{Action: action_PropagateHeartbeatIntervalToTransactions},
					{Action: action_SendHeartbeat},
				},
				Transitions: []Transition{{
					To: State_Idle,
					If: statemachine.GuardNot(guard_HasTransactionsInflight),
				}},
			},
			// If we've recevied a heartbeat from the preferred active coordinator we must stop coordinating immediately.
			// We flush the transactions we have past the point of no return and track them through to completion; however,
			// the protocol doesn't currently attempt any handover of locks, instead tolerating what will be retryable on chain
			// failures.
			// TODO AM: think about checking block height tolerance and handover of locks here https://github.com/LFDT-Paladin/paladin/issues/1141
			common.Event_HeartbeatReceived: {
				Validator: validator_IsHeartbeatFromPreferredActiveCoordinator,
				Actions: []ActionRule{
					{Action: action_HeartbeatReceived},
					{Action: action_ResetHeartbeatIntervalsSinceLastReceive},
					{Action: action_CleanUpTransactionsNotYetDispatched},
				},
				Transitions: []Transition{{
					To: State_Flush,
					If: statemachine.GuardAnd(
						statemachine.GuardNot(guard_FlushComplete),
					),
				}, {
					To: State_Closing,
					If: statemachine.GuardAnd(
						guard_FlushComplete,
					),
				}},
			},
			Event_TransactionsDelegated: {
				// don't select a transaction here since events must to move into pooled state before
				// they can be selected and there is a separate event for that
				Actions: []ActionRule{{Action: action_ProcessDelegatedTransactions}},
			},
			common.Event_TransactionStateTransition: {
				Actions: []ActionRule{
					{
						// This TX is leaving dispatched after being reverted on chain, cancel any transaction being assembled
						// This could be more nuanced if we could capture the set of potential states that are being removed
						// as part of unwinding the dependency chain, and only repool the transaction once assembly is complete if
						// it is using one of these potential outputs as an input.
						Validator: statemachine.ValidatorAnd(
							validator_TransactionStateTransitionFrom(transaction.State_Dispatched),
							validator_TransactionStateTransitionTo(transaction.State_Pooled, transaction.State_Reverted),
						),
						If:     guard_HasTransactionAssembling,
						Action: action_cancelCurrentlyAssemblingTransaction,
					},
					{
						Validator: validator_TransactionStateTransitionTo(transaction.State_Pooled),
						Action:    action_PoolTransaction,
					},
					{
						Validator: validator_TransactionStateTransitionTo(transaction.State_Ready_For_Dispatch),
						Action:    action_QueueTransactionForDispatch,
					},
					{
						Validator: validator_TransactionStateTransitionTo(transaction.State_Final),
						Action:    action_CleanUpTransaction,
					},
					{
						Validator: validator_TransactionStateTransitionTo(transaction.State_Evicted),
						Action:    action_CleanUpTransaction,
					},
					{
						Action: action_NudgeDispatchLoop,
					},
					{
						Action: action_SelectTransaction,
						If:     statemachine.GuardNot(guard_HasTransactionAssembling),
					},
				},
			},
			// TODO: We are periodically flushing in all coordinator selection modes, not just coordinator endorser, where the preferred
			// active coordinator can change. This allows us to rotate the signing identity on a regular basis, but we might want to consider
			// making this behaviour configurable via the domain (e.g. when the domain will provide the signing identity, or is configured to
			// use a fixed signing identity)
			common.Event_NewBlock: {
				Actions: []ActionRule{
					{
						Action: action_UpdateBlockHeight,
					},
					{
						Action: action_ExpireGrapherLocks,
					},
					{
						If:     guard_IsNewBlockRangeEpoch,
						Action: action_SelectActiveCoordinator,
					},
					// If we are entering a new block range we clean up transactions that have not reached point of no return.
					// They will disappear from our heartbeats which will trigger the originator to start trying to redelegate to the new
					// currentActiveCoordinator (which could be us). The new coordinator should be rejecting these delegations until it is in
					// State_Active (e.g. while it waits for the flush to complete). If it doesn't, the base ledger still protects against
					// duplicate submissions and double spends; we tolerate the inefficiency this causes in the protocol.
					//
					// We clean up ahead of transitioning out of State_Active so that we can make a decision about where we need to go next.
					// E.g. we don't need to flush if we don't have any dispatched transactions.
					{
						If:     guard_IsNewBlockRangeEpoch,
						Action: action_CleanUpTransactionsNotYetDispatched,
					},
				},
				// All of these transitions only apply if we are entering a new block range. After action_SelectActiveCoordinator on epoch,
				// preferredActiveCoordinator and currentActiveCoordinator always match.
				// If we reach these transitions without having any inflight transactions, we must have just cleaned up the transactions
				// that hadn't yet reached the point of no return, otherwise we would have been in State_Idle, not State_Active. This is why
				// we preemptively transition to State_Active/State_Observing, since we know the transactions we cleaned up should be immediately
				// redelegated to the new currentActiveCoordinator.
				Transitions: []Transition{{
					// We still have dispatched transactions in memory. Regardless of whether or not we are the active coordinator
					// for this block range, we still need to flush all the dispatched transactions from the previous block range.
					To: State_Flush,
					If: statemachine.GuardAnd(
						guard_IsNewBlockRangeEpoch,
						statemachine.GuardNot(guard_FlushComplete),
					),
				}, {
					// We don't have any dispatched transactions in memory and we are still the current active coordinator.
					// We "reenter" State_Active so that we can trigger a signing key rotation.
					To: State_Active,
					If: statemachine.GuardAnd(
						guard_IsNewBlockRangeEpoch,
						guard_FlushComplete,
						guard_IsCurrentActiveCoordinator,
					),
				}, {
					// We don't have any dispatched transactions in memory and and another node has been selected as the new active coordinator.
					// We move straight to State_Closing so that the new active coordinator knows that we have stood down.
					To: State_Closing,
					If: statemachine.GuardAnd(
						guard_IsNewBlockRangeEpoch,
						guard_FlushComplete,
						statemachine.GuardNot(guard_IsCurrentActiveCoordinator),
					),
				}},
			},
		},
	},
	State_Flush: {
		Events: map[EventType]EventHandler{
			Event_TransactionsDelegated: {
				Actions: []ActionRule{{Action: action_RejectDelegatedTransactions}},
			},
			common.Event_HeartbeatInterval: {
				Actions: []ActionRule{
					{Action: action_IncrementHeartbeatIntervalsSinceStateChange},
					{Action: action_SendHeartbeat},
					{Action: action_PropagateHeartbeatIntervalToTransactions},
				},
			},
			common.Event_NewBlock: {
				Actions: []ActionRule{
					{
						Action: action_UpdateBlockHeight,
					},
					{
						Action: action_ExpireGrapherLocks,
					},
					{
						If:     guard_IsNewBlockRangeEpoch,
						Action: action_SelectActiveCoordinator,
					},
				},
			},
			common.Event_TransactionStateTransition: {
				Actions: []ActionRule{
					{
						Validator: validator_TransactionStateTransitionTo(transaction.State_Final),
						Action:    action_CleanUpTransaction,
					}, {
						// A transaction was dispatched and has been reverted on chain but the revert reason has been considered
						// retryable. The next coordinator will be able to assemble and submit this transaction again. We just
						// need to clean it up from memory.
						Validator: statemachine.ValidatorAnd(
							validator_TransactionStateTransitionFrom(transaction.State_Dispatched),
							statemachine.ValidatorNot(
								validator_TransactionStateTransitionTo(transaction.State_Confirmed, transaction.State_Reverted),
							),
						),
						Action: action_CleanUpTransaction,
					},
				},
				Transitions: []Transition{{
					// Another node is the active coordinator for the epoch; move to Closing to keep heartbeating confirmed work through grace period.
					To: State_Closing,
					If: statemachine.GuardAnd(guard_FlushComplete, statemachine.GuardNot(guard_IsCurrentActiveCoordinator)),
				}, {
					// We are still the active coordinator for the new block range. We move back to State_Active
					// so we can start accepting delegated transactions again, and submitting them using our new signing identity.
					To: State_Active,
					If: statemachine.GuardAnd(guard_FlushComplete, guard_IsCurrentActiveCoordinator),
				}},
			},
			Event_ActiveCoordinatorUnavailable: {
				Actions: []ActionRule{
					{Action: action_CurrentActiveCoordinatorUnavailable},
				},
			},
		},
	},
	State_Closing: {
		// Send a heartbeat here, outside of the usual heartbeat interval, so that other nodes see that we've finished our flush without delay.
		OnTransitionTo: []ActionRule{
			{Action: action_SendHeartbeat},
		},
		Events: map[EventType]EventHandler{
			Event_TransactionsDelegated: {
				Actions: []ActionRule{{Action: action_RejectDelegatedTransactions}},
			},
			common.Event_HeartbeatReceived: {
				Validator: statemachine.ValidatorOr(
					validator_IsHeartbeatFromCurrentActiveCoordinator,
					validator_IsHeartbeatFromPreferredActiveCoordinator,
				),
				Actions: []ActionRule{
					{Action: action_HeartbeatReceived},
					{Action: action_ResetHeartbeatIntervalsSinceLastReceive},
				}},
			common.Event_HeartbeatInterval: {
				Actions: []ActionRule{
					{Action: action_IncrementHeartbeatIntervalsSinceStateChange},
					{Action: action_SendHeartbeat},
					{Action: action_PropagateHeartbeatIntervalToTransactions},
				},
				// Regardless of whether we have transactions in memory or not, we stay in closing until the closing grace period
				// has expired so that we can continue to send heartbeats to the other nodes, including the new active coordinator.
				Transitions: []Transition{{
					To: State_Idle,
					If: statemachine.GuardAnd(
						statemachine.GuardNot(guard_HasTransactionsInflight),
						guard_ClosingGracePeriodExpired,
						guard_InactiveGracePeriodExceeded,
					),
				}, {
					To: State_Observing,
					If: statemachine.GuardAnd(
						statemachine.GuardNot(guard_HasTransactionsInflight),
						guard_ClosingGracePeriodExpired,
						statemachine.GuardNot(guard_InactiveGracePeriodExceeded),
					),
				}},
			},
			common.Event_TransactionStateTransition: {
				Actions: []ActionRule{
					{
						Validator: validator_TransactionStateTransitionTo(transaction.State_Final),
						Action:    action_CleanUpTransaction,
					},
				},
			},
			common.Event_NewBlock: {
				Actions: []ActionRule{
					{
						Action: action_UpdateBlockHeight,
					},
					{
						Action: action_ExpireGrapherLocks,
					},
					{
						If:     guard_IsNewBlockRangeEpoch,
						Action: action_SelectActiveCoordinator,
					},
				},
				// If we're now the active coordinator again we can leave closing earlier than the closing grace period
				// These are all edge case transitions, likely to only be reached if there is a significant delay in confirming
				// dispatched transactions, or if the block range is configured to be very short.
				//
				// In all cases we need to transition into a state that allows us to (eventually) process delegated transactions again.
				// The key deciding factor is whether we have been receiving heartbeats from the previous active coordinator or whether
				// the system has gone idle.
				Transitions: []Transition{{
					To: State_Elect,
					If: statemachine.GuardAnd(
						guard_IsCurrentActiveCoordinator,
						statemachine.GuardNot(guard_InactiveGracePeriodExpiredSinceStateChange),
					),
				}, {
					To: State_Active,
					If: statemachine.GuardAnd(
						guard_IsCurrentActiveCoordinator,
						guard_InactiveGracePeriodExpiredSinceStateChange,
						guard_HasTransactionsInflight,
					),
				}, {
					To: State_Idle,
					If: statemachine.GuardAnd(
						guard_IsCurrentActiveCoordinator,
						guard_InactiveGracePeriodExpiredSinceStateChange,
						statemachine.GuardNot(guard_HasTransactionsInflight),
					),
				}},
			},
			Event_ActiveCoordinatorUnavailable: {
				Actions: []ActionRule{
					{Action: action_CurrentActiveCoordinatorUnavailable},
				},
				Transitions: []Transition{{
					To: State_Active,
					If: statemachine.GuardAnd(
						guard_IsCurrentActiveCoordinator,
						guard_HasTransactionsInflight,
					),
				}, {
					To: State_Idle,
					If: statemachine.GuardAnd(
						guard_IsCurrentActiveCoordinator,
						statemachine.GuardNot(guard_HasTransactionsInflight),
					),
				}},
			},
		},
	},
}

func (c *coordinator) initializeStateMachineEventLoop(initialState State, eventQueueSize int, priorityEventQueueSize int) {
	c.stateMachineEventLoop = statemachine.NewStateMachineEventLoop(statemachine.StateMachineEventLoopConfig[State, *coordinator]{
		InitialState:           initialState,
		Definitions:            stateDefinitionsMap,
		Entity:                 c,
		EventQueueSize:         eventQueueSize,
		PriorityEventQueueSize: priorityEventQueueSize,
		Name:                   fmt.Sprintf("coordinator-%s", c.contractAddress.String()[0:8]),
		TransitionCallback:     c.onStateTransition,
		PreProcess:             c.preProcessEvent,
	})
}

// preProcessEvent handles events that should be processed before the state machine.
// Returns (true, nil) if the event was fully handled and should not be passed to the state machine.
func (c *coordinator) preProcessEvent(ctx context.Context, entity *coordinator, event common.Event) (bool, error) {
	// Transaction events are propagated to the transaction state machine, not the coordinator state machine
	if transactionEvent, ok := event.(transaction.Event); ok {
		log.L(ctx).Debugf("coordinator propagating event %s to transactions: %s", event.TypeString(), transactionEvent.TypeString())
		return true, c.propagateEventToTransaction(ctx, transactionEvent)
	}
	return false, nil
}

// onStateTransition is called when the state machine transitions to a new state
func (c *coordinator) onStateTransition(ctx context.Context, entity *coordinator, from State, to State, event common.Event) {
	c.heartbeatIntervalsSinceStateChange = 0
}

// QueueEvent asynchronously queues a state machine event for processing.
// Should be called by most Paladin components to ensure memory integrity of
// sequencer state machine and transactions.
func (c *coordinator) QueueEvent(ctx context.Context, event common.Event) {
	c.stateMachineEventLoop.QueueEvent(ctx, event)
}

func (c *coordinator) TryQueueEvent(ctx context.Context, event common.Event) bool {
	return c.stateMachineEventLoop.TryQueueEvent(ctx, event)
}

// Queue a state machine event generated internally for the sequencer loop to process. Is prioritized above
// external event sources
func (c *coordinator) queueEventInternal(ctx context.Context, event common.Event) {
	c.stateMachineEventLoop.QueuePriorityEvent(ctx, event)
}
