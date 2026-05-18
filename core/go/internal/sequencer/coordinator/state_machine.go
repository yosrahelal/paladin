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
	State_Initial       = common.CoordinatorState_Initial       // Coordinator created but not yet selected an active coordinator
	State_Idle          = common.CoordinatorState_Idle          // Not acting as a coordinator and not aware of any other active coordinators
	State_Observing     = common.CoordinatorState_Observing     // Not acting as a coordinator but aware of another node acting as a coordinator
	State_Elect         = common.CoordinatorState_Elect         // Sent HandoverRequest to the active coordinator; waiting to see it start flushing
	State_Prepared      = common.CoordinatorState_Prepared      // Confirmed the active coordinator is flushing; waiting for its Closing heartbeat before taking over
	State_Active        = common.CoordinatorState_Active        // Assembling and dispatching transactions; may remain active across epoch boundaries
	State_Active_Flush  = common.CoordinatorState_Active_Flush  // Draining dispatched transactions while still the active coordinator (key-rotation)
	State_Closing_Flush = common.CoordinatorState_Closing_Flush // Draining dispatched transactions after stepping down (preemption)
	State_Closing       = common.CoordinatorState_Closing       // Flush complete; sending closing heartbeats through the grace period
)

const (
	Event_CoordinatorCreated EventType = iota + 200
	Event_TransactionsDelegated
	Event_RequestTimeoutInterval
	Event_StateTimeoutInterval
	Event_HandoverRequest // pushed by transport_client when a CoordinatorHandoverRequest message is received from a higher-priority node
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

var stateDefinitionsMap = StateDefinitions{
	State_Initial: {
		Events: map[EventType]EventHandler{
			Event_CoordinatorCreated: {
				Actions:     []ActionRule{{Action: action_CalculateCoordinatorPriorities}},
				Transitions: []Transition{{To: State_Idle}},
			},
		},
	},
	State_Idle: {
		Events: map[EventType]EventHandler{
			common.Event_HeartbeatReceived: {
				Validator: validator_IsHeartbeatSenderLive,
				Actions: []ActionRule{
					{Action: action_UpdateActiveCoordinator},
				},
				Transitions: []Transition{{
					To: State_Observing,
				}},
			},
			Event_TransactionsDelegated: {
				// Any node in Idle accepts a delegation and becomes the active coordinator.
				// A higher-priority node that later announces itself will trigger preemption from Active.
				Actions:     []ActionRule{{Action: action_ProcessDelegatedTransactions}},
				Transitions: []Transition{{To: State_Active}},
			},
			common.Event_NewBlock: {
				Actions: []ActionRule{
					{Action: action_UpdateBlockHeight},
					{If: guard_IsNewBlockRangeEpoch, Action: action_CalculateCoordinatorPriorities},
				},
			},
		},
	},
	State_Observing: {
		Events: map[EventType]EventHandler{
			common.Event_HeartbeatReceived: {
				Validator: validator_IsHeartbeatSenderLive,
				Actions: []ActionRule{
					{Action: action_ResetHeartbeatIntervalsSinceLastReceive},
					{Action: action_UpdateActiveCoordinator},
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
			Event_TransactionsDelegated: {
				Actions: []ActionRule{
					{
						// This node is higher-priority than the current active coordinator — initiate a handover.
						If:     guard_IsHigherPriorityThanCurrentActive,
						Action: action_ProcessDelegatedTransactions,
					},
					{
						// This node is lower-priority — reject and include the current active coordinator's identity.
						If:     statemachine.GuardNot(guard_IsHigherPriorityThanCurrentActive),
						Action: action_RejectDelegatedTransactions,
					},
				},
				Transitions: []Transition{{
					To: State_Elect,
					If: guard_IsHigherPriorityThanCurrentActive,
				}},
			},
			common.Event_NewBlock: {
				Actions: []ActionRule{
					{Action: action_UpdateBlockHeight},
					{
						If:     guard_IsNewBlockRangeEpoch,
						Action: action_CalculateCoordinatorPriorities,
					},
				},
			},
		},
	},
	State_Elect: {
		OnTransitionTo: []ActionRule{
			{Action: action_ScheduleStateTimeout},
			{Action: action_SendHandoverRequest},
		},
		Events: map[EventType]EventHandler{
			Event_RequestTimeoutInterval: {
				Actions: []ActionRule{{Action: action_NudgeHandoverRequest}},
			},
			Event_StateTimeoutInterval: {
				// The active coordinator has not moved to flush; become active directly.
				// This may result in state contention but the protocol allows for this while
				// the system eventually normalises.
				Transitions: []Transition{{
					To:      State_Active,
					Actions: []ActionRule{{Action: action_ClearTimeoutSchedules}},
				}},
			},
			common.Event_HeartbeatInterval: {
				Actions: []ActionRule{
					{Action: action_PropagateHeartbeatIntervalToTransactions},
					{Action: action_SendHeartbeat},
				},
			},
			common.Event_HeartbeatReceived: {
				Actions: []ActionRule{
					{
						// We're not going to take over if we reach this point so clean up any delegations.
						// action_HeartbeatReceived is intentionally NOT in event-level actions here: it updates
						// currentActiveCoordinator, which would corrupt the validator_IsHeartbeatFromHigherPriorityCoordinator
						// check on the transitions below. Instead it runs as a transition action.
						Action: action_CleanUpTransactionsNotYetDispatched,
						Validator: statemachine.ValidatorAnd(
							validator_IsHeartbeatFromHigherPriorityCoordinator,
							validator_IsHeartbeatSenderLive,
						),
					},
				},
				Transitions: []Transition{
					{
						// The active coordinator has started flushing in response to our request.
						To: State_Prepared,
						Validator: statemachine.ValidatorAnd(
							validator_IsHeartbeatFromCurrentActiveCoordinator,
							validator_HeartBeatState(State_Closing_Flush, State_Closing),
						),
						Actions: []ActionRule{{Action: action_ClearTimeoutSchedules}},
					},
					{
						// A higher-priority node is now the active coordinator; stand down.
						// Move to observing if we don't have any transactions in flight.
						To: State_Observing,
						Validator: statemachine.ValidatorAnd(
							validator_IsHeartbeatFromHigherPriorityCoordinator,
							validator_IsHeartbeatSenderLive,
						),
						If: statemachine.GuardNot(guard_HasTransactionsInflight),
						Actions: []ActionRule{
							{Action: action_UpdateActiveCoordinator},
							{Action: action_ClearTimeoutSchedules},
						},
					}, {
						// Otherwise move back to closing while we wait for our previously confirmed
						// transactions to be cleared from memory.
						To: State_Closing,
						Validator: statemachine.ValidatorAnd(
							validator_IsHeartbeatFromHigherPriorityCoordinator,
							validator_IsHeartbeatSenderLive,
						),
						If: statemachine.GuardAnd(guard_HasTransactionsInflight, statemachine.GuardNot(guard_HasUnconfirmedDispatchedTransactions)),
						Actions: []ActionRule{
							{Action: action_UpdateActiveCoordinator},
							{Action: action_ClearTimeoutSchedules},
						},
					}, {
						To: State_Closing_Flush,
						Validator: statemachine.ValidatorAnd(
							validator_IsHeartbeatFromHigherPriorityCoordinator,
							validator_IsHeartbeatSenderLive,
						),
						If: statemachine.GuardAnd(guard_HasTransactionsInflight, guard_HasUnconfirmedDispatchedTransactions),
						Actions: []ActionRule{
							{Action: action_UpdateActiveCoordinator},
							{Action: action_ClearTimeoutSchedules},
						},
					},
				},
			},
		Event_HandoverRequest: {
			Validator: validator_IsHandoverRequestFromHigherPriorityCoordinator,
			Actions: []ActionRule{
				{Action: action_UpdateActiveCoordinator},
				{Action: action_CleanUpTransactionsNotYetDispatched},
			},
			Transitions: []Transition{{
				To: State_Closing_Flush,
				If: guard_HasUnconfirmedDispatchedTransactions,
			}, {
				To: State_Closing,
				If: statemachine.GuardNot(guard_HasUnconfirmedDispatchedTransactions),
			}},
		},
		Event_TransactionsDelegated: {
			// Accept delegations while in Elect so originators are not bounced while we wait.
			Actions: []ActionRule{{Action: action_ProcessDelegatedTransactions}},
			},
			common.Event_NewBlock: {
				Actions: []ActionRule{
					{Action: action_UpdateBlockHeight},
					{If: guard_IsNewBlockRangeEpoch, Action: action_CalculateCoordinatorPriorities},
				},
			},
			common.Event_TransactionStateTransition: {
				Actions: []ActionRule{
					{
						// There is a small chance we have come here from State_Closing and still have transactions in terminal
						// states from a previous time of actively coordinating that we haven't cleaned up from memory yet,
						// so we handle that here.
						Validator: validator_TransactionStateTransitionTo(transaction.State_Final),
						Action:    action_CleanUpTransaction,
					},
				},
			},
		},
	},
	State_Prepared: {
		Events: map[EventType]EventHandler{
			common.Event_HeartbeatInterval: {
				Actions: []ActionRule{
					{Action: action_IncrementHeartbeatIntervalCounts},
					{Action: action_PropagateHeartbeatIntervalToTransactions},
					{Action: action_SendHeartbeat},
				},
				Transitions: []Transition{{
					To: State_Active,
					If: guard_InactiveGracePeriodExceeded,
				}},
			},
			common.Event_HeartbeatReceived: {
				// TODO: this handler is so long because of repeated validators- we should be able to define event handlers per validator
				Actions: []ActionRule{
					{
						// In prepared we're more selective about what resets this counter:
						// Higher priority coordinators will cause a transition out of this state
						// So it's just our current active we want to track and recognise if it stops flushing
						Action: action_ResetHeartbeatIntervalsSinceLastReceive,
						Validator: statemachine.ValidatorOr(
							statemachine.ValidatorAnd(
								validator_IsHeartbeatFromCurrentActiveCoordinator,
								validator_HeartBeatState(common.CoordinatorState_Closing_Flush),
							),
							validator_IsHeartbeatFromHigherPriorityCoordinator,
						),
					},
					// Clean up any transactions the outgoing coordinator has already confirmed so that we don't duplicate
					// if their originator has already redelegated to us
					{Action: action_ProcessConfirmedTransactionsFromSnapshot},
					{
						// We're not going to take over if we reach this point so clean up any delegations
						Action: action_CleanUpTransactionsNotYetDispatched,
						Validator: statemachine.ValidatorAnd(
							validator_IsHeartbeatFromHigherPriorityCoordinator,
							validator_IsHeartbeatSenderLive,
						),
					},
				},
				Transitions: []Transition{
					{
						// The outgoing coordinator has completed its flush; we can take over.
						To: State_Active,
						Validator: statemachine.ValidatorAnd(
							validator_IsHeartbeatFromCurrentActiveCoordinator,
							validator_HeartBeatState(common.CoordinatorState_Closing),
						),
						Actions: []ActionRule{{Action: action_ImportStatesAndLocks}},
					},
					{
						// A higher-priority node is now the active coordinator; stand down.
						// Move to observing if we don't have any transactions in flight
						To: State_Observing,
						Validator: statemachine.ValidatorAnd(
							validator_IsHeartbeatFromHigherPriorityCoordinator,
							validator_IsHeartbeatSenderLive,
						),
						If: statemachine.GuardNot(guard_HasTransactionsInflight),
						Actions: []ActionRule{
							{Action: action_ClearTimeoutSchedules},
						},
					}, {
						// Otherwise move back to closing or flush while we wait for our previously confirmed
						// transactions to be cleared from memory
						To: State_Closing,
						Validator: statemachine.ValidatorAnd(
							validator_IsHeartbeatFromHigherPriorityCoordinator,
							validator_IsHeartbeatSenderLive,
						),
						If: statemachine.GuardAnd(guard_HasTransactionsInflight, statemachine.GuardNot(guard_HasUnconfirmedDispatchedTransactions)),
						Actions: []ActionRule{
							{Action: action_ClearTimeoutSchedules},
						},
					}, {
						To: State_Closing_Flush,
						Validator: statemachine.ValidatorAnd(
							validator_IsHeartbeatFromHigherPriorityCoordinator,
							validator_IsHeartbeatSenderLive,
						),
						If: statemachine.GuardAnd(guard_HasTransactionsInflight, guard_HasUnconfirmedDispatchedTransactions),
						Actions: []ActionRule{
							{Action: action_ClearTimeoutSchedules},
						},
					},
				},
			},
		Event_HandoverRequest: {
			Validator: validator_IsHandoverRequestFromHigherPriorityCoordinator,
			Actions: []ActionRule{
				{Action: action_UpdateActiveCoordinator},
				{Action: action_CleanUpTransactionsNotYetDispatched},
			},
			Transitions: []Transition{{
				To: State_Closing_Flush,
				If: guard_HasUnconfirmedDispatchedTransactions,
			}, {
				To: State_Closing,
				If: statemachine.GuardNot(guard_HasUnconfirmedDispatchedTransactions),
			}},
		},
		Event_TransactionsDelegated: {
			Actions: []ActionRule{{Action: action_ProcessDelegatedTransactions}},
		},
		common.Event_NewBlock: {
			Actions: []ActionRule{
				{Action: action_UpdateBlockHeight},
				{If: guard_IsNewBlockRangeEpoch, Action: action_CalculateCoordinatorPriorities},
			},
		},
		common.Event_TransactionStateTransition: {
			Actions: []ActionRule{
				{
					// There is a small chance we have come here from State_Closing (via State_Elect) and still have transactions in terminal
					// states from a previous time of actively coordinating that we haven't cleaned up from memory yet,
					// so we handle that here.
					Validator: validator_TransactionStateTransitionTo(transaction.State_Final),
					Action:    action_CleanUpTransaction,
				},
			},
		},
	},
},
State_Active: {
		OnTransitionTo: []ActionRule{
			{Action: action_NewSigningIdentity},
			{Action: action_StartDispatchLoop},
			{Action: action_SelectTransaction},
			// Now we're active we can remove any record of inactivity from a previous coordinator
			// We don't increment the counters in this state as we're the active coordinator who is heartbeating.
			{Action: action_ResetHeartbeatIntervalsSinceLastReceive},
		},
		OnTransitionFrom: []ActionRule{
			// No op if already stopped- some transitions need to call this earlier
			{Action: action_StopDispatchLoop},
		},
		Events: map[EventType]EventHandler{
			common.Event_HeartbeatInterval: {
				Actions: []ActionRule{
					{Action: action_PropagateHeartbeatIntervalToTransactions},
					{Action: action_SendHeartbeat},
				},
				Transitions: []Transition{{
					To: State_Idle,
					If: statemachine.GuardNot(guard_HasTransactionsInflight),
				}},
			},
			common.Event_HeartbeatReceived: {
				// TODO AM: could this become an array - or can the state machine support and array- first validator wins
				Validator: statemachine.ValidatorAnd(
					validator_IsHeartbeatFromHigherPriorityCoordinator,
					validator_IsHeartbeatSenderLive,
				),
				// A higher-priority node live node is announcing itself; step down.
				Transitions: []Transition{{
					To: State_Closing_Flush,
					Actions: []ActionRule{
						{Action: action_UpdateActiveCoordinator},
						{Action: action_StopDispatchLoop},
						// Once the dispatch loop is stopped we know there won't be anymore
						// State_Ready_For_Dispatch to State_Dispatched transitions so it is safe to clean up
						{Action: action_CleanUpTransactionsNotYetDispatched},
					},
				}},
			},
			Event_HandoverRequest: {
				// A higher-priority node has explicitly requested we step down; treat identically to a preemption heartbeat.
				// The difference is that the other node will watch our flush and take over gracefully
				Validator: validator_IsHandoverRequestFromHigherPriorityCoordinator,
				Actions: []ActionRule{
					{Action: action_UpdateActiveCoordinator},
					{Action: action_StopDispatchLoop},
					// Once the dispatch loop is stopped we know there won't be anymore
					// State_Ready_For_Dispatch to State_Dispatched transitions so it is safe to clean up
					{Action: action_CleanUpTransactionsNotYetDispatched},
				},
				Transitions: []Transition{{
					To: State_Closing_Flush,
					If: guard_HasUnconfirmedDispatchedTransactions,
				}, {
					To: State_Closing,
					If: statemachine.GuardNot(guard_HasUnconfirmedDispatchedTransactions),
				}},
			},
			Event_TransactionsDelegated: {
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
			common.Event_NewBlock: {
				Actions: []ActionRule{
					{Action: action_UpdateBlockHeight},
					{If: guard_IsNewBlockRangeEpoch, Action: action_CalculateCoordinatorPriorities},
					// If we're in a new block range epoch and the signing key has been used
					// we need to rotate it. Stop the dispatch loop ahead of making a decision on whether
					// we have any unconfirmed dispatched transactions

					// The transition from Active -> Active may seem a bit odd here but it is a clean way
					// to trigger a signing key rotation and only then restart the dispatch loop if we do not
					// have any transactions to flush.
					{
						Action: action_StopDispatchLoop,
						If: statemachine.GuardAnd(
							guard_IsNewBlockRangeEpoch,
							guard_SigningIdentityUsed,
						),
					},
				},
				// Transition to Active_Flush for a key-rotation drain: the signing identity has been used
				// but there are still dispatched transactions in-flight that must be confirmed first.
				Transitions: []Transition{{
					To: State_Active_Flush,
					If: statemachine.GuardAnd(
						guard_IsNewBlockRangeEpoch,
						guard_SigningIdentityUsed,
						guard_HasUnconfirmedDispatchedTransactions,
					),
				}, {
					To: State_Active,
					If: statemachine.GuardAnd(
						guard_IsNewBlockRangeEpoch,
						guard_SigningIdentityUsed,
						statemachine.GuardNot(guard_HasUnconfirmedDispatchedTransactions),
					),
				}},
			},
		},
	},
	State_Active_Flush: {
		// Key-rotation flush: this node is still the active coordinator; it is draining dispatched
		// transactions so the signing key can be rotated before the next dispatch.
		Events: map[EventType]EventHandler{
			common.Event_HeartbeatInterval: {
				Actions: []ActionRule{
					{Action: action_PropagateHeartbeatIntervalToTransactions},
					{Action: action_SendHeartbeat},
				},
			},
			common.Event_HeartbeatReceived: {
				// TODO AM: could this become an array - or can the state machine support and array- first validator wins
				Validator: statemachine.ValidatorAnd(
					validator_IsHeartbeatFromHigherPriorityCoordinator,
					validator_IsHeartbeatSenderLive,
				),
				// A higher-priority node live node is announcing itself; step down.
				Transitions: []Transition{{
					To: State_Closing_Flush,
					Actions: []ActionRule{
						{Action: action_UpdateActiveCoordinator},
						{Action: action_ClearTimeoutSchedules},
						{Action: action_CleanUpTransactionsNotYetDispatched},
					},
				}},
			},
			Event_HandoverRequest: {
				// A higher-priority node has explicitly requested we step down; treat identically to a preemption heartbeat.
				// The difference is that the other node will watch our flush and take over gracefully
				Validator: validator_IsHandoverRequestFromHigherPriorityCoordinator,
				Actions: []ActionRule{
					{Action: action_CleanUpTransactionsNotYetDispatched},
					{Action: action_UpdateActiveCoordinator},
				},
				Transitions: []Transition{{
					To: State_Closing_Flush,
					If: guard_HasUnconfirmedDispatchedTransactions,
				}, {
					To: State_Closing,
					If: statemachine.GuardNot(guard_HasUnconfirmedDispatchedTransactions),
				}},
			},
			Event_TransactionsDelegated: {
				// Still the active coordinator — accept delegations normally- we can process transactions, just not dispatch them
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
						Action: action_SelectTransaction,
						If:     statemachine.GuardNot(guard_HasTransactionAssembling),
					},
				},
				Transitions: []Transition{{
					To: State_Active,
					If: statemachine.GuardNot(guard_HasUnconfirmedDispatchedTransactions),
				}},
			},
			common.Event_NewBlock: {
				Actions: []ActionRule{
					{Action: action_UpdateBlockHeight},
					{If: guard_IsNewBlockRangeEpoch, Action: action_CalculateCoordinatorPriorities},
				},
			},
		},
	},
	State_Closing_Flush: {
		// Step-down flush: this node is no longer the active coordinator.
		// It drains dispatched transactions before transitioning to Closing.
		// Send an immediate heartbeat on entry so any node waiting in State_Elect sees the
		// flush acknowledgement without waiting for the next heartbeat interval.
		OnTransitionTo: []ActionRule{
			{Action: action_SendHeartbeat},
		},
		Events: map[EventType]EventHandler{
			common.Event_HeartbeatInterval: {
				Actions: []ActionRule{
					{Action: action_IncrementHeartbeatIntervalsSinceStateChange},
					{Action: action_SendHeartbeat},
					{Action: action_PropagateHeartbeatIntervalToTransactions},
				},
			},
			common.Event_HeartbeatReceived: {
				Actions: []ActionRule{{
					Action:    action_ResetHeartbeatIntervalsSinceLastReceive,
					Validator: validator_IsHeartbeatSenderLive,
				}},
			},
			Event_TransactionsDelegated: {
				Actions: []ActionRule{
					{
						// This node is now higher-priority than the current active coordinator we stepped down for
						If:     guard_IsHigherPriorityThanCurrentActive,
						Action: action_ProcessDelegatedTransactions,
					},
					{
						// This node is lower-priority — reject and include the current active coordinator's identity.
						If:     statemachine.GuardNot(guard_IsHigherPriorityThanCurrentActive),
						Action: action_RejectDelegatedTransactions,
					},
				},
				Transitions: []Transition{{
					// this is an edge case which would require disagreement within the network at a block range epoch boundary
					To: State_Elect,
					If: guard_IsHigherPriorityThanCurrentActive,
				}},
			},
			common.Event_TransactionStateTransition: {
				Actions: []ActionRule{
					{
						Validator: validator_TransactionStateTransitionTo(transaction.State_Final),
						Action:    action_CleanUpTransaction,
					},
					{
						// A dispatched transaction was reverted but it retryable; clean up so the originator can redelegate to the new coordinator.
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
					To: State_Closing,
					If: statemachine.GuardNot(guard_HasUnconfirmedDispatchedTransactions),
				}},
			},
			common.Event_NewBlock: {
				Actions: []ActionRule{
					{Action: action_UpdateBlockHeight},
					{If: guard_IsNewBlockRangeEpoch, Action: action_CalculateCoordinatorPriorities},
				},
			},
		},
	},
	State_Closing: {
		// Send an immediate heartbeat on entry so that any node waiting in State_Prepared sees
		// the flush-complete signal without waiting for the next heartbeat interval.
		OnTransitionTo: []ActionRule{{Action: action_SendHeartbeat}},
		Events: map[EventType]EventHandler{
			common.Event_HeartbeatReceived: {
				Validator: validator_IsHeartbeatSenderLive,
				Actions: []ActionRule{
					{Action: action_ResetHeartbeatIntervalsSinceLastReceive},
					{Action: action_UpdateActiveCoordinator},
				},
			},
			common.Event_HeartbeatInterval: {
				Actions: []ActionRule{
					{Action: action_IncrementHeartbeatIntervalsSinceStateChange},
					{Action: action_SendHeartbeat},
					{Action: action_PropagateHeartbeatIntervalToTransactions},
				},
				Transitions: []Transition{
					{
						To: State_Idle,
						If: statemachine.GuardAnd(
							statemachine.GuardNot(guard_HasTransactionsInflight),
							guard_ClosingGracePeriodExpired,
							guard_InactiveGracePeriodExceeded,
						),
					},
					{
						To: State_Observing,
						If: statemachine.GuardAnd(
							statemachine.GuardNot(guard_HasTransactionsInflight),
							guard_ClosingGracePeriodExpired,
							statemachine.GuardNot(guard_InactiveGracePeriodExceeded),
						),
					},
				},
			},
			Event_TransactionsDelegated: {
				Actions: []ActionRule{{
					// Current active coordinator is still live and higher priority; redirect the originator.
					If: statemachine.GuardAnd(
						statemachine.GuardNot(guard_IsHigherPriorityThanCurrentActive),
						statemachine.GuardNot(guard_InactiveGracePeriodExceeded),
					),
					Action: action_RejectDelegatedTransactions,
				}},
				Transitions: []Transition{
					{
						To: State_Elect,
						If: statemachine.GuardAnd(
							guard_IsHigherPriorityThanCurrentActive,
							statemachine.GuardNot(guard_InactiveGracePeriodExceeded),
						),
						Actions: []ActionRule{{Action: action_ProcessDelegatedTransactions}},
					},
					{
						// Move to active if the current active coordinator has gone idle regardless of priority
						To: State_Active,
						If: statemachine.GuardAnd(
							statemachine.GuardNot(guard_IsHigherPriorityThanCurrentActive),
							guard_InactiveGracePeriodExceeded,
						),
					},
				},
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
					{Action: action_UpdateBlockHeight},
					{If: guard_IsNewBlockRangeEpoch, Action: action_CalculateCoordinatorPriorities},
				},
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
	// heartbeat events from ourself are filtered out
	if heartbeatEvent, ok := event.(*common.HeartbeatReceivedEvent); ok {
		if heartbeatEvent.From == c.nodeName {
			return true, nil
		}
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
