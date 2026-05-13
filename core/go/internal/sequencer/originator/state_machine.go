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

	"github.com/LFDT-Paladin/paladin/common/go/pkg/log"
	"github.com/LFDT-Paladin/paladin/core/internal/components"
	"github.com/LFDT-Paladin/paladin/core/internal/sequencer/common"
	"github.com/LFDT-Paladin/paladin/core/internal/sequencer/originator/transaction"
	"github.com/LFDT-Paladin/paladin/core/internal/sequencer/statemachine"
	"github.com/google/uuid"
)

type State = common.OriginatorState
type EventType = common.EventType

const (
	State_Initial   = common.OriginatorState_Initial   // Waiting for OriginatorCreatedEvent to fire initial coordinator selection
	State_Idle      = common.OriginatorState_Idle      // Not acting as an originator and not aware of any active coordinators
	State_Observing = common.OriginatorState_Observing // Not acting as an originator but aware of a node acting as a coordinator
	State_Sending   = common.OriginatorState_Sending   // Has some transactions that have been sent to a coordinator but not yet confirmed
)

const (
	Event_OriginatorCreated  EventType = iota + 300 // fired once by Start to drive the initial coordinator selection
	Event_TransactionCreated                        // a new transaction has been created and is ready to be sent to the coordinator TODO maybe name something like Intent created?
)

// Type aliases for the generic statemachine types, specialized for originator
type (
	Action           = statemachine.Action[*originator]
	Guard            = statemachine.Guard[*originator]
	Validator        = statemachine.Validator[*originator]
	ActionRule       = statemachine.ActionRule[*originator]
	Transition       = statemachine.Transition[State, *originator]
	EventHandler     = statemachine.EventHandler[State, *originator]
	StateDefinition  = statemachine.StateDefinition[State, *originator]
	StateDefinitions = statemachine.StateDefinitions[State, *originator]
)

var stateDefinitionsMap = StateDefinitions{
	State_Initial: {
		Events: map[EventType]EventHandler{
			Event_OriginatorCreated: {
				Actions:     []ActionRule{{Action: action_SelectActiveCoordinator}},
				Transitions: []Transition{{To: State_Idle}},
			},
		},
	},
	State_Idle: {
		Events: map[EventType]EventHandler{
			common.Event_NewBlock: {
				Actions: []ActionRule{
					{
						Action: action_UpdateBlockHeight,
					},
					{
						If:     guard_IsNewBlockRangeEpoch,
						Action: action_SelectActiveCoordinator,
					},
				},
			},
			common.Event_HeartbeatReceived: {
				Validator: validator_IsHeartbeatFromCurrentActiveCoordinator,
				Actions: []ActionRule{
					{Action: action_ResetHeartbeatIntervalsSinceLastReceive},
				},
				Transitions: []Transition{{
					To: State_Observing,
				}},
			},
			Event_TransactionCreated: {
				Validator: validator_TransactionDoesNotExist,
				Actions:   []ActionRule{{Action: action_TransactionCreated}},
				Transitions: []Transition{{
					To: State_Sending,
				}},
			},
			common.Event_TransactionStateTransition: {
				Actions: []ActionRule{
					{
						Validator: validator_OriginatorTransactionStateTransitionToFinal,
						Action:    action_CleanUpTransaction,
					},
					{
						Validator: statemachine.ValidatorOr(
							validator_OriginatorTransactionStateTransitionToConfirmed,
							validator_OriginatorTransactionStateTransitionToReverted,
						),
						Action: action_FinalizeTransaction,
					},
				},
			},
			common.Event_EndorserNodesDiscovered: {
				Actions: []ActionRule{{Action: action_UpdateOriginatorNodePool}},
			},
		},
	},
	State_Observing: {
		Events: map[EventType]EventHandler{
			common.Event_NewBlock: {
				Actions: []ActionRule{
					{Action: action_UpdateBlockHeight},
					{
						If:     guard_IsNewBlockRangeEpoch,
						Action: action_SelectActiveCoordinator,
					},
				},
			},
			common.Event_HeartbeatInterval: {
				Actions:     []ActionRule{{Action: action_IncrementHeartbeatIntervalCounts}},
				Transitions: []Transition{{To: State_Idle, If: guard_InactiveGracePeriodExceeded}},
			},
			Event_TransactionCreated: {
				Validator: validator_TransactionDoesNotExist,
				Actions:   []ActionRule{{Action: action_TransactionCreated}},
				Transitions: []Transition{{
					To: State_Sending,
				}},
			},
			common.Event_HeartbeatReceived: {
				Validator: validator_IsHeartbeatFromCurrentActiveCoordinator,
				Actions: []ActionRule{
					{Action: action_ResetHeartbeatIntervalsSinceLastReceive},
				},
			},
			common.Event_TransactionStateTransition: {
				Actions: []ActionRule{
					{
						Validator: validator_OriginatorTransactionStateTransitionToFinal,
						Action:    action_CleanUpTransaction,
					},
					{
						Validator: statemachine.ValidatorOr(
							validator_OriginatorTransactionStateTransitionToConfirmed,
							validator_OriginatorTransactionStateTransitionToReverted,
						),
						Action: action_FinalizeTransaction,
					},
				},
			},
			common.Event_EndorserNodesDiscovered: {
				Actions: []ActionRule{{Action: action_UpdateOriginatorNodePool}},
			},
		},
	},
	State_Sending: {
		OnTransitionTo: []ActionRule{
			// Do not delegate immediately if we are waiting for the previous coordinator to flush;
			// the redelegate will be triggered when we finish watching.
			{
				Action: action_SendDelegationRequest,
				If:     statemachine.GuardNot(guard_WatchingPreviousCoordinatorFlush),
			},
		},
		Events: map[EventType]EventHandler{
			common.Event_NewBlock: {
				Actions: []ActionRule{
					{Action: action_UpdateBlockHeight},
					{
						If:     guard_IsNewBlockRangeEpoch,
						Action: action_SelectActiveCoordinator,
					},
					// We do not immediately delegate to the new coordinator as we need to see the previous coordinator flush and
					// close first
				},
			},
			Event_TransactionCreated: {
				Validator: validator_TransactionDoesNotExist,
				Actions: []ActionRule{
					{Action: action_TransactionCreated},
					// Do not delegate the new transaction immediately if we are watching the previous coordinator flush.
					{
						Action: action_SendDelegationRequest,
						If:     statemachine.GuardNot(guard_WatchingPreviousCoordinatorFlush),
					},
				},
			},
			common.Event_HeartbeatReceived: {
				// No validator: applyHeartbeatReceived internally handles routing between the active
				// coordinator and the previous coordinator (when watchingPreviousCoordinatorFlush is true).
				Actions: []ActionRule{
					{Action: action_HeartbeatReceived},
					{Action: action_SendDelegationRequest, If: guard_NeedsRedelegate},
				},
			},
			common.Event_HeartbeatInterval: {
				Actions: []ActionRule{
					{Action: action_IncrementHeartbeatIntervalCounts},
					// If the active coordinator has been silent past the inactive grace period, redelegate to it
					// to nudge it into action. Failover to a different coordinator is not yet implemented.
					{
						If:     statemachine.GuardOr(guard_InactiveGracePeriodExceeded, guard_NeedsRedelegate),
						Action: action_SendDelegationRequest,
					},
				},
			},
			common.Event_TransactionStateTransition: {
				Actions: []ActionRule{
					{
						Validator: validator_OriginatorTransactionStateTransitionToFinal,
						Action:    action_CleanUpTransaction,
					},
					{
						Validator: statemachine.ValidatorOr(
							validator_OriginatorTransactionStateTransitionToConfirmed,
							validator_OriginatorTransactionStateTransitionToReverted,
						),
						Action: action_FinalizeTransaction,
					},
				},
				Transitions: []Transition{
					{To: State_Observing, If: statemachine.GuardNot(guard_HasUnconfirmedTransactions)},
				},
			},
			common.Event_EndorserNodesDiscovered: {
				Actions: []ActionRule{{Action: action_UpdateOriginatorNodePool}},
			},
		},
	},
}

func (o *originator) initializeStateMachineEventLoop(initialState State, eventQueueSize int, priorityEventQueueSize int) {
	o.stateMachineEventLoop = statemachine.NewStateMachineEventLoop(statemachine.StateMachineEventLoopConfig[State, *originator]{
		InitialState:           initialState,
		Definitions:            stateDefinitionsMap,
		Entity:                 o,
		EventQueueSize:         eventQueueSize,
		PriorityEventQueueSize: priorityEventQueueSize,
		Name:                   fmt.Sprintf("originator-%s", o.contractAddress.String()[0:8]),
		PreProcess:             o.preProcessEvent,
	})
}

func (o *originator) preProcessEvent(ctx context.Context, entity *originator, event common.Event) (bool, error) {
	if transactionEvent, ok := event.(transaction.Event); ok {
		log.L(ctx).Debugf("Originator propagating transaction event %s to transaction: %s", event.TypeString(), transactionEvent.GetTransactionID().String())
		return true, o.propagateEventToTransaction(ctx, transactionEvent)
	}
	return false, nil
}

func (o *originator) GetTxStatus(ctx context.Context, txID uuid.UUID) (status components.PrivateTxStatus, err error) {
	o.RLock()
	defer o.RUnlock()
	if txn, ok := o.transactionsByID[txID]; ok {
		return txn.GetStatus(ctx), nil
	}
	return components.PrivateTxStatus{
		TxID:   txID.String(),
		Status: "unknown",
	}, nil
}
