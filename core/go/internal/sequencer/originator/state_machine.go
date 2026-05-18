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
	Event_DelegationRejected                        // pushed by transport_client when a DelegationRequestAcknowledgment arrives with Accepted == false
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
				Transitions: []Transition{{To: State_Idle}},
			},
		},
	},
	State_Idle: {
		Events: map[EventType]EventHandler{
			common.Event_HeartbeatReceived: {
				Validator: validator_IsHeartbeatSenderLive,
				Actions: []ActionRule{
					{Action: action_UpdateActiveCoordinatorFromHeartbeat},
					{Action: action_ResetHeartbeatIntervalsSinceLastReceive},
				},
				Transitions: []Transition{{To: State_Observing}},
			},
			Event_TransactionCreated: {
				Validator: validator_TransactionDoesNotExist,
				Actions:   []ActionRule{{Action: action_TransactionCreated}},
				Transitions: []Transition{{
					To: State_Sending,
				}},
			},
			common.Event_NewBlock: {
				Actions: []ActionRule{{Action: action_UpdateBlockHeight}},
			},
			common.Event_CoordinatorPriorityListUpdated: {
				Actions: []ActionRule{{Action: action_UpdateCoordinatorPriorityList}},
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
		},
	},
	State_Observing: {
		Events: map[EventType]EventHandler{
			common.Event_HeartbeatReceived: {
				Validator: validator_IsHeartbeatSenderLive,
				Actions: []ActionRule{
					{Action: action_ResetHeartbeatIntervalsSinceLastReceive},
					{Action: action_UpdateActiveCoordinatorFromHeartbeat},
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
			common.Event_NewBlock: {
				Actions: []ActionRule{{Action: action_UpdateBlockHeight}},
			},
			common.Event_CoordinatorPriorityListUpdated: {
				Actions: []ActionRule{{Action: action_UpdateCoordinatorPriorityList}},
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
		},
	},
	State_Sending: {
		OnTransitionTo: []ActionRule{
			// Delegate immediately to the current active coordinator on entering Sending.
			// If the coordinator is still in Elect or Prepared it will accept the delegation
			// and manage the handover itself.
			{Action: action_SendDelegationRequest},
		},
		Events: map[EventType]EventHandler{
			Event_TransactionCreated: {
				Validator: validator_TransactionDoesNotExist,
				Actions: []ActionRule{
					{Action: action_TransactionCreated},
					{Action: action_SendDelegationRequest},
				},
			},
			common.Event_HeartbeatReceived: {
				Actions: []ActionRule{
					// 1. Process confirmed transactions from every heartbeat regardless of sender state or identity.
					{Action: action_ProcessConfirmedTransactions},
					// 2. Higher-priority coordinator announced; redirect and reset liveness timer.
					{
						Validator: statemachine.ValidatorAnd(
							validator_IsHeartbeatSenderLive,
							validator_IsSenderHigherPriorityThanCurrentCoordinator,
						),
						Action: action_SwitchActiveCoordinator,
					},
					// 3. Any live non-current node becomes coordinator when ours has gone silent.
					{
						Validator: statemachine.ValidatorAnd(
							validator_IsHeartbeatSenderLive,
							statemachine.ValidatorNot(validator_IsFromCurrentCoordinator),
						),
						If:     guard_InactiveGracePeriodExceeded,
						Action: action_SwitchActiveCoordinator,
					},
					// 4. Heartbeat from the (possibly just-elected) current coordinator:
					//    reset the liveness timer and process dispatched transactions.
					//    Steps 2/3 may have updated currentActiveCoordinator to the heartbeat
					//    sender, so this naturally fires for the same heartbeat in those cases.
					{
						Validator: validator_IsFromCurrentCoordinator,

						Action: action_ProcessCurrentCoordinatorHeartbeat,
					},
					// 5. Our coordinator has dropped transactions (or our new coordinator from the earlier action
					//    has never heard of our transactions); redelegate everything.
					//    No liveness check: a closing coordinator that drops transactions also
					//    needs to trigger a redelegate.
					{
						Validator: statemachine.ValidatorAnd(
							validator_IsFromCurrentCoordinator,
							validator_HasDroppedTransactions,
						),
						Action: action_SendDelegationRequest,
					},
				},
			},
			common.Event_HeartbeatInterval: {
				Actions: []ActionRule{
					{Action: action_IncrementHeartbeatIntervalCounts},
					// Nudge with a redelegate when the active coordinator has been silent too long
					// TODO: this is the point where we could consider failing over to a new coordinator
					// the current design results in noone coordinating if every sending originator agrees
					// that an unavailable node is the preferred active coordinator
					{
						If:     statemachine.GuardOr(guard_InactiveGracePeriodExceeded),
						Action: action_SendDelegationRequest,
					},
				},
			},
			Event_DelegationRejected: {
				Actions: []ActionRule{
					{Action: action_HandleDelegationRejected},
					// We always redelegate after a rejection, regardless of whether the current active coordinator has changed
					{Action: action_SendDelegationRequest},
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
			common.Event_NewBlock: {
				Actions: []ActionRule{{Action: action_UpdateBlockHeight}},
			},
			common.Event_CoordinatorPriorityListUpdated: {
				Actions: []ActionRule{{Action: action_UpdateCoordinatorPriorityList}},
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
