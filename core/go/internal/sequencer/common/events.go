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

package common

import (
	"time"

	"github.com/LFDT-Paladin/paladin/sdk/go/pkg/pldtypes"
	"github.com/google/uuid"
)

type EventType int

// function that can be used to emit events from the internals of the sequencer to feed back into the state machine
type EmitEvent func(event Event)

const (
	Event_HeartbeatInterval          EventType = iota // emitted on a regular basis, interval defined by the sequencer config
	Event_TransactionStateTransition                  // transaction state machine transition; originator/coordinator handle cleanup and side effects
	Event_NewBlock                                    // a new block has been confirmed on the base ledger
	Event_HeartbeatReceived                           // a heartbeat notification was received from the active coordinator
	Event_CoordinatorPriorityListUpdated              // pushed by the coordinator to its co-located originator after recalculating the priority list
	Event_DelegationRejected                          // pushed by transport_client to the originator when a delegation acknowledgement indicates rejection
	Event_HandoverRequest                             // pushed by transport_client to the coordinator when a CoordinatorHandoverRequest message is received
)

type BaseEvent struct {
	EventTime time.Time
}

func (e *BaseEvent) GetEventTime() time.Time {
	return e.EventTime
}

type Event interface {
	Type() EventType
	TypeString() string
	GetEventTime() time.Time
}

type HeartbeatIntervalEvent struct {
	BaseEvent
}

func (*HeartbeatIntervalEvent) Type() EventType {
	return Event_HeartbeatInterval
}

func (*HeartbeatIntervalEvent) TypeString() string {
	return "Event_HeartbeatInterval"
}

// TransactionStateTransitionEvent is queued by a transaction state machine when it transitions state.
// S is the state type (comparable, typically int-based enum); each state machine uses its own State type parameter.
type TransactionStateTransitionEvent[S comparable] struct {
	BaseEvent
	TransactionID uuid.UUID
	From          S
	To            S
}

func (*TransactionStateTransitionEvent[S]) Type() EventType {
	return Event_TransactionStateTransition
}

func (*TransactionStateTransitionEvent[S]) TypeString() string {
	return "Event_TransactionStateTransition"
}

type NewBlockEvent struct {
	BaseEvent
	BlockHeight uint64
}

func (*NewBlockEvent) Type() EventType {
	return Event_NewBlock
}

func (*NewBlockEvent) TypeString() string {
	return "Event_NewBlock"
}

type HeartbeatReceivedEvent struct {
	BaseEvent
	From                string               `json:"from"`
	ContractAddress     *pldtypes.EthAddress `json:"contractAddress"`
	CoordinatorSnapshot *CoordinatorSnapshot `json:"coordinatorSnapshot"`
}

func (*HeartbeatReceivedEvent) Type() EventType {
	return Event_HeartbeatReceived
}

func (*HeartbeatReceivedEvent) TypeString() string {
	return "Event_HeartbeatReceived"
}

// CoordinatorPriorityListUpdatedEvent is queued by the coordinator to its co-located originator
// after action_CalculateCoordinatorPriorities runs. It carries the new priority-ordered list so
// the originator always has a consistent view of coordinator priority without computing it independently.
type CoordinatorPriorityListUpdatedEvent struct {
	BaseEvent
	Nodes []string
}

func (*CoordinatorPriorityListUpdatedEvent) Type() EventType {
	return Event_CoordinatorPriorityListUpdated
}

func (*CoordinatorPriorityListUpdatedEvent) TypeString() string {
	return "Event_CoordinatorPriorityListUpdated"
}

// DelegationRejectedEvent is queued by the transport client to the originator when a
// DelegationRequestAcknowledgment arrives with Accepted == false. It carries the name of the
// coordinator that the rejecting node believes is currently active so the originator can
// fast-redirect to a higher-priority coordinator.
type DelegationRejectedEvent struct {
	BaseEvent
	ActiveCoordinator string
}

func (*DelegationRejectedEvent) Type() EventType {
	return Event_DelegationRejected
}

func (*DelegationRejectedEvent) TypeString() string {
	return "Event_DelegationRejected"
}

// HandoverRequestEvent is queued by the transport client to the coordinator when a
// CoordinatorHandoverRequest message is received from a higher-priority node. The coordinator
// in Active state handles it identically to a preemption heartbeat.
type HandoverRequestEvent struct {
	BaseEvent
	FromNode string
}

func (*HandoverRequestEvent) Type() EventType {
	return Event_HandoverRequest
}

func (*HandoverRequestEvent) TypeString() string {
	return "Event_HandoverRequest"
}
