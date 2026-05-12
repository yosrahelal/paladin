/*
 * Copyright © 2026 Kaleido, Inc.
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

	"github.com/LFDT-Paladin/paladin/core/internal/sequencer/common"
)

func action_RejectDelegatedTransactions(ctx context.Context, c *coordinator, event common.Event) error {
	e := event.(*TransactionsDelegatedEvent)
	return c.transportWriter.SendDelegationRequestRejection(ctx, e.FromNode, e.DelegationID, c.currentBlockHeight)
}

// When we validate who heartbeats are from, we must always exclude heartbeats from ourselves

func validator_IsHeartbeatFromPreferredActiveCoordinator(_ context.Context, c *coordinator, event common.Event) (bool, error) {
	e := event.(*common.HeartbeatReceivedEvent)
	return c.nodeName != e.From && c.preferredActiveCoordinator == e.From &&
		e.CoordinatorSnapshot.CoordinatorState == common.CoordinatorState_Active, nil
}

func validator_IsHeartbeatFromCurrentActiveCoordinator(_ context.Context, c *coordinator, event common.Event) (bool, error) {
	e := event.(*common.HeartbeatReceivedEvent)
	return c.nodeName != e.From && c.currentActiveCoordinator == e.From, nil
}

func validator_IsHeartbeatFromPreviousActiveCoordinator(_ context.Context, c *coordinator, event common.Event) (bool, error) {
	e := event.(*common.HeartbeatReceivedEvent)
	return c.nodeName != e.From && c.previousActiveCoordinatorNode == e.From, nil
}

// validator_IsHeartbeatFromActiveWhenWeArePreferred returns true when we (the preferred coordinator)
// are in Idle state and receive a heartbeat from an Active fallback coordinator. This is the
// "awakening" trigger: the preferred coordinator should assert its role by entering Elect state.
func validator_IsHeartbeatFromActiveWhenWeArePreferred(_ context.Context, c *coordinator, event common.Event) (bool, error) {
	e := event.(*common.HeartbeatReceivedEvent)
	return c.nodeName != e.From &&
		c.nodeName == c.preferredActiveCoordinator &&
		e.CoordinatorSnapshot.CoordinatorState == common.CoordinatorState_Active, nil
}

func action_HeartbeatReceived(_ context.Context, c *coordinator, event common.Event) error {
	e := event.(*common.HeartbeatReceivedEvent)
	c.activeCoordinatorState = e.CoordinatorSnapshot.CoordinatorState
	// is this a
	if c.currentActiveCoordinator != c.preferredActiveCoordinator &&
		c.activeCoordinatorState == common.CoordinatorState_Active &&
		e.From == c.preferredActiveCoordinator {
		c.previousActiveCoordinatorNode = c.currentActiveCoordinator
		c.currentActiveCoordinator = c.preferredActiveCoordinator
	}
	return nil
}

func action_ResetHeartbeatIntervalsSinceLastReceive(_ context.Context, c *coordinator, _ common.Event) error {
	c.heartbeatIntervalsSinceLastReceive = 0
	return nil
}

func action_IncrementHeartbeatIntervalCounts(_ context.Context, c *coordinator, _ common.Event) error {
	c.heartbeatIntervalsSinceLastReceive++
	c.heartbeatIntervalsSinceStateChange++
	return nil
}

func guard_InactiveGracePeriodExceeded(_ context.Context, c *coordinator) bool {
	return c.heartbeatIntervalsSinceLastReceive >= c.inactiveGracePeriod
}
