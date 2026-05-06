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

func validator_IsHeartbeatFromActiveCoordinator(_ context.Context, c *coordinator, event common.Event) (bool, error) {
	e := event.(*common.HeartbeatReceivedEvent)
	return c.activeCoordinatorNode == e.From, nil
}

func validator_IsHeartbeatFromPreviousActiveCoordinator(_ context.Context, c *coordinator, event common.Event) (bool, error) {
	e := event.(*common.HeartbeatReceivedEvent)
	return c.previousActiveCoordinatorNode == e.From, nil
}

func action_HeartbeatReceived(_ context.Context, c *coordinator, event common.Event) error {
	e := event.(*common.HeartbeatReceivedEvent)
	c.activeCoordinatorState = e.CoordinatorSnapshot.CoordinatorState
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
