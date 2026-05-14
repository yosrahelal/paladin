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

	"github.com/LFDT-Paladin/paladin/core/internal/sequencer/common"
	"github.com/LFDT-Paladin/paladin/core/internal/sequencer/coordinator/transaction"
)

// Guard type is defined as a type alias in state_machine.go using statemachine.Guard[*coordinator]

func guard_HasUnconfirmedDispatchedTransactions(ctx context.Context, c *coordinator) bool {
	return len(
		c.getTransactionsInStates(ctx, []transaction.State{
			transaction.State_Dispatched,
		}),
	) > 0
}

// Function noTransactionsInflight returns true if all transactions that have been delegated to this coordinator have been confirmed/reverted
// and since removed from memory
func guard_HasTransactionsInflight(_ context.Context, c *coordinator) bool {
	return len(c.transactionsByID) > 0
}

func guard_ClosingGracePeriodExpired(_ context.Context, c *coordinator) bool {
	return c.heartbeatIntervalsSinceStateChange >= c.closingGracePeriod
}

func guard_HasTransactionAssembling(ctx context.Context, c *coordinator) bool {
	//TODO this could be optimized by keeping track of a boolean that is switched from the onStateChange handler
	return len(
		c.getTransactionsInStates(ctx, []transaction.State{
			transaction.State_Assembling,
		}),
	) > 0
}

// guard_IsCurrentActiveCoordinator returns true when this node believes it is the current active
// coordinator (i.e. index 0 in the priority list, or set by static/sender mode).
func guard_IsCurrentActiveCoordinator(_ context.Context, c *coordinator) bool {
	return c.nodeName == c.currentActiveCoordinator
}

// guard_SigningIdentityUsed returns true if any transaction has retrieved the signing identity
// via the callback since the last key rotation. This determines whether a key rotation is needed
// on an epoch boundary.
func guard_SigningIdentityUsed(_ context.Context, c *coordinator) bool {
	return c.signingIdentityUsed
}

// guard_InactiveGracePeriodExceeded returns true when no heartbeat has been received for at least
// inactiveGracePeriod heartbeat intervals.
func guard_InactiveGracePeriodExceeded(_ context.Context, c *coordinator) bool {
	return c.heartbeatIntervalsSinceLastReceive >= c.inactiveGracePeriod
}

// guard_IsHigherPriorityThanCurrentActive returns true when this node has a strictly higher
// priority (lower index) than the current active coordinator in the coordinator priority list.
// Used in Observing and Closing when deciding whether to initiate a handover.
func guard_IsHigherPriorityThanCurrentActive(_ context.Context, c *coordinator) bool {
	return common.IsHigherPriority(c.coordinatorPriorityList, c.nodeName, c.currentActiveCoordinator)
}
