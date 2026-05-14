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
	"github.com/LFDT-Paladin/paladin/toolkit/pkg/prototk"
)

// action_CalculateCoordinatorPriorities recomputes the coordinator priority list for the current
// block height and epoch. It stores the result on the coordinator and pushes it to the co-located
// originator via the notifyOriginator callback.
func action_CalculateCoordinatorPriorities(ctx context.Context, c *coordinator, _ common.Event) error {
	if c.domainAPI.ContractConfig().GetCoordinatorSelection() != prototk.ContractConfig_COORDINATOR_ENDORSER {
		// For STATIC and SENDER modes, the coordinator is set once at Start time and never changes.
		return nil
	}
	c.coordinatorPriorityList = common.ComputeCoordinatorPriorityList(
		ctx,
		c.nodePool,
		c.currentBlockHeight,
		c.coordinatorSelectionBlockRange,
	)
	if len(c.coordinatorPriorityList) > 0 {
		c.currentActiveCoordinator = c.coordinatorPriorityList[0]
	}

	c.notifyOriginator(ctx, &common.CoordinatorPriorityListUpdatedEvent{
		Nodes: c.coordinatorPriorityList,
	})
	return nil
}

func action_UpdateBlockHeight(ctx context.Context, c *coordinator, event common.Event) error {
	c.currentBlockHeight, c.newBlockRangeEpoch = common.DecodeNewBlockHeight(c.currentBlockHeight, c.coordinatorSelectionBlockRange, event)
	c.grapher.CleanUpLocks(ctx, c.currentBlockHeight)
	return nil
}

func guard_IsNewBlockRangeEpoch(_ context.Context, c *coordinator) bool {
	// This is set when we update the block height, and remains valid until the next block height update
	return c.newBlockRangeEpoch
}
