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
	"slices"

	"github.com/LFDT-Paladin/paladin/core/internal/sequencer/common"
	"github.com/LFDT-Paladin/paladin/toolkit/pkg/prototk"
)

func action_SelectActiveCoordinator(ctx context.Context, c *coordinator, _ common.Event) error {
	if c.domainAPI.ContractConfig().GetCoordinatorSelection() != prototk.ContractConfig_COORDINATOR_ENDORSER {
		// For STATIC and SENDER modes, activeCoordinatorNode is set once at Start time and never changes.
		return nil
	}
	selected := common.SelectCoordinatorNode(
		ctx,
		c.coordinatorEndorserPool,
		c.currentBlockHeight,
		c.coordinatorSelectionBlockRange,
	)
	if c.activeCoordinatorNode != selected {
		c.previousActiveCoordinatorNode = c.activeCoordinatorNode
		c.activeCoordinatorNode = selected
	}
	return nil
}

// TODO AM: not sure this lives in here- or that the function above needs a separate file now
func (c *coordinator) updateOriginatorNodePool(originatorNode string) {
	// In COORDINATOR_ENDORSER mode the pool is fixed at initialisation from the contract config
	// (all valid endorser candidates are already known), so dynamic updates are skipped.
	if c.domainAPI.ContractConfig().GetCoordinatorSelection() == prototk.ContractConfig_COORDINATOR_ENDORSER {
		return
	}
	if !slices.Contains(c.originatorNodePool, originatorNode) {
		c.originatorNodePool = append(c.originatorNodePool, originatorNode)
	}
	if !slices.Contains(c.originatorNodePool, c.nodeName) {
		// As coordinator we should always be in the pool as it's used to select the next coordinator when necessary
		c.originatorNodePool = append(c.originatorNodePool, c.nodeName)
	}
	slices.Sort(c.originatorNodePool)
}

func action_UpdateBlockHeight(_ context.Context, c *coordinator, event common.Event) error {
	c.currentBlockHeight, c.newBlockRangeEpoch = common.DecodeNewBlockHeight(c.currentBlockHeight, c.coordinatorSelectionBlockRange, event)
	return nil
}

func action_ExpireGrapherLocks(ctx context.Context, c *coordinator, _ common.Event) error {
	c.grapher.CleanUpLocks(ctx, c.currentBlockHeight)
	return nil
}

func guard_IsNewBlockRangeEpoch(_ context.Context, c *coordinator) bool {
	// This is set when we update the block height, and remains valid until the next block height update
	return c.newBlockRangeEpoch
}
