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

	"github.com/LFDT-Paladin/paladin/common/go/pkg/log"
	"github.com/LFDT-Paladin/paladin/core/internal/sequencer/common"
	"github.com/LFDT-Paladin/paladin/toolkit/pkg/prototk"
)

// action_CurrentActiveCoordinatorUnavailable sets current from the originator's newly selected active coordinator
// preferred coordinator does not change
// TODO AM: if we think we're the active coordinator, don't change it- just log a warning that orig and coord have diverged
func action_CurrentActiveCoordinatorUnavailable(ctx context.Context, c *coordinator, event common.Event) error {
	if c.domainAPI.ContractConfig().GetCoordinatorSelection() != prototk.ContractConfig_COORDINATOR_ENDORSER {
		return nil
	}
	if c.currentActiveCoordinator == c.nodeName {
		log.L(ctx).Warnf("Received an active coordinator unavailable event while in State_Active.")
		return nil
	}
	ev := event.(*ActiveCoordinatorUnavailableEvent)

	c.previousActiveCoordinatorNode = c.currentActiveCoordinator
	c.currentActiveCoordinator = ev.NewActiveCoordinator
	return nil
}

func action_SelectActiveCoordinator(ctx context.Context, c *coordinator, _ common.Event) error {
	if c.domainAPI.ContractConfig().GetCoordinatorSelection() != prototk.ContractConfig_COORDINATOR_ENDORSER {
		// For STATIC and SENDER modes, preferred/current coordinator are set once at Start time and never change.
		return nil
	}
	selectedPreferred, selectedCurrent := common.SelectCoordinatorNode(
		ctx,
		c.coordinatorEndorserPool,
		c.currentBlockHeight,
		c.coordinatorSelectionBlockRange,
		0,
	)
	c.previousActiveCoordinatorNode = c.currentActiveCoordinator
	c.preferredActiveCoordinator = selectedPreferred
	c.currentActiveCoordinator = selectedCurrent

	return nil
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
