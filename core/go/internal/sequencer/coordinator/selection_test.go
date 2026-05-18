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
	"testing"

	"github.com/LFDT-Paladin/paladin/core/internal/sequencer/common"
	"github.com/LFDT-Paladin/paladin/toolkit/pkg/prototk"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_action_CalculateCoordinatorPriorities_SingleNodeInPool_ReturnsNode(t *testing.T) {
	ctx := context.Background()
	c, _ := NewCoordinatorBuilderForTesting(t, State_Idle).
		NodePool("node1").
		CoordinatorSelectionBlockRange(100).
		CurrentBlockHeight(1000).
		CoordinatorSelectionMode(prototk.ContractConfig_COORDINATOR_ENDORSER).
		Build()

	require.NoError(t, action_CalculateCoordinatorPriorities(ctx, c, nil))
	assert.Equal(t, "node1", c.currentActiveCoordinator)
}

func Test_action_CalculateCoordinatorPriorities_MultipleNodesInPool_ReturnsOneOfPool(t *testing.T) {
	ctx := context.Background()
	c, _ := NewCoordinatorBuilderForTesting(t, State_Idle).
		NodePool("node1", "node2", "node3").
		CoordinatorSelectionBlockRange(100).
		CurrentBlockHeight(1000).
		CoordinatorSelectionMode(prototk.ContractConfig_COORDINATOR_ENDORSER).
		Build()

	require.NoError(t, action_CalculateCoordinatorPriorities(ctx, c, nil))
	assert.Contains(t, []string{"node1", "node2", "node3"}, c.currentActiveCoordinator)
}

func Test_action_CalculateCoordinatorPriorities_BlockHeightRounding_SameRangeSameCoordinator(t *testing.T) {
	ctx := context.Background()
	c, _ := NewCoordinatorBuilderForTesting(t, State_Idle).
		NodePool("node1", "node2", "node3").
		CoordinatorSelectionBlockRange(100).
		CoordinatorSelectionMode(prototk.ContractConfig_COORDINATOR_ENDORSER).
		Build()

	require.NoError(t, action_UpdateBlockHeight(ctx, c, &common.NewBlockEvent{BlockHeight: 1000}))
	require.NoError(t, action_CalculateCoordinatorPriorities(ctx, c, nil))
	coordinatorNode1 := c.currentActiveCoordinator

	require.NoError(t, action_UpdateBlockHeight(ctx, c, &common.NewBlockEvent{BlockHeight: 1001}))
	require.NoError(t, action_CalculateCoordinatorPriorities(ctx, c, nil))
	coordinatorNode2 := c.currentActiveCoordinator

	require.NoError(t, action_UpdateBlockHeight(ctx, c, &common.NewBlockEvent{BlockHeight: 1099}))
	require.NoError(t, action_CalculateCoordinatorPriorities(ctx, c, nil))
	coordinatorNode3 := c.currentActiveCoordinator

	assert.Equal(t, coordinatorNode1, coordinatorNode2)
	assert.Equal(t, coordinatorNode2, coordinatorNode3)

	require.NoError(t, action_UpdateBlockHeight(ctx, c, &common.NewBlockEvent{BlockHeight: 1100}))
	require.NoError(t, action_CalculateCoordinatorPriorities(ctx, c, nil))
	assert.Contains(t, []string{"node1", "node2", "node3"}, c.currentActiveCoordinator)
}

func Test_action_CalculateCoordinatorPriorities_DifferentBlockRanges_CanSelectDifferentCoordinators(t *testing.T) {
	ctx := context.Background()
	c, _ := NewCoordinatorBuilderForTesting(t, State_Idle).
		NodePool("node1", "node2").
		CoordinatorSelectionBlockRange(50).
		CoordinatorSelectionMode(prototk.ContractConfig_COORDINATOR_ENDORSER).
		Build()

	require.NoError(t, action_UpdateBlockHeight(ctx, c, &common.NewBlockEvent{BlockHeight: 100}))
	require.NoError(t, action_CalculateCoordinatorPriorities(ctx, c, nil))
	coordinatorNode1 := c.currentActiveCoordinator

	require.NoError(t, action_UpdateBlockHeight(ctx, c, &common.NewBlockEvent{BlockHeight: 150}))
	require.NoError(t, action_CalculateCoordinatorPriorities(ctx, c, nil))
	coordinatorNode2 := c.currentActiveCoordinator

	assert.Contains(t, []string{"node1", "node2"}, coordinatorNode1)
	assert.Contains(t, []string{"node1", "node2"}, coordinatorNode2)
}

func Test_action_CalculateCoordinatorPriorities_SenderMode_NoOp(t *testing.T) {
	ctx := context.Background()
	// In SENDER mode the coordinatorSelection field is COORDINATOR_SENDER, so
	// action_CalculateCoordinatorPriorities should be a no-op and leave currentActiveCoordinator
	// unchanged.
	c, _ := NewCoordinatorBuilderForTesting(t, State_Idle).
		CurrentActiveCoordinator("node1").
		Build()
	// Default builder uses SENDER mode; currentActiveCoordinator is pre-set above.

	require.NoError(t, action_CalculateCoordinatorPriorities(ctx, c, nil))
	assert.Equal(t, "node1", c.currentActiveCoordinator)
}

func Test_action_UpdateBlockHeight_SetsCurrentBlockHeight(t *testing.T) {
	ctx := context.Background()
	c, _ := NewCoordinatorBuilderForTesting(t, State_Idle).Build()

	err := action_UpdateBlockHeight(ctx, c, &common.NewBlockEvent{BlockHeight: 1000})
	require.NoError(t, err)
	assert.Equal(t, uint64(1000), c.currentBlockHeight)
}

func Test_action_UpdateBlockHeight_NewEpoch_SetsNewBlockRangeEpochTrue(t *testing.T) {
	ctx := context.Background()
	c, _ := NewCoordinatorBuilderForTesting(t, State_Idle).Build()
	c.coordinatorSelectionBlockRange = 10
	c.currentBlockHeight = 9

	err := action_UpdateBlockHeight(ctx, c, &common.NewBlockEvent{BlockHeight: 10})
	require.NoError(t, err)
	assert.True(t, c.newBlockRangeEpoch, "crossing a block range boundary should set newBlockRangeEpoch=true")
}

func Test_action_UpdateBlockHeight_SameEpoch_SetsNewBlockRangeEpochFalse(t *testing.T) {
	ctx := context.Background()
	c, _ := NewCoordinatorBuilderForTesting(t, State_Idle).Build()
	c.coordinatorSelectionBlockRange = 10
	c.currentBlockHeight = 0

	err := action_UpdateBlockHeight(ctx, c, &common.NewBlockEvent{BlockHeight: 1})
	require.NoError(t, err)
	assert.False(t, c.newBlockRangeEpoch, "staying within the same block range should set newBlockRangeEpoch=false")
}

func Test_guard_IsNewBlockRangeEpoch_WhenNewEpoch_ReturnsTrue(t *testing.T) {
	ctx := context.Background()
	c, _ := NewCoordinatorBuilderForTesting(t, State_Idle).Build()
	c.newBlockRangeEpoch = true
	assert.True(t, guard_IsNewBlockRangeEpoch(ctx, c))
}

func Test_guard_IsNewBlockRangeEpoch_WhenSameEpoch_ReturnsFalse(t *testing.T) {
	ctx := context.Background()
	c, _ := NewCoordinatorBuilderForTesting(t, State_Idle).Build()
	c.newBlockRangeEpoch = false
	assert.False(t, guard_IsNewBlockRangeEpoch(ctx, c))
}
