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

	"github.com/LFDT-Paladin/paladin/config/pkg/confutil"
	"github.com/LFDT-Paladin/paladin/toolkit/pkg/prototk"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
)

func Test_action_SelectActiveCoordinator_StaticMode_ReturnsStoredNode(t *testing.T) {
	ctx := context.Background()
	builder := NewCoordinatorBuilderForTesting(t, State_Idle)
	builder.GetDomainAPI().On("ContractConfig").Return(&prototk.ContractConfig{
		CoordinatorSelection: prototk.ContractConfig_COORDINATOR_STATIC,
		StaticCoordinator:    proto.String("identity@node1"),
	})
	c, _ := builder.Build()
	require.NoError(t, c.initializeStaticCoordinatorFromContractConfig(ctx))

	require.NoError(t, action_SelectActiveCoordinator(ctx, c, nil))
	assert.Equal(t, "node1", c.activeCoordinatorNode)
}

func Test_action_SelectActiveCoordinator_EndorserMode_SingleNodeInPool_ReturnsNode(t *testing.T) {
	ctx := context.Background()
	builder := NewCoordinatorBuilderForTesting(t, State_Idle)
	builder.GetDomainAPI().On("ContractConfig").Return(&prototk.ContractConfig{
		CoordinatorSelection:          prototk.ContractConfig_COORDINATOR_ENDORSER,
		CoordinatorEndorserCandidates: []string{"id@node1"},
	})
	config := builder.GetSequencerConfig()
	config.BlockRange = confutil.P(uint64(100))
	builder.OverrideSequencerConfig(config)
	c, _ := builder.CurrentBlockHeight(1000).Build()
	require.NoError(t, c.initializeOriginatorNodePoolFromContractConfig(ctx))

	require.NoError(t, action_SelectActiveCoordinator(ctx, c, nil))
	assert.Equal(t, "node1", c.activeCoordinatorNode)
}

func Test_action_SelectActiveCoordinator_EndorserMode_MultipleNodesInPool_ReturnsOneOfPool(t *testing.T) {
	ctx := context.Background()
	builder := NewCoordinatorBuilderForTesting(t, State_Idle)
	builder.GetDomainAPI().On("ContractConfig").Return(&prototk.ContractConfig{
		CoordinatorSelection:          prototk.ContractConfig_COORDINATOR_ENDORSER,
		CoordinatorEndorserCandidates: []string{"id@node1", "id@node2", "id@node3"},
	})
	config := builder.GetSequencerConfig()
	config.BlockRange = confutil.P(uint64(100))
	builder.OverrideSequencerConfig(config)
	c, _ := builder.CurrentBlockHeight(1000).Build()
	require.NoError(t, c.initializeOriginatorNodePoolFromContractConfig(ctx))

	require.NoError(t, action_SelectActiveCoordinator(ctx, c, nil))
	assert.Contains(t, []string{"node1", "node2", "node3"}, c.activeCoordinatorNode)
}

func Test_action_SelectActiveCoordinator_EndorserMode_BlockHeightRounding_SameRangeSameCoordinator(t *testing.T) {
	ctx := context.Background()
	builder := NewCoordinatorBuilderForTesting(t, State_Idle)
	builder.GetDomainAPI().On("ContractConfig").Return(&prototk.ContractConfig{
		CoordinatorSelection:          prototk.ContractConfig_COORDINATOR_ENDORSER,
		CoordinatorEndorserCandidates: []string{"id@node1", "id@node2", "id@node3"},
	})
	config := builder.GetSequencerConfig()
	config.BlockRange = confutil.P(uint64(100))
	builder.OverrideSequencerConfig(config)
	c, _ := builder.Build()
	require.NoError(t, c.initializeOriginatorNodePoolFromContractConfig(ctx))

	require.NoError(t, action_UpdateBlockHeight(ctx, c, &NewBlockEvent{BlockHeight: 1000}))
	require.NoError(t, action_SelectActiveCoordinator(ctx, c, nil))
	coordinatorNode1 := c.activeCoordinatorNode

	require.NoError(t, action_UpdateBlockHeight(ctx, c, &NewBlockEvent{BlockHeight: 1001}))
	require.NoError(t, action_SelectActiveCoordinator(ctx, c, nil))
	coordinatorNode2 := c.activeCoordinatorNode

	require.NoError(t, action_UpdateBlockHeight(ctx, c, &NewBlockEvent{BlockHeight: 1099}))
	require.NoError(t, action_SelectActiveCoordinator(ctx, c, nil))
	coordinatorNode3 := c.activeCoordinatorNode

	assert.Equal(t, coordinatorNode1, coordinatorNode2)
	assert.Equal(t, coordinatorNode2, coordinatorNode3)

	require.NoError(t, action_UpdateBlockHeight(ctx, c, &NewBlockEvent{BlockHeight: 1100}))
	require.NoError(t, action_SelectActiveCoordinator(ctx, c, nil))
	assert.Contains(t, []string{"node1", "node2", "node3"}, c.activeCoordinatorNode)
}

func Test_action_SelectActiveCoordinator_EndorserMode_DifferentBlockRanges_CanSelectDifferentCoordinators(t *testing.T) {
	ctx := context.Background()
	builder := NewCoordinatorBuilderForTesting(t, State_Idle)
	builder.GetDomainAPI().On("ContractConfig").Return(&prototk.ContractConfig{
		CoordinatorSelection:          prototk.ContractConfig_COORDINATOR_ENDORSER,
		CoordinatorEndorserCandidates: []string{"id@node1", "id@node2"},
	})
	config := builder.GetSequencerConfig()
	config.BlockRange = confutil.P(uint64(50))
	builder.OverrideSequencerConfig(config)
	c, _ := builder.Build()
	require.NoError(t, c.initializeOriginatorNodePoolFromContractConfig(ctx))

	require.NoError(t, action_UpdateBlockHeight(ctx, c, &NewBlockEvent{BlockHeight: 100}))
	require.NoError(t, action_SelectActiveCoordinator(ctx, c, nil))
	coordinatorNode1 := c.activeCoordinatorNode

	require.NoError(t, action_UpdateBlockHeight(ctx, c, &NewBlockEvent{BlockHeight: 150}))
	require.NoError(t, action_SelectActiveCoordinator(ctx, c, nil))
	coordinatorNode2 := c.activeCoordinatorNode

	assert.Contains(t, []string{"node1", "node2"}, coordinatorNode1)
	assert.Contains(t, []string{"node1", "node2"}, coordinatorNode2)
}

func Test_action_SelectActiveCoordinator_SenderMode_ReturnsCurrentNodeName(t *testing.T) {
	ctx := context.Background()
	builder := NewCoordinatorBuilderForTesting(t, State_Idle)
	builder.GetDomainAPI().On("ContractConfig").Return(&prototk.ContractConfig{
		CoordinatorSelection: prototk.ContractConfig_COORDINATOR_SENDER,
	})
	c, _ := builder.Build()

	require.NoError(t, action_SelectActiveCoordinator(ctx, c, nil))
	assert.Equal(t, "node1", c.activeCoordinatorNode)
}

func Test_updateOriginatorNodePool_AddsNodeToEmptyPool(t *testing.T) {
	builder := NewCoordinatorBuilderForTesting(t, State_Idle)
	c, _ := builder.OriginatorNodePool().Build()

	c.updateOriginatorNodePool("node2")

	assert.Equal(t, 2, len(c.originatorNodePool), "pool should contain 2 nodes")
	assert.Contains(t, c.originatorNodePool, "node2", "pool should contain node2")
	assert.Contains(t, c.originatorNodePool, "node1", "pool should contain coordinator's own node")
}

func Test_updateOriginatorNodePool_AddsNodeToNonEmptyPool(t *testing.T) {
	builder := NewCoordinatorBuilderForTesting(t, State_Idle)
	c, _ := builder.OriginatorNodePool("node1", "node3").Build()

	c.updateOriginatorNodePool("node2")

	assert.Equal(t, 3, len(c.originatorNodePool), "pool should contain 3 nodes")
	assert.Contains(t, c.originatorNodePool, "node1", "pool should contain node1")
	assert.Contains(t, c.originatorNodePool, "node2", "pool should contain node2")
	assert.Contains(t, c.originatorNodePool, "node3", "pool should contain node3")
}

func Test_updateOriginatorNodePool_DoesNotAddDuplicateNode(t *testing.T) {
	builder := NewCoordinatorBuilderForTesting(t, State_Idle)
	c, _ := builder.OriginatorNodePool("node1", "node2").Build()

	c.updateOriginatorNodePool("node2")

	assert.Equal(t, 2, len(c.originatorNodePool), "pool should still contain 2 nodes")
	assert.Contains(t, c.originatorNodePool, "node1", "pool should contain node1")
	assert.Contains(t, c.originatorNodePool, "node2", "pool should contain node2")
}

func Test_updateOriginatorNodePool_EnsuresCoordinatorsOwnNodeIsAlwaysInPool(t *testing.T) {
	builder := NewCoordinatorBuilderForTesting(t, State_Idle)
	c, _ := builder.OriginatorNodePool().Build()

	c.updateOriginatorNodePool("node2")

	assert.Contains(t, c.originatorNodePool, "node1", "pool should contain coordinator's own node")
	assert.Equal(t, 2, len(c.originatorNodePool), "pool should contain 2 nodes")
}

func Test_updateOriginatorNodePool_EnsuresCoordinatorsOwnNodeIsAddedEvenWhenPoolAlreadyHasOtherNodes(t *testing.T) {
	builder := NewCoordinatorBuilderForTesting(t, State_Idle)
	c, _ := builder.OriginatorNodePool("node2", "node3").Build()

	c.updateOriginatorNodePool("node4")

	assert.Contains(t, c.originatorNodePool, "node1", "pool should contain coordinator's own node")
	assert.Equal(t, 4, len(c.originatorNodePool), "pool should contain 4 nodes")
}

func Test_updateOriginatorNodePool_DoesNotDuplicateCoordinatorsOwnNode(t *testing.T) {
	builder := NewCoordinatorBuilderForTesting(t, State_Idle)
	c, _ := builder.OriginatorNodePool("node1", "node2").Build()

	c.updateOriginatorNodePool("node1")

	assert.Equal(t, 2, len(c.originatorNodePool), "pool should still contain 2 nodes")
	assert.Contains(t, c.originatorNodePool, "node1", "pool should contain node1")
	assert.Contains(t, c.originatorNodePool, "node2", "pool should contain node2")
}

func Test_updateOriginatorNodePool_HandlesMultipleSequentialUpdates(t *testing.T) {
	builder := NewCoordinatorBuilderForTesting(t, State_Idle)
	c, _ := builder.OriginatorNodePool().Build()

	c.updateOriginatorNodePool("node2")
	c.updateOriginatorNodePool("node3")
	c.updateOriginatorNodePool("node4")

	assert.Equal(t, 4, len(c.originatorNodePool), "pool should contain 4 nodes")
	assert.Contains(t, c.originatorNodePool, "node1", "pool should contain node1")
	assert.Contains(t, c.originatorNodePool, "node2", "pool should contain node2")
	assert.Contains(t, c.originatorNodePool, "node3", "pool should contain node3")
	assert.Contains(t, c.originatorNodePool, "node4", "pool should contain node4")
}

func Test_updateOriginatorNodePool_HandlesEmptyStringNode(t *testing.T) {
	builder := NewCoordinatorBuilderForTesting(t, State_Idle)
	c, _ := builder.OriginatorNodePool().Build()

	c.updateOriginatorNodePool("")

	assert.Equal(t, 2, len(c.originatorNodePool), "pool should contain 2 nodes")
	assert.Contains(t, c.originatorNodePool, "", "pool should contain empty string")
	assert.Contains(t, c.originatorNodePool, "node1", "pool should contain coordinator's own node")
}

func Test_action_UpdateBlockHeight_SetsCurrentBlockHeight(t *testing.T) {
	ctx := context.Background()
	builder := NewCoordinatorBuilderForTesting(t, State_Idle)
	c, _ := builder.Build()

	err := action_UpdateBlockHeight(ctx, c, &NewBlockEvent{BlockHeight: 1000})
	require.NoError(t, err)
	assert.Equal(t, uint64(1000), c.currentBlockHeight)
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
