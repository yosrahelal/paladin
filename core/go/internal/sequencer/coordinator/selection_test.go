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
	"github.com/LFDT-Paladin/paladin/core/internal/sequencer/common"
	"github.com/LFDT-Paladin/paladin/toolkit/pkg/prototk"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
)

func Test_initializeActiveCoordinatorFromContractConfig_StaticMode_SetsActiveCoordinatorNode(t *testing.T) {
	ctx := context.Background()
	builder := NewCoordinatorBuilderForTesting(t, State_Idle)
	builder.GetDomainAPI().On("ContractConfig").Return(&prototk.ContractConfig{
		CoordinatorSelection: prototk.ContractConfig_COORDINATOR_STATIC,
		StaticCoordinator:    proto.String("identity@node1"),
	})
	c, _ := builder.Build()
	require.NoError(t, c.initializeFromContractConfig(ctx))

	assert.Equal(t, "node1", c.preferredActiveCoordinator)
}

func Test_action_SelectActiveCoordinator_SingleNodeInPool_ReturnsNode(t *testing.T) {
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
	require.NoError(t, c.initializeFromContractConfig(ctx))

	require.NoError(t, action_SelectActiveCoordinator(ctx, c, nil))
	assert.Equal(t, "node1", c.preferredActiveCoordinator)
}

func Test_action_SelectActiveCoordinator_MultipleNodesInPool_ReturnsOneOfPool(t *testing.T) {
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
	require.NoError(t, c.initializeFromContractConfig(ctx))

	require.NoError(t, action_SelectActiveCoordinator(ctx, c, nil))
	assert.Contains(t, []string{"node1", "node2", "node3"}, c.preferredActiveCoordinator)
}

func Test_action_SelectActiveCoordinator_BlockHeightRounding_SameRangeSameCoordinator(t *testing.T) {
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
	require.NoError(t, c.initializeFromContractConfig(ctx))

	require.NoError(t, action_UpdateBlockHeight(ctx, c, &common.NewBlockEvent{BlockHeight: 1000}))
	require.NoError(t, action_SelectActiveCoordinator(ctx, c, nil))
	coordinatorNode1 := c.preferredActiveCoordinator

	require.NoError(t, action_UpdateBlockHeight(ctx, c, &common.NewBlockEvent{BlockHeight: 1001}))
	require.NoError(t, action_SelectActiveCoordinator(ctx, c, nil))
	coordinatorNode2 := c.preferredActiveCoordinator

	require.NoError(t, action_UpdateBlockHeight(ctx, c, &common.NewBlockEvent{BlockHeight: 1099}))
	require.NoError(t, action_SelectActiveCoordinator(ctx, c, nil))
	coordinatorNode3 := c.preferredActiveCoordinator

	assert.Equal(t, coordinatorNode1, coordinatorNode2)
	assert.Equal(t, coordinatorNode2, coordinatorNode3)

	require.NoError(t, action_UpdateBlockHeight(ctx, c, &common.NewBlockEvent{BlockHeight: 1100}))
	require.NoError(t, action_SelectActiveCoordinator(ctx, c, nil))
	assert.Contains(t, []string{"node1", "node2", "node3"}, c.preferredActiveCoordinator)
}

func Test_action_ActiveCoordinatorUnavailable_SetsCurrentFromEvent(t *testing.T) {
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
	require.NoError(t, c.initializeFromContractConfig(ctx))

	require.NoError(t, action_SelectActiveCoordinator(ctx, c, nil))
	preferred := c.preferredActiveCoordinator
	require.Contains(t, []string{"node1", "node2", "node3"}, preferred)

	var other string
	for _, n := range []string{"node1", "node2", "node3"} {
		if n != preferred {
			other = n
			break
		}
	}
	require.NotEmpty(t, other)

	ev := &ActiveCoordinatorUnavailableEvent{
		BaseEvent:            common.BaseEvent{},
		NewActiveCoordinator: other,
	}
	require.NoError(t, action_CoordinatorUnavailable(ctx, c, ev))

	assert.Equal(t, preferred, c.preferredActiveCoordinator, "preferred stays hash-at-epoch (step zero)")
	assert.Equal(t, other, c.currentActiveCoordinator, "current follows originator delegation target")
}

func Test_action_SelectActiveCoordinator_DifferentBlockRanges_CanSelectDifferentCoordinators(t *testing.T) {
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
	require.NoError(t, c.initializeFromContractConfig(ctx))

	require.NoError(t, action_UpdateBlockHeight(ctx, c, &common.NewBlockEvent{BlockHeight: 100}))
	require.NoError(t, action_SelectActiveCoordinator(ctx, c, nil))
	coordinatorNode1 := c.preferredActiveCoordinator

	require.NoError(t, action_UpdateBlockHeight(ctx, c, &common.NewBlockEvent{BlockHeight: 150}))
	require.NoError(t, action_SelectActiveCoordinator(ctx, c, nil))
	coordinatorNode2 := c.preferredActiveCoordinator

	assert.Contains(t, []string{"node1", "node2"}, coordinatorNode1)
	assert.Contains(t, []string{"node1", "node2"}, coordinatorNode2)
}

func Test_initializeActiveCoordinatorFromContractConfig_SenderMode_SetsActiveCoordinatorToSelf(t *testing.T) {
	ctx := context.Background()
	builder := NewCoordinatorBuilderForTesting(t, State_Idle)
	builder.GetDomainAPI().On("ContractConfig").Return(&prototk.ContractConfig{
		CoordinatorSelection: prototk.ContractConfig_COORDINATOR_SENDER,
	})
	c, _ := builder.Build()

	require.NoError(t, c.initializeFromContractConfig(ctx))
	assert.Equal(t, "node1", c.preferredActiveCoordinator)
}

func Test_action_UpdateBlockHeight_SetsCurrentBlockHeight(t *testing.T) {
	ctx := context.Background()
	builder := NewCoordinatorBuilderForTesting(t, State_Idle)
	c, _ := builder.Build()

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
