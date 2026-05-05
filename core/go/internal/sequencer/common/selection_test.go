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

package common

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_SelectCoordinatorNode_EndorserMode_SingleNode_ReturnsThatNode(t *testing.T) {
	ctx := context.Background()
	result := SelectCoordinatorNode(ctx, []string{"node1"}, 1000, 100)
	assert.Equal(t, "node1", result)
}

func Test_SelectCoordinatorNode_EndorserMode_MultipleNodes_ReturnsNodeFromPool(t *testing.T) {
	ctx := context.Background()
	pool := []string{"node1", "node2", "node3"}
	result := SelectCoordinatorNode(ctx, pool, 1000, 100)
	assert.Contains(t, pool, result)
}

func Test_SelectCoordinatorNode_EndorserMode_SameBlockRange_ReturnsSameNode(t *testing.T) {
	ctx := context.Background()
	pool := []string{"node1", "node2", "node3"}
	blockRange := uint64(100)

	node1 := SelectCoordinatorNode(ctx, pool, 1000, blockRange)
	node2 := SelectCoordinatorNode(ctx, pool, 1050, blockRange)
	node3 := SelectCoordinatorNode(ctx, pool, 1099, blockRange)

	assert.Equal(t, node1, node2, "same block range epoch should select same coordinator")
	assert.Equal(t, node2, node3, "same block range epoch should select same coordinator")
}

func Test_SelectCoordinatorNode_EndorserMode_DifferentBlockRanges_CanSelectDifferentNodes(t *testing.T) {
	ctx := context.Background()
	// Use a 2-node pool to guarantee different selection is possible
	pool := []string{"node1", "node2"}
	blockRange := uint64(50)

	n1 := SelectCoordinatorNode(ctx, pool, 100, blockRange)
	n2 := SelectCoordinatorNode(ctx, pool, 150, blockRange)

	assert.Contains(t, pool, n1)
	assert.Contains(t, pool, n2)
}

func Test_SelectCoordinatorNode_EndorserMode_CoordinatorAndOriginatorAgree(t *testing.T) {
	ctx := context.Background()
	pool := []string{"node1", "node2", "node3"}
	blockRange := uint64(100)
	blockHeight := uint64(1000)

	// Both coordinator-side and originator-side call the same function with the same inputs;
	// the result must be identical regardless of nodeName (which is not a parameter anymore).
	fromCoordinator := SelectCoordinatorNode(ctx, pool, blockHeight, blockRange)
	fromOriginator := SelectCoordinatorNode(ctx, pool, blockHeight, blockRange)

	assert.Equal(t, fromCoordinator, fromOriginator, "coordinator and originator must agree on the active coordinator")
}

func Test_DecodeNewBlockHeight_NewEpoch(t *testing.T) {
	event := &NewBlockEvent{BlockHeight: 100}
	newHeight, newEpoch := DecodeNewBlockHeight(0, 100, event)
	require.Equal(t, uint64(100), newHeight)
	assert.True(t, newEpoch)
}

func Test_DecodeNewBlockHeight_SameEpoch(t *testing.T) {
	event := &NewBlockEvent{BlockHeight: 50}
	newHeight, newEpoch := DecodeNewBlockHeight(0, 100, event)
	require.Equal(t, uint64(50), newHeight)
	assert.False(t, newEpoch)
}

func Test_DecodeNewBlockHeight_SameEpochMidRange(t *testing.T) {
	event := &NewBlockEvent{BlockHeight: 1099}
	newHeight, newEpoch := DecodeNewBlockHeight(1000, 100, event)
	require.Equal(t, uint64(1099), newHeight)
	assert.False(t, newEpoch)
}
