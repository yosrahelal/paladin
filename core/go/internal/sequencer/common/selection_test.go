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

func TestDedupeSortedCoordinatorEndorserNodes_RemovesDuplicatesAndSorts(t *testing.T) {
	in := []string{"b", "a", "b", "a", "c"}
	got := DedupeSortedCoordinatorEndorserNodes(append([]string(nil), in...))
	assert.Equal(t, []string{"a", "b", "c"}, got)
}

func Test_SelectCoordinatorNode_EndorserMode_SingleNode_ReturnsThatNode(t *testing.T) {
	ctx := context.Background()
	selected := SelectCoordinatorNode(ctx, []string{"node1"}, 1000, 100)
	assert.Equal(t, "node1", selected)
}

func Test_SelectCoordinatorNode_EndorserMode_MultipleNodes_ReturnsNodeFromPool(t *testing.T) {
	ctx := context.Background()
	pool := []string{"node1", "node2", "node3"}
	selected := SelectCoordinatorNode(ctx, pool, 1000, 100)
	assert.Contains(t, pool, selected)
}

func Test_SelectCoordinatorNode_EndorserMode_SameBlockRange_ReturnsSameNode(t *testing.T) {
	ctx := context.Background()
	pool := []string{"node1", "node2", "node3"}
	blockRange := uint64(100)

	c1 := SelectCoordinatorNode(ctx, pool, 1000, blockRange)
	c2 := SelectCoordinatorNode(ctx, pool, 1050, blockRange)
	c3 := SelectCoordinatorNode(ctx, pool, 1099, blockRange)

	assert.Equal(t, c1, c2, "same block range epoch should select same coordinator")
	assert.Equal(t, c2, c3, "same block range epoch should select same coordinator")
}

func Test_SelectCoordinatorNode_EndorserMode_DifferentBlockRanges_CanSelectDifferentNodes(t *testing.T) {
	ctx := context.Background()
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

	fromCoordinator := SelectCoordinatorNode(ctx, pool, blockHeight, blockRange)
	fromOriginator := SelectCoordinatorNode(ctx, pool, blockHeight, blockRange)

	assert.Equal(t, fromCoordinator, fromOriginator, "coordinator and originator must agree on the same pool, height, and range")
}

func TestSelectCoordinatorNode_WhenBlockHeightIsExactEpochBoundary_UsesThatBoundaryForSelection(t *testing.T) {
	ctx := context.Background()
	pool := []string{"a-node", "b-node", "m-node", "z-node"}
	blockRange := uint64(100)
	atBoundary := SelectCoordinatorNode(ctx, pool, 1000, blockRange)
	atEnd := SelectCoordinatorNode(ctx, pool, 1099, blockRange)
	assert.Equal(t, atBoundary, atEnd)
}

func TestSelectCoordinatorNode_WhenPoolOrderIsLexicographic_HashIndexIsStableForFixedInputs(t *testing.T) {
	ctx := context.Background()
	pool := []string{"a", "b", "c", "d", "e"}
	blockRange := uint64(50)
	first := SelectCoordinatorNode(ctx, pool, 75, blockRange)
	second := SelectCoordinatorNode(ctx, pool, 75, blockRange)
	assert.Equal(t, first, second)
	assert.Contains(t, pool, first)
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
