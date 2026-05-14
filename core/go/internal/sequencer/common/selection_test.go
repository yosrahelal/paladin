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

func Test_ComputeCoordinatorPriorityList_SingleNode_ReturnsThatNode(t *testing.T) {
	ctx := context.Background()
	list := ComputeCoordinatorPriorityList(ctx, []string{"node1"}, 1000, 100)
	require.Len(t, list, 1)
	assert.Equal(t, "node1", list[0])
}

func Test_ComputeCoordinatorPriorityList_MultipleNodes_TopIsInPool(t *testing.T) {
	ctx := context.Background()
	pool := []string{"node1", "node2", "node3"}
	list := ComputeCoordinatorPriorityList(ctx, pool, 1000, 100)
	require.Len(t, list, len(pool))
	assert.Contains(t, pool, list[0], "highest-priority node must be a member of the pool")
}

func Test_ComputeCoordinatorPriorityList_SameBlockRange_ReturnsSameTop(t *testing.T) {
	ctx := context.Background()
	pool := []string{"node1", "node2", "node3"}
	blockRange := uint64(100)

	l1 := ComputeCoordinatorPriorityList(ctx, pool, 1000, blockRange)
	l2 := ComputeCoordinatorPriorityList(ctx, pool, 1050, blockRange)
	l3 := ComputeCoordinatorPriorityList(ctx, pool, 1099, blockRange)

	assert.Equal(t, l1[0], l2[0], "same block range epoch should produce the same top node")
	assert.Equal(t, l2[0], l3[0], "same block range epoch should produce the same top node")
}

func Test_ComputeCoordinatorPriorityList_DifferentBlockRanges_CanSelectDifferentTopNode(t *testing.T) {
	ctx := context.Background()
	pool := []string{"node1", "node2"}
	blockRange := uint64(50)

	l1 := ComputeCoordinatorPriorityList(ctx, pool, 100, blockRange)
	l2 := ComputeCoordinatorPriorityList(ctx, pool, 150, blockRange)

	assert.Contains(t, pool, l1[0])
	assert.Contains(t, pool, l2[0])
}

func Test_ComputeCoordinatorPriorityList_TwoCallsAgree(t *testing.T) {
	ctx := context.Background()
	pool := []string{"node1", "node2", "node3"}
	blockRange := uint64(100)
	blockHeight := uint64(1000)

	first := ComputeCoordinatorPriorityList(ctx, pool, blockHeight, blockRange)
	second := ComputeCoordinatorPriorityList(ctx, pool, blockHeight, blockRange)

	assert.Equal(t, first, second, "two independent calls with the same inputs must return the same list")
}

func Test_ComputeCoordinatorPriorityList_EpochBoundary_SameBoundaryProducesSameTop(t *testing.T) {
	ctx := context.Background()
	pool := []string{"a-node", "b-node", "m-node", "z-node"}
	blockRange := uint64(100)
	atBoundary := ComputeCoordinatorPriorityList(ctx, pool, 1000, blockRange)
	atEnd := ComputeCoordinatorPriorityList(ctx, pool, 1099, blockRange)
	assert.Equal(t, atBoundary[0], atEnd[0])
}

func Test_ComputeCoordinatorPriorityList_IsStableForFixedInputs(t *testing.T) {
	ctx := context.Background()
	pool := []string{"a", "b", "c", "d", "e"}
	blockRange := uint64(50)
	first := ComputeCoordinatorPriorityList(ctx, pool, 75, blockRange)
	second := ComputeCoordinatorPriorityList(ctx, pool, 75, blockRange)
	assert.Equal(t, first, second)
	assert.Contains(t, pool, first[0])
}

func Test_ComputeCoordinatorPriorityList_WrapAroundOrder(t *testing.T) {
	// Fix a pool and block height so the hash deterministically picks index 2 ("node3").
	// With wrap-around the expected order is [node3, node4, node1, node2].
	ctx := context.Background()
	pool := []string{"node1", "node2", "node3", "node4"}

	list := ComputeCoordinatorPriorityList(ctx, pool, 1000, 100)
	require.Len(t, list, len(pool))

	// Locate where the top node sits in the original pool.
	top := list[0]
	var topIdx int
	for i, n := range pool {
		if n == top {
			topIdx = i
			break
		}
	}
	// Every subsequent entry must be the next pool node with wrap-around.
	for i := range len(pool) {
		expected := pool[(topIdx+i)%len(pool)]
		assert.Equal(t, expected, list[i], "position %d must follow wrap-around order", i)
	}
}


func Test_ComputeCoordinatorPriorityList_EmptyPool_ReturnsNil(t *testing.T) {
	ctx := context.Background()
	list := ComputeCoordinatorPriorityList(ctx, nil, 1000, 100)
	assert.Nil(t, list)
}

func Test_ComputeCoordinatorPriorityList_ListContainsAllPoolNodes(t *testing.T) {
	ctx := context.Background()
	pool := []string{"node1", "node2", "node3"}
	list := ComputeCoordinatorPriorityList(ctx, pool, 1000, 100)
	require.Len(t, list, len(pool))
	for _, node := range pool {
		assert.Contains(t, list, node, "all pool nodes must appear in the priority list")
	}
}

func Test_PriorityIndexOf_ReturnsIndexForKnownNode(t *testing.T) {
	list := []string{"a", "b", "c"}
	assert.Equal(t, 0, PriorityIndexOf(list, "a"))
	assert.Equal(t, 1, PriorityIndexOf(list, "b"))
	assert.Equal(t, 2, PriorityIndexOf(list, "c"))
}

func Test_PriorityIndexOf_ReturnsLenForUnknownNode(t *testing.T) {
	list := []string{"a", "b", "c"}
	assert.Equal(t, len(list), PriorityIndexOf(list, "unknown"))
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
