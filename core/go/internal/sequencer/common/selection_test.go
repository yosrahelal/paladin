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
	"slices"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// preferredCoordinatorPoolIndexViaSelect returns the pool index of preferred at failoverOffset 0 for tests only.
func preferredCoordinatorPoolIndexViaSelect(ctx context.Context, pool []string, currentBlockHeight, blockRange uint64) int {
	pref, _ := SelectCoordinatorNode(ctx, pool, currentBlockHeight, blockRange, 0)
	return slices.Index(pool, pref)
}

func TestDedupeSortedCoordinatorEndorserNodes_RemovesDuplicatesAndSorts(t *testing.T) {
	in := []string{"b", "a", "b", "a", "c"}
	got := DedupeSortedCoordinatorEndorserNodes(append([]string(nil), in...))
	assert.Equal(t, []string{"a", "b", "c"}, got)
}

func Test_SelectCoordinatorNode_EndorserMode_SingleNode_ReturnsThatNode(t *testing.T) {
	ctx := context.Background()
	preferred, current := SelectCoordinatorNode(ctx, []string{"node1"}, 1000, 100, 0)
	assert.Equal(t, "node1", preferred)
	assert.Equal(t, "node1", current)
}

func Test_SelectCoordinatorNode_EndorserMode_MultipleNodes_ReturnsNodeFromPool(t *testing.T) {
	ctx := context.Background()
	pool := []string{"node1", "node2", "node3"}
	p := preferredCoordinatorPoolIndexViaSelect(ctx, pool, 1000, 100)
	preferred, current := SelectCoordinatorNode(ctx, pool, 1000, 100, 0)
	assert.Contains(t, pool, preferred)
	assert.Equal(t, preferred, current)
	assert.Equal(t, pool[p], preferred)
}

func Test_SelectCoordinatorNode_EndorserMode_SameBlockRange_ReturnsSameNode(t *testing.T) {
	ctx := context.Background()
	pool := []string{"node1", "node2", "node3"}
	blockRange := uint64(100)

	pr1, c1 := SelectCoordinatorNode(ctx, pool, 1000, blockRange, 0)
	pr2, c2 := SelectCoordinatorNode(ctx, pool, 1050, blockRange, 0)
	pr3, c3 := SelectCoordinatorNode(ctx, pool, 1099, blockRange, 0)

	assert.Equal(t, pr1, pr2, "same block range epoch should select same coordinator")
	assert.Equal(t, pr2, pr3, "same block range epoch should select same coordinator")
	assert.Equal(t, pr1, c1)
	assert.Equal(t, pr2, c2)
	assert.Equal(t, pr3, c3)
}

func Test_SelectCoordinatorNode_EndorserMode_DifferentBlockRanges_CanSelectDifferentNodes(t *testing.T) {
	ctx := context.Background()
	pool := []string{"node1", "node2"}
	blockRange := uint64(50)

	n1p, n1c := SelectCoordinatorNode(ctx, pool, 100, blockRange, 0)
	n2p, n2c := SelectCoordinatorNode(ctx, pool, 150, blockRange, 0)

	assert.Contains(t, pool, n1p)
	assert.Contains(t, pool, n2p)
	assert.Equal(t, n1p, n1c)
	assert.Equal(t, n2p, n2c)
}

func Test_SelectCoordinatorNode_EndorserMode_CoordinatorAndOriginatorAgree(t *testing.T) {
	ctx := context.Background()
	pool := []string{"node1", "node2", "node3"}
	blockRange := uint64(100)
	blockHeight := uint64(1000)

	fromCoordinatorP, fromCoordinatorC := SelectCoordinatorNode(ctx, pool, blockHeight, blockRange, 0)
	fromOriginatorP, fromOriginatorC := SelectCoordinatorNode(ctx, pool, blockHeight, blockRange, 0)

	assert.Equal(t, fromCoordinatorP, fromOriginatorP, "coordinator and originator must agree on preferred")
	assert.Equal(t, fromCoordinatorC, fromOriginatorC, "coordinator and originator must agree on current for the same pool, height, range, and failover offset")
}

func TestSelectCoordinatorNode_WhenBlockHeightIsExactEpochBoundary_UsesThatBoundaryForSelection(t *testing.T) {
	ctx := context.Background()
	pool := []string{"a-node", "b-node", "m-node", "z-node"}
	blockRange := uint64(100)
	atBoundaryP, atBoundaryC := SelectCoordinatorNode(ctx, pool, 1000, blockRange, 0)
	atEndP, atEndC := SelectCoordinatorNode(ctx, pool, 1099, blockRange, 0)
	assert.Equal(t, atBoundaryP, atEndP)
	assert.Equal(t, atBoundaryC, atEndC)
}

func TestSelectCoordinatorNode_WhenPoolOrderIsLexicographic_HashIndexIsStableForFixedInputs(t *testing.T) {
	ctx := context.Background()
	pool := []string{"a", "b", "c", "d", "e"}
	blockRange := uint64(50)
	firstP, firstC := SelectCoordinatorNode(ctx, pool, 75, blockRange, 0)
	secondP, secondC := SelectCoordinatorNode(ctx, pool, 75, blockRange, 0)
	assert.Equal(t, firstP, secondP)
	assert.Equal(t, firstC, secondC)
	assert.Contains(t, pool, firstP)
}

func heightWithPreferredIndex(t *testing.T, pool []string, blockRange uint64, wantIdx int) uint64 {
	t.Helper()
	ctx := context.Background()
	for h := blockRange; h < blockRange*5000; h++ {
		if preferredCoordinatorPoolIndexViaSelect(ctx, pool, h, blockRange) == wantIdx {
			return h
		}
	}
	t.Fatalf("no height in scan range gives preferred index %d for pool %v", wantIdx, pool)
	return 0
}

func TestSelectCoordinatorNode_WhenFailoverOffsetAdvances_SelectsNextMemberInLexOrder(t *testing.T) {
	ctx := context.Background()
	pool := []string{"a", "b", "c", "d", "e"}
	blockRange := uint64(100)
	h := heightWithPreferredIndex(t, pool, blockRange, 2)
	p := preferredCoordinatorPoolIndexViaSelect(ctx, pool, h, blockRange)
	require.Equal(t, 2, p)
	require.Equal(t, "c", pool[p])

	_, cur0 := SelectCoordinatorNode(ctx, pool, h, blockRange, 0)
	assert.Equal(t, "c", cur0)
	_, cur1 := SelectCoordinatorNode(ctx, pool, h, blockRange, 1)
	assert.Equal(t, "d", cur1)
	_, cur2 := SelectCoordinatorNode(ctx, pool, h, blockRange, 2)
	assert.Equal(t, "e", cur2)
	_, cur3 := SelectCoordinatorNode(ctx, pool, h, blockRange, 3)
	assert.Equal(t, "a", cur3)
	_, cur4 := SelectCoordinatorNode(ctx, pool, h, blockRange, 4)
	assert.Equal(t, "b", cur4)

	pr, _ := SelectCoordinatorNode(ctx, pool, h, blockRange, 4)
	assert.Equal(t, "c", pr)
}

func TestSelectCoordinatorNode_WhenFailoverIncrements_WalksRing(t *testing.T) {
	pool := []string{"a", "b", "c", "d", "e"}
	blockRange := uint64(100)
	h := heightWithPreferredIndex(t, pool, blockRange, 2)
	off := 0
	for _, want := range []string{"c", "d", "e", "a", "b", "c"} {
		_, cur := SelectCoordinatorNode(context.Background(), pool, h, blockRange, off)
		assert.Equal(t, want, cur)
		off++
	}
}

func TestSelectCoordinatorNode_WhenFailoverOffsetLarge_ModulosInsideSelection(t *testing.T) {
	ctx := context.Background()
	pool := []string{"a", "b", "c", "d", "e"}
	blockRange := uint64(100)
	h := heightWithPreferredIndex(t, pool, blockRange, 2)
	_, curSmall := SelectCoordinatorNode(ctx, pool, h, blockRange, 2)
	_, curLarge := SelectCoordinatorNode(ctx, pool, h, blockRange, 2+5*100)
	assert.Equal(t, curSmall, curLarge)
}

func TestSelectCoordinatorNode_WhenFailoverOffsetWraps_ModuloRing(t *testing.T) {
	ctx := context.Background()
	pool := []string{"a", "b", "c"}
	blockRange := uint64(100)
	h := heightWithPreferredIndex(t, pool, blockRange, 2)
	p := preferredCoordinatorPoolIndexViaSelect(ctx, pool, h, blockRange)
	require.Equal(t, 2, p)
	_, c0 := SelectCoordinatorNode(ctx, pool, h, blockRange, 0)
	require.Equal(t, "c", c0)
	_, c1 := SelectCoordinatorNode(ctx, pool, h, blockRange, 1)
	assert.Equal(t, "a", c1)
	_, c2 := SelectCoordinatorNode(ctx, pool, h, blockRange, 2)
	assert.Equal(t, "b", c2)
	_, c3 := SelectCoordinatorNode(ctx, pool, h, blockRange, 3)
	assert.Equal(t, "c", c3)
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
