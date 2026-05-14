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
	"hash/fnv"
	"slices"
	"strconv"

	"github.com/LFDT-Paladin/paladin/common/go/pkg/log"
)

// DedupeSortedCoordinatorEndorserNodes sorts node names in place and removes duplicate entries
// (adjacent after sort). Use this when building the endorser pool so hash-modulus selection
// sees one slot per coordinator node.
func DedupeSortedCoordinatorEndorserNodes(nodes []string) []string {
	if len(nodes) == 0 {
		return nodes
	}
	slices.Sort(nodes)
	return slices.Compact(nodes)
}

// ComputeCoordinatorPriorityList returns a priority-ordered list of coordinator nodes for the
// given block height and range. The node at index 0 is the highest-priority (currently selected)
// coordinator; remaining nodes follow in sorted order. All nodes that call this function with the
// same pool and block height will independently reach the same result.
//
// For COORDINATOR_STATIC and COORDINATOR_SENDER modes, the coordinator field is set once at
// construction/Start time and this function is never invoked.
func ComputeCoordinatorPriorityList(
	ctx context.Context,
	nodePool []string,
	currentBlockHeight uint64,
	blockRange uint64,
) []string {
	n := len(nodePool)
	if n == 0 {
		return nil
	}
	if n == 1 {
		return []string{nodePool[0]}
	}
	effectiveBlockNumber := currentBlockHeight - (currentBlockHeight % blockRange)

	// Take a numeric hash of the effective block number
	h := fnv.New32a()
	h.Write([]byte(strconv.FormatUint(effectiveBlockNumber, 10)))
	p := int(h.Sum32()) % n
	selected := nodePool[p]
	log.L(ctx).Debugf("coordinator priority list: selected index %d (%q) from pool %+v", p, selected, nodePool)

	// Build priority list: walk the sorted pool starting at the selected index,
	// wrapping around so the ordering is e.g. [3,4,1,2] when p=2 and n=4.
	list := make([]string, n)
	for i := range n {
		list[i] = nodePool[(p+i)%n]
	}
	return list
}

// PriorityIndexOf returns the index of node in the priority list, or len(list) if absent.
// A lower index means higher priority (index 0 is the current active coordinator).
func PriorityIndexOf(list []string, node string) int {
	for i, n := range list {
		if n == node {
			return i
		}
	}
	return len(list)
}

func IsHigherPriority(list []string, node1 string, node2 string) bool {
	idx1 := PriorityIndexOf(list, node1)
	idx2 := PriorityIndexOf(list, node2)
	return idx1 < idx2
}

// DecodeNewBlockHeight extracts the new block height from a NewBlockEvent and determines
// whether we have entered a new block range epoch. Both coordinator and originator use this
// to update their block height state consistently.
func DecodeNewBlockHeight(currentBlockHeight uint64, blockRange uint64, event Event) (uint64, bool) {
	e := event.(*NewBlockEvent)
	newHeight := e.BlockHeight
	newBlockRangeEpoch := newHeight/blockRange != currentBlockHeight/blockRange
	return newHeight, newBlockRangeEpoch
}
