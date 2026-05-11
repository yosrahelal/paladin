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
// (adjacent after sort). Use this when building the endorser pool so hash-modulus selection and
// failover offsets see one slot per coordinator node.
func DedupeSortedCoordinatorEndorserNodes(nodes []string) []string {
	if len(nodes) == 0 {
		return nodes
	}
	slices.Sort(nodes)
	return slices.Compact(nodes)
}

// SelectCoordinatorNode returns the preferred coordinator for this height/range and the current
// delegation target for the given failoverOffset. The offset is applied on the sorted deduped pool
// ring: current slot is (preferredIndex + failoverOffset) mod len(pool). Callers reset the offset
// to 0 on a new epoch and increment it (e.g. on unavailability); they do not need to normalize.
// Originators and coordinators each keep their own failoverOffset; both use this function with the
// same pool and height inputs so preferred identity agrees, unavailability-driven offsets should
// stay consistent as they are driven by the same heartbeats across both types.
//
// For COORDINATOR_STATIC and COORDINATOR_SENDER modes, preferred/current coordinator fields are
// set once at construction/Start time and this function is never invoked.
func SelectCoordinatorNode(
	ctx context.Context,
	coordinatorEndorserPool []string,
	currentBlockHeight uint64,
	blockRange uint64,
	failoverOffset int,
) (preferred, current string) {
	n := len(coordinatorEndorserPool)
	if n == 0 {
		return "", ""
	}
	if n == 1 {
		return coordinatorEndorserPool[0], coordinatorEndorserPool[0]
	}
	effectiveBlockNumber := currentBlockHeight - (currentBlockHeight % blockRange)

	// Take a numeric hash of the effective block number
	h := fnv.New32a()
	h.Write([]byte(strconv.FormatUint(effectiveBlockNumber, 10)))
	p := int(h.Sum32()) % n
	preferred = coordinatorEndorserPool[p]
	s := (p + failoverOffset) % n
	if s < 0 {
		s += n
	}
	current = coordinatorEndorserPool[s]
	log.L(ctx).Debugf("endorser coordinator preferred %q current %q (failoverOffset=%d preferredIndex=%d pool %+v)", preferred, current, failoverOffset, p, coordinatorEndorserPool)
	return preferred, current
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
