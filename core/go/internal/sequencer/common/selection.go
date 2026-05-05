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
	"strconv"

	"github.com/LFDT-Paladin/paladin/common/go/pkg/log"
)

// SelectCoordinatorNode deterministically selects the active coordinator node in
// COORDINATOR_ENDORSER mode. Both coordinator and originator call this function
// independently so they arrive at the same result without any inter-process notification.
//
// For COORDINATOR_STATIC and COORDINATOR_SENDER modes, activeCoordinatorNode is set once
// at construction/Start time and this function is never invoked.
//
// Parameters:
//   - coordinatorEndorserPool: the sorted, fixed set of endorser candidates
//   - currentBlockHeight: the current chain block height
//   - blockRange: the block range granularity for epoch calculation
func SelectCoordinatorNode(
	ctx context.Context,
	coordinatorEndorserPool []string,
	currentBlockHeight uint64,
	blockRange uint64,
) string {
	// Round block number down to the nearest block range (e.g. block 1012, 1013, 1014 etc. all become 1000 for hashing)
	effectiveBlockNumber := currentBlockHeight - (currentBlockHeight % blockRange)

	// Take a numeric hash of the effective block number
	h := fnv.New32a()
	h.Write([]byte(strconv.FormatUint(effectiveBlockNumber, 10)))
	selected := coordinatorEndorserPool[int(h.Sum32())%len(coordinatorEndorserPool)]
	log.L(ctx).Debugf("coordinator %s selected based on hash modulus of the endorser pool %+v", selected, coordinatorEndorserPool)
	return selected
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
