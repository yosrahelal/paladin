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
	"hash/fnv"
	"slices"
	"strconv"

	"github.com/LFDT-Paladin/paladin/common/go/pkg/log"
	"github.com/LFDT-Paladin/paladin/core/internal/sequencer/common"
	"github.com/LFDT-Paladin/paladin/toolkit/pkg/prototk"
)

func action_SelectActiveCoordinator(ctx context.Context, c *coordinator, _ common.Event) error {
	c.activeCoordinatorNode = c.selectActiveCoordinatorNode(ctx)
	return nil
}

func (c *coordinator) selectActiveCoordinatorNode(ctx context.Context) string {
	var coordinatorNode string
	switch c.domainAPI.ContractConfig().GetCoordinatorSelection() {
	case prototk.ContractConfig_COORDINATOR_STATIC:
		// Validated and stored at construction time; return directly.
		coordinatorNode = c.staticCoordinatorNode
		log.L(ctx).Debugf("coordinator %s selected as next active coordinator in static coordinator mode", coordinatorNode)
	case prototk.ContractConfig_COORDINATOR_ENDORSER:
		// Round block number down to the nearest block range (e.g. block 1012, 1013, 1014 etc. all become 1000 for hashing)
		effectiveBlockNumber := c.currentBlockHeight - (c.currentBlockHeight % c.coordinatorSelectionBlockRange)

		// Take a numeric hash of the identities using the current block range
		h := fnv.New32a()
		h.Write([]byte(strconv.FormatUint(effectiveBlockNumber, 10)))
		// the originatorNodePool for coordinator endorser mode is built and validated at construction time
		coordinatorNode = c.originatorNodePool[int(h.Sum32())%len(c.originatorNodePool)]
		log.L(ctx).Debugf("coordinator %s selected based on hash modulus of the originator pool %+v", coordinatorNode, c.originatorNodePool)
	case prototk.ContractConfig_COORDINATOR_SENDER:
		coordinatorNode = c.nodeName
		log.L(ctx).Debugf("coordinator %s selected as next active coordinator in sender coordinator mode", coordinatorNode)
	}

	log.L(ctx).Debugf("selected active coordinator for contract %s: %s", c.contractAddress.String(), coordinatorNode)
	return coordinatorNode
}

func (c *coordinator) updateOriginatorNodePool(originatorNode string) {
	if !slices.Contains(c.originatorNodePool, originatorNode) {
		c.originatorNodePool = append(c.originatorNodePool, originatorNode)
	}
	if !slices.Contains(c.originatorNodePool, c.nodeName) {
		// As coordinator we should always be in the pool as it's used to select the next coordinator when necessary
		c.originatorNodePool = append(c.originatorNodePool, c.nodeName)
	}
	slices.Sort(c.originatorNodePool)
}

func action_UpdateBlockHeight(ctx context.Context, c *coordinator, event common.Event) error {
	e := event.(*NewBlockEvent)
	newHeight := e.BlockHeight
	blockRange := c.coordinatorSelectionBlockRange

	// integer division tells us which block range epoch we're in and allows us to compare old with new
	c.newBlockRangeEpoch = newHeight/blockRange == c.currentBlockHeight/blockRange
	c.currentBlockHeight = newHeight
	return nil
}

func guard_IsNewBlockRangeEpoch(_ context.Context, c *coordinator) bool {
	// This is set when we update the block height, and remains valid until the next block height update
	return c.newBlockRangeEpoch
}
