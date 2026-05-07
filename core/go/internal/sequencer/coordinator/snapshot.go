/*
 * Copyright © 2025 Kaleido, Inc.
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

	"github.com/LFDT-Paladin/paladin/common/go/pkg/log"
	"github.com/LFDT-Paladin/paladin/core/internal/sequencer/common"
	"github.com/LFDT-Paladin/paladin/sdk/go/pkg/pldtypes"
)

func action_SendHeartbeat(ctx context.Context, c *coordinator, _ common.Event) error {
	return c.sendHeartbeat(ctx, c.contractAddress)
}

// sendHeartbeat builds the base snapshot once, then sends a per-node copy to each node in the
// originator pool. In Flush/Closing states, the grapher is queried per-node: each node receives
// all locks (unfiltered) plus only the OutputStates it is permitted to hold (filtered by AllowedNodes).
func (c *coordinator) sendHeartbeat(ctx context.Context, contractAddress *pldtypes.EthAddress) error {
	base := c.getSnapshot(ctx)
	includeLocks := base.CoordinatorState == common.CoordinatorState_Flush || base.CoordinatorState == common.CoordinatorState_Closing
	log.L(ctx).Debugf("sending heartbeats for sequencer %s (includeLocks=%v)", contractAddress.String(), includeLocks)
	var err error
	for _, node := range c.originatorNodePool {
		log.L(ctx).Debugf("sending heartbeat to %s", node)
		snapshot := base
		if includeLocks {
			statesAndLocks, exportErr := c.grapher.ExportStatesAndLocks(ctx, node)
			if exportErr != nil {
				log.L(ctx).Errorf("error exporting states and locks for node %s: %v", node, exportErr)
				err = exportErr
				continue
			}
			snapshot = &common.CoordinatorSnapshot{
				DispatchedTransactions: base.DispatchedTransactions,
				PooledTransactions:     base.PooledTransactions,
				ConfirmedTransactions:  base.ConfirmedTransactions,
				CoordinatorState:       base.CoordinatorState,
				BlockHeight:            base.BlockHeight,
				Locks:                  statesAndLocks.LockedState,
				OutputStates:           statesAndLocks.OutputState,
			}
		}
		if sendErr := c.transportWriter.SendHeartbeat(ctx, node, contractAddress, snapshot); sendErr != nil {
			log.L(ctx).Errorf("error sending heartbeat to %s: %v", node, sendErr)
			err = sendErr
		}
	}
	return err
}

// getSnapshot builds the coordinator snapshot (without per-node lock data).
// Locks are attached per-node in sendHeartbeat for Flush/Closing heartbeats.
func (c *coordinator) getSnapshot(ctx context.Context) *common.CoordinatorSnapshot {
	log.L(ctx).Debugf("creating snapshot for sequencer %s", c.contractAddress.String())
	pooledTransactions := make([]*common.SnapshotPooledTransaction, 0, len(c.transactionsByID))
	dispatchedTransactions := make([]*common.SnapshotDispatchedTransaction, 0, len(c.transactionsByID))
	confirmedTransactions := make([]*common.SnapshotConfirmedTransaction, 0, len(c.transactionsByID))

	for _, txn := range c.transactionsByID {
		pooledTransaction, dispatchedTransaction, confirmedTransaction := txn.GetSnapshot(ctx)
		if pooledTransaction != nil {
			pooledTransactions = append(pooledTransactions, pooledTransaction)
		}
		if dispatchedTransaction != nil {
			dispatchedTransactions = append(dispatchedTransactions, dispatchedTransaction)
		}
		if confirmedTransaction != nil {
			confirmedTransactions = append(confirmedTransactions, confirmedTransaction)
		}
	}

	coordinatorState := c.stateMachineEventLoop.GetCurrentState()
	log.L(ctx).Debugf("created snapshot for sequencer %s with %d transactions (%d pooled, %d dispatched, %d confirmed)",
		c.contractAddress.String(), len(pooledTransactions)+len(dispatchedTransactions)+len(confirmedTransactions),
		len(pooledTransactions), len(dispatchedTransactions), len(confirmedTransactions))

	return &common.CoordinatorSnapshot{
		DispatchedTransactions: dispatchedTransactions,
		PooledTransactions:     pooledTransactions,
		ConfirmedTransactions:  confirmedTransactions,
		CoordinatorState:       coordinatorState,
		BlockHeight:            c.currentBlockHeight,
	}
}

func action_IncrementHeartbeatIntervalsSinceStateChange(ctx context.Context, c *coordinator, event common.Event) error {
	c.heartbeatIntervalsSinceStateChange++
	return nil
}

func action_PropagateHeartbeatIntervalToTransactions(ctx context.Context, c *coordinator, _ common.Event) error {
	return c.propagateEventToAllTransactions(ctx, &common.HeartbeatIntervalEvent{})
}
