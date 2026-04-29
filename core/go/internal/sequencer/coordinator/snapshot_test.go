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
	"fmt"
	"testing"

	"github.com/LFDT-Paladin/paladin/core/internal/sequencer/coordinator/transaction"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

func TestGetSnapshot_OK(t *testing.T) {
	ctx := context.Background()
	c, _ := NewCoordinatorBuilderForTesting(t, State_Idle).Build()
	snapshot := c.getSnapshot(ctx)
	assert.NotNil(t, snapshot)
}

func TestGetSnapshot_AggregatesTransactionsBySnapshotType(t *testing.T) {
	ctx := context.Background()
	pooledTxn, _ := transaction.NewTransactionBuilderForTesting(t, transaction.State_Pooled).Build()
	dispatchedTxn, _ := transaction.NewTransactionBuilderForTesting(t, transaction.State_Dispatched).Build()
	confirmedTxn, _ := transaction.NewTransactionBuilderForTesting(t, transaction.State_Confirmed).Build()
	excludedTxn, _ := transaction.NewTransactionBuilderForTesting(t, transaction.State_Reverted).Build()
	c, _ := NewCoordinatorBuilderForTesting(t, State_Idle).
		Transactions(pooledTxn, dispatchedTxn, confirmedTxn, excludedTxn).
		Build()

	snapshot := c.getSnapshot(ctx)
	require.NotNil(t, snapshot)
	assert.Len(t, snapshot.PooledTransactions, 1)
	assert.Len(t, snapshot.DispatchedTransactions, 1)
	assert.Len(t, snapshot.ConfirmedTransactions, 1)
	assert.Equal(t, pooledTxn.GetID(), snapshot.PooledTransactions[0].ID)
	assert.Equal(t, dispatchedTxn.GetID(), snapshot.DispatchedTransactions[0].ID)
	assert.Equal(t, confirmedTxn.GetID(), snapshot.ConfirmedTransactions[0].ID)
}

func TestGetSnapshot_IncludesCoordinatorStateAndBlockHeight(t *testing.T) {
	ctx := context.Background()
	blockHeight := uint64(12345)
	c, _ := NewCoordinatorBuilderForTesting(t, State_Idle).CurrentBlockHeight(blockHeight).Build()

	snapshot := c.getSnapshot(ctx)
	require.NotNil(t, snapshot)
	assert.Equal(t, c.GetCurrentState(), State(snapshot.CoordinatorState))
	assert.Equal(t, blockHeight, snapshot.BlockHeight)
}

func TestSendHeartbeat_Success(t *testing.T) {
	ctx := context.Background()
	c, mocks := NewCoordinatorBuilderForTesting(t, State_Idle).
		OriginatorNodePool("node1", "node2", "node3").
		Build()

	err := c.sendHeartbeat(ctx, c.contractAddress)
	assert.NoError(t, err)
	assert.True(t, mocks.SentMessageRecorder.HasSentHeartbeat())
}

func TestSendHeartbeat_SkipsCurrentNode(t *testing.T) {
	ctx := context.Background()
	c, mocks := NewCoordinatorBuilderForTesting(t, State_Idle).
		OriginatorNodePool("node1").
		Build()

	err := c.sendHeartbeat(ctx, c.contractAddress)
	assert.NoError(t, err)
	// Should not send heartbeat since only node1 is in pool and it's the current node
	assert.False(t, mocks.SentMessageRecorder.HasSentHeartbeat())
}

func TestSendHeartbeat_HandlesError(t *testing.T) {
	ctx := context.Background()
	c, mocks := NewCoordinatorBuilderForTesting(t, State_Idle).
		OriginatorNodePool("node1", "node2").
		WithMockTransportWriter().
		Build()
	mocks.TransportWriter.EXPECT().SendHeartbeat(mock.Anything, "node2", mock.Anything, mock.Anything).
		Return(fmt.Errorf("transport error"))

	err := c.sendHeartbeat(ctx, c.contractAddress)
	// Should return the error but continue processing
	assert.Error(t, err)
	assert.Equal(t, "transport error", err.Error())
}

func TestAction_SendHeartbeat(t *testing.T) {
	ctx := context.Background()
	c, mocks := NewCoordinatorBuilderForTesting(t, State_Idle).
		OriginatorNodePool("node1", "node2").
		Build()

	err := action_SendHeartbeat(ctx, c, nil)
	assert.NoError(t, err)
	assert.True(t, mocks.SentMessageRecorder.HasSentHeartbeat())
}

func Test_action_IncrementHeartbeatIntervalsSinceStateChange(t *testing.T) {
	ctx := context.Background()
	c, _ := NewCoordinatorBuilderForTesting(t, State_Idle).HeartbeatIntervalsSinceStateChange(2).Build()

	err := action_IncrementHeartbeatIntervalsSinceStateChange(ctx, c, nil)
	require.NoError(t, err)
	assert.Equal(t, 3, c.heartbeatIntervalsSinceStateChange)
}

func Test_action_PropagateHeartbeatToTransactions_NoTransactions(t *testing.T) {
	ctx := context.Background()
	c, _ := NewCoordinatorBuilderForTesting(t, State_Idle).Build()

	err := action_PropagateHeartbeatIntervalToTransactions(ctx, c, nil)
	require.NoError(t, err)
}

func Test_action_PropagateHeartbeatToTransactions_WithTransactions(t *testing.T) {
	ctx := context.Background()
	txn, _ := transaction.NewTransactionBuilderForTesting(t, transaction.State_Pooled).Build()
	c, _ := NewCoordinatorBuilderForTesting(t, State_Idle).Transactions(txn).Build()

	err := action_PropagateHeartbeatIntervalToTransactions(ctx, c, nil)
	require.NoError(t, err)
}
