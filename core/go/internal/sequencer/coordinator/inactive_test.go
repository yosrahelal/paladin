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
	"fmt"
	"testing"

	"github.com/LFDT-Paladin/paladin/core/internal/sequencer/common"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_action_HeartbeatReceived_SetsActiveCoordinatorState(t *testing.T) {
	ctx := context.Background()
	builder := NewCoordinatorBuilderForTesting(t, State_Observing)
	c, _ := builder.Build()
	event := &common.HeartbeatReceivedEvent{}
	event.From = "node1"
	event.CoordinatorSnapshot = &common.CoordinatorSnapshot{
		CoordinatorState: State_Active,
	}

	err := action_HeartbeatReceived(ctx, c, event)
	require.NoError(t, err)
	assert.Equal(t, State_Active, c.activeCoordinatorState)
}

func Test_action_ResetHeartbeatIntervalsSinceLastReceive(t *testing.T) {
	ctx := context.Background()
	c, _ := NewCoordinatorBuilderForTesting(t, State_Observing).HeartbeatIntervalsSinceLastReceive(7).Build()

	err := action_ResetHeartbeatIntervalsSinceLastReceive(ctx, c, nil)
	require.NoError(t, err)
	assert.Equal(t, 0, c.heartbeatIntervalsSinceLastReceive)
}

func Test_action_IncrementHeartbeatIntervalCounts(t *testing.T) {
	ctx := context.Background()
	c, _ := NewCoordinatorBuilderForTesting(t, State_Observing).
		HeartbeatIntervalsSinceLastReceive(3).
		HeartbeatIntervalsSinceStateChange(2).
		Build()

	err := action_IncrementHeartbeatIntervalCounts(ctx, c, nil)
	require.NoError(t, err)
	assert.Equal(t, 4, c.heartbeatIntervalsSinceLastReceive)
	assert.Equal(t, 3, c.heartbeatIntervalsSinceStateChange)
}

func Test_guard_InactiveGracePeriodExceeded_NotExceeded(t *testing.T) {
	ctx := context.Background()
	c, _ := NewCoordinatorBuilderForTesting(t, State_Observing).
		InactiveGracePeriod(10).HeartbeatIntervalsSinceLastReceive(5).Build()

	assert.False(t, guard_InactiveGracePeriodExceeded(ctx, c))
}

func Test_guard_InactiveGracePeriodExceeded_ExactlyMet(t *testing.T) {
	ctx := context.Background()
	c, _ := NewCoordinatorBuilderForTesting(t, State_Observing).
		InactiveGracePeriod(10).HeartbeatIntervalsSinceLastReceive(10).Build()

	assert.True(t, guard_InactiveGracePeriodExceeded(ctx, c))
}

func Test_guard_InactiveGracePeriodExceeded_Exceeded(t *testing.T) {
	ctx := context.Background()
	c, _ := NewCoordinatorBuilderForTesting(t, State_Observing).
		InactiveGracePeriod(10).HeartbeatIntervalsSinceLastReceive(15).Build()

	assert.True(t, guard_InactiveGracePeriodExceeded(ctx, c))
}

func Test_action_RejectDelegatedTransactions_Success(t *testing.T) {
	ctx := context.Background()
	c, mocks := NewCoordinatorBuilderForTesting(t, State_Idle).WithMockTransportWriter().Build()

	delegationID := "del-123"
	fromNode := "remoteNode"
	mocks.TransportWriter.EXPECT().SendDelegationRequestRejection(ctx, fromNode, delegationID, c.currentBlockHeight).Return(nil)

	event := &TransactionsDelegatedEvent{
		FromNode:     fromNode,
		DelegationID: delegationID,
	}
	err := action_RejectDelegatedTransactions(ctx, c, event)
	require.NoError(t, err)
}

func Test_action_RejectDelegatedTransactions_PropagatesError(t *testing.T) {
	ctx := context.Background()
	c, mocks := NewCoordinatorBuilderForTesting(t, State_Idle).WithMockTransportWriter().Build()

	delegationID := "del-456"
	fromNode := "remoteNode"
	expectedErr := fmt.Errorf("transport error")
	mocks.TransportWriter.EXPECT().SendDelegationRequestRejection(ctx, fromNode, delegationID, c.currentBlockHeight).Return(expectedErr)

	event := &TransactionsDelegatedEvent{
		FromNode:     fromNode,
		DelegationID: delegationID,
	}
	err := action_RejectDelegatedTransactions(ctx, c, event)
	require.ErrorIs(t, err, expectedErr)
}

func Test_validator_IsHeartbeatFromPreferredActiveCoordinator_FromPreferredNode_ReturnsTrue(t *testing.T) {
	ctx := context.Background()
	c, _ := NewCoordinatorBuilderForTesting(t, State_Observing).PreferredActiveCoordinator("nodeA").Build()

	event := &common.HeartbeatReceivedEvent{}
	event.From = "nodeA"

	result, err := validator_IsHeartbeatFromPreferredActiveCoordinator(ctx, c, event)
	require.NoError(t, err)
	assert.True(t, result)
}

func Test_validator_IsHeartbeatFromPreferredActiveCoordinator_FromOtherNode_ReturnsFalse(t *testing.T) {
	ctx := context.Background()
	c, _ := NewCoordinatorBuilderForTesting(t, State_Observing).PreferredActiveCoordinator("nodeA").Build()

	event := &common.HeartbeatReceivedEvent{}
	event.From = "nodeB"

	result, err := validator_IsHeartbeatFromPreferredActiveCoordinator(ctx, c, event)
	require.NoError(t, err)
	assert.False(t, result)
}

func Test_validator_IsHeartbeatFromCurrentActiveCoordinator_FromCurrentNode_ReturnsTrue(t *testing.T) {
	ctx := context.Background()
	c, _ := NewCoordinatorBuilderForTesting(t, State_Observing).
		PreferredActiveCoordinator("nodeP").
		CurrentActiveCoordinator("nodeC").
		Build()

	event := &common.HeartbeatReceivedEvent{}
	event.From = "nodeC"

	result, err := validator_IsHeartbeatFromCurrentActiveCoordinator(ctx, c, event)
	require.NoError(t, err)
	assert.True(t, result)
}

func Test_validator_IsHeartbeatFromCurrentActiveCoordinator_FromPreferredOnly_ReturnsFalse(t *testing.T) {
	ctx := context.Background()
	c, _ := NewCoordinatorBuilderForTesting(t, State_Observing).
		PreferredActiveCoordinator("nodeP").
		CurrentActiveCoordinator("nodeC").
		Build()

	event := &common.HeartbeatReceivedEvent{}
	event.From = "nodeP"

	result, err := validator_IsHeartbeatFromCurrentActiveCoordinator(ctx, c, event)
	require.NoError(t, err)
	assert.False(t, result)
}

func Test_guard_IsPreferredActiveCoordinator_MatchesPreferredField(t *testing.T) {
	ctx := context.Background()
	c, _ := NewCoordinatorBuilderForTesting(t, State_Idle).
		NodeName("self").
		PreferredActiveCoordinator("self").
		CurrentActiveCoordinator("other").
		Build()
	assert.True(t, guard_IsPreferredActiveCoordinator(ctx, c))
	assert.False(t, guard_IsCurrentActiveCoordinator(ctx, c))
}

func Test_guard_IsCurrentActiveCoordinator_MatchesCurrentField(t *testing.T) {
	ctx := context.Background()
	c, _ := NewCoordinatorBuilderForTesting(t, State_Idle).
		NodeName("self").
		PreferredActiveCoordinator("other").
		CurrentActiveCoordinator("self").
		Build()
	assert.False(t, guard_IsPreferredActiveCoordinator(ctx, c))
	assert.True(t, guard_IsCurrentActiveCoordinator(ctx, c))
}
