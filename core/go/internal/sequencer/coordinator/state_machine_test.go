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
	"testing"

	"github.com/LFDT-Paladin/paladin/core/internal/sequencer/statemachine"
	"github.com/stretchr/testify/require"
)

func Test_queueEventInternal_QueuesPriorityEvent(t *testing.T) {
	builder := NewCoordinatorBuilderForTesting(t, State_Idle)
	ctx, cancel := context.WithCancel(t.Context())
	c, _ := builder.Build()
	require.NoError(t, c.Start(ctx))
	defer func() {
		cancel()
		c.WaitForDone(t.Context())
	}()

	syncEvent := statemachine.NewSyncEvent()
	c.queueEventInternal(ctx, syncEvent)
	<-syncEvent.Done
	require.False(t, c.stateMachineEventLoop.IsStopped(), "event loop should still be running")
}

func Test_TryQueueEvent_QueuesToEventLoop(t *testing.T) {
	builder := NewCoordinatorBuilderForTesting(t, State_Idle)
	ctx, cancel := context.WithCancel(t.Context())
	c, _ := builder.Build()
	require.NoError(t, c.Start(ctx))
	defer func() {
		cancel()
		c.WaitForDone(t.Context())
	}()

	event := &CoordinatorCreatedEvent{}
	ok := c.TryQueueEvent(ctx, event)
	require.True(t, ok, "TryQueueEvent should return true when event is queued")

	// Drain the event so the loop can process it and we can cleanly stop
	syncEvent := statemachine.NewSyncEvent()
	c.QueueEvent(ctx, syncEvent)
	<-syncEvent.Done
}
