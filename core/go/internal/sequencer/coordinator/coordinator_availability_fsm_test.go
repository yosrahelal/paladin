/*
 * Copyright © 2026 Kaleido, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the
 * License. You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations under the License.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package coordinator

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

const skipCoordinatorAvailabilityFollowUp = "waiting on preferred/current split, cyclic-walk helper, and local sync wiring — coordinator availability follow-up"

func TestCoordinatorBuilder_WhenPreviousActiveCoordinatorSet_SeedsCoordinatorField(t *testing.T) {
	c, _ := NewCoordinatorBuilderForTesting(t, State_Idle).PreviousActiveCoordinatorNode("prior-coordinator").Build()
	assert.Equal(t, "prior-coordinator", c.previousActiveCoordinatorNode)
}

func TestCoordinatorBuilder_WhenNewBlockRangeEpochSet_SeedsCoordinatorField(t *testing.T) {
	c, _ := NewCoordinatorBuilderForTesting(t, State_Idle).NewBlockRangeEpoch(true).Build()
	assert.True(t, c.newBlockRangeEpoch)
}

func TestCoordinatorBuilder_WhenNodeNameSet_PassesToConstructedCoordinator(t *testing.T) {
	c, _ := NewCoordinatorBuilderForTesting(t, State_Idle).NodeName("member@custom").Build()
	assert.Equal(t, "member@custom", c.nodeName)
}

func TestCoordinator_WhenElectCompletesViaPreviousClosingHeartbeat_ImportsStateOnlyOnThatPath(t *testing.T) {
	t.Skip(skipCoordinatorAvailabilityFollowUp)
}

func TestCoordinator_WhenElectCompletesViaInactiveGrace_DoesNotImportStateLikeClosingHeartbeatPath(t *testing.T) {
	t.Skip(skipCoordinatorAvailabilityFollowUp)
}

func TestCoordinator_WhenActiveAndEpochChangesWithInflightDispatched_TransitionsToFlush(t *testing.T) {
	t.Skip(skipCoordinatorAvailabilityFollowUp)
}

func TestCoordinator_WhenActiveAndEpochChangesWithSamePreferredAndNoInflight_ReentersActive(t *testing.T) {
	t.Skip(skipCoordinatorAvailabilityFollowUp)
}

func TestCoordinator_WhenActiveAndEpochChangesWithNoInflightAndNotPreferred_TransitionsToClosing(t *testing.T) {
	t.Skip(skipCoordinatorAvailabilityFollowUp)
}

func TestCoordinator_WhenFlushCompletesAndStillPreferredForRange_TransitionsToActive(t *testing.T) {
	t.Skip(skipCoordinatorAvailabilityFollowUp)
}

func TestCoordinator_WhenFlushCompletesAndNotPreferred_TransitionsToClosing(t *testing.T) {
	t.Skip(skipCoordinatorAvailabilityFollowUp)
}

func TestCoordinator_WhenClosingStarts_EmitsImmediateHeartbeat(t *testing.T) {
	t.Skip(skipCoordinatorAvailabilityFollowUp)
}

func TestCoordinator_WhenClosingGraceExpires_WithNewActiveHeartbeatSeen_TransitionsToObserving(t *testing.T) {
	t.Skip(skipCoordinatorAvailabilityFollowUp)
}

func TestCoordinator_WhenClosingGraceExpires_WithoutNewActiveHeartbeat_TransitionsToIdle(t *testing.T) {
	t.Skip(skipCoordinatorAvailabilityFollowUp)
}

func TestCoordinator_WhenEnteringActive_RefreshesSigningIdentityAndSelectsTransactions(t *testing.T) {
	t.Skip(skipCoordinatorAvailabilityFollowUp)
}

func TestCoordinator_WhenStaticMode_UnavailabilityDoesNotWalkEndorserPool(t *testing.T) {
	t.Skip(skipCoordinatorAvailabilityFollowUp)
}

func TestCoordinator_WhenSenderMode_UnavailabilityDoesNotWalkEndorserPool(t *testing.T) {
	t.Skip(skipCoordinatorAvailabilityFollowUp)
}

func TestCoordinator_WhenFallbackObservesPreferredActive_YieldsViaFlushToClose(t *testing.T) {
	t.Skip(skipCoordinatorAvailabilityFollowUp)
}

func TestCoordinator_WhenPreferredReceivesFallbackActiveHeartbeatsWhilePreferred_TransitionsToActive(t *testing.T) {
	t.Skip(skipCoordinatorAvailabilityFollowUp)
}

func TestCoordinator_WhenOriginatorChangesCurrentTarget_ReceivesLocalPrioritySyncEvent(t *testing.T) {
	t.Skip(skipCoordinatorAvailabilityFollowUp)
}

func TestCoordinator_WhenEpochRollsDuringFlush_FailoverOffsetResetsConsistentlyWithHandoverFsm(t *testing.T) {
	t.Skip(skipCoordinatorAvailabilityFollowUp)
}
