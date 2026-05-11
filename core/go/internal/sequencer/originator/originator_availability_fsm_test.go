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

package originator

import (
	"testing"

	"github.com/LFDT-Paladin/paladin/config/pkg/confutil"
	"github.com/LFDT-Paladin/paladin/config/pkg/pldconf"
	"github.com/stretchr/testify/assert"
)

const skipOriginatorAvailabilityFollowUp = "waiting on preferred/current split, cyclic-walk helper, and local sync wiring — coordinator availability follow-up"

func TestOriginatorBuilder_WhenOverrideSequencerConfigSet_NewOriginatorUsesThatConfig(t *testing.T) {
	cfg := pldconf.SequencerDefaults
	cfg.BlockRange = confutil.P(uint64(83))
	b := NewOriginatorBuilderForTesting(State_Idle)
	b.OverrideSequencerConfig(&cfg)
	o, _ := b.Build()
	assert.Equal(t, uint64(83), o.blockRangeSize)
}

func TestOriginatorBuilder_WhenNeedsRedelegateSet_SeedsOriginatorField(t *testing.T) {
	o, _ := NewOriginatorBuilderForTesting(State_Idle).NeedsRedelegate(true).Build()
	assert.True(t, o.needsRedelegate)
}

func TestOriginator_WhenNewEpochRuns_PreservesPreviousActiveAndRecomputesActiveWithWatchingFlushOnlyOnIdentityChange(t *testing.T) {
	t.Skip(skipOriginatorAvailabilityFollowUp)
}

func TestOriginator_WhenWatchingPreviousFlush_DelegationSuppressedEvenInSending(t *testing.T) {
	t.Skip(skipOriginatorAvailabilityFollowUp)
}

func TestOriginator_WhenWatchingPreviousFlush_ExitsOnPreviousClosingHeartbeat(t *testing.T) {
	t.Skip(skipOriginatorAvailabilityFollowUp)
}

func TestOriginator_WhenWatchingPreviousFlush_ExitsOnHeartbeatFromNewActiveWhileWatching(t *testing.T) {
	t.Skip(skipOriginatorAvailabilityFollowUp)
}

func TestOriginator_WhenWatchingPreviousFlush_ExitsOnHeartbeatIntervalInactivePathThatNudgesNewCoordinator(t *testing.T) {
	t.Skip(skipOriginatorAvailabilityFollowUp)
}

func TestOriginator_WhenSnapshotShowsMissingNonFinalTransaction_SetsNeedsRedelegate(t *testing.T) {
	t.Skip(skipOriginatorAvailabilityFollowUp)
}

func TestOriginator_WhenStaticMode_UnavailabilityWaitsWithoutWalkingPool(t *testing.T) {
	t.Skip(skipOriginatorAvailabilityFollowUp)
}

func TestOriginator_WhenSenderMode_DoesNotMutateFailoverOffset(t *testing.T) {
	t.Skip(skipOriginatorAvailabilityFollowUp)
}

func TestOriginator_WhenEndorserMode_UsesCyclicWalkOnlyWhenConfigured(t *testing.T) {
	t.Skip(skipOriginatorAvailabilityFollowUp)
}

func TestOriginator_WhenHeartbeatFromCurrentStalePastInactive_AdvancedFailoverOffsetAndRedelegatesAndQueuesLocalSync(t *testing.T) {
	t.Skip(skipOriginatorAvailabilityFollowUp)
}

func TestOriginator_WhenDelegationSendFails_DoesNotAdvanceFailoverOffset(t *testing.T) {
	t.Skip(skipOriginatorAvailabilityFollowUp)
}

func TestOriginator_WhenHeartbeatLossAndDelegationError_PrecedenceFavorsHeartbeatFailoverPath(t *testing.T) {
	t.Skip(skipOriginatorAvailabilityFollowUp)
}

func TestOriginator_WhenRepeatedCurrentCoordinatorFailures_AdvanceFailoverOffsetAroundPoolWithoutExtraTimer(t *testing.T) {
	t.Skip(skipOriginatorAvailabilityFollowUp)
}

func TestOriginator_WhenNewEpochWhileOnFallback_ResetsFailoverOffsetToZero(t *testing.T) {
	t.Skip(skipOriginatorAvailabilityFollowUp)
}

func TestOriginator_WhenDelegationSucceedsToPreferredWhileOnFallback_PreferredBecomesActiveAndOthersObserve(t *testing.T) {
	t.Skip(skipOriginatorAvailabilityFollowUp)
}

func TestOriginator_WhenFallbackObservesPreferredActive_RedelegatesPerSpec(t *testing.T) {
	t.Skip(skipOriginatorAvailabilityFollowUp)
}

func TestOriginator_WhenFallbackNeverObservesPreferred_MayRemainOnFallbackUnderLocalRules(t *testing.T) {
	t.Skip(skipOriginatorAvailabilityFollowUp)
}

func TestOriginator_WhenDrainingFallback_DualTracksFallbackOutcomesAndPreferredForNewWork(t *testing.T) {
	t.Skip(skipOriginatorAvailabilityFollowUp)
}

func TestOriginator_WhenWatchingPreviousFlushWhileRepointingToFallback_ReconcilesPerSpec(t *testing.T) {
	t.Skip(skipOriginatorAvailabilityFollowUp)
}
