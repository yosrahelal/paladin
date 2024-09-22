/*
 * Copyright © 2024 Kaleido, Inc.
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

package publictxmgr

import (
	"context"
	"time"

	"github.com/kaleido-io/paladin/core/internal/cache"
	"github.com/kaleido-io/paladin/core/internal/flushwriter"
	"github.com/kaleido-io/paladin/toolkit/pkg/confutil"
	"github.com/kaleido-io/paladin/toolkit/pkg/log"
	"github.com/kaleido-io/paladin/toolkit/pkg/retry"
	"github.com/kaleido-io/paladin/toolkit/pkg/tktypes"
)

type TransactionEngineConfig struct {
	MaxInFlightOrchestrators *int               `yaml:"maxInFlightOrchestrators"`
	Interval                 *string            `yaml:"interval"`
	MaxStaleTime             *string            `yaml:"maxStaleTime"`
	MaxIdleTime              *string            `yaml:"maxIdleTime"`
	MaxOverloadProcessTime   *string            `yaml:"maxOverloadProcessTime"`
	TransactionCache         cache.Config       `yaml:"transactionCache"` // can be larger than number of orchestrators for hot swapping
	SubmissionWriter         flushwriter.Config `yaml:"submissionWriter"`
	Retry                    retry.Config       `yaml:"retry"`
}

var DefaultTransactionEngineConfig = &TransactionEngineConfig{
	MaxInFlightOrchestrators: confutil.P(50),
	Interval:                 confutil.P("5s"),
	MaxStaleTime:             confutil.P("1m"),
	MaxIdleTime:              confutil.P("10s"),
	MaxOverloadProcessTime:   confutil.P("10m"),
	Retry: retry.Config{
		InitialDelay: confutil.P("250ms"),
		MaxDelay:     confutil.P("30s"),
		Factor:       confutil.P(2.0),
	},
	SubmissionWriter: flushwriter.Config{
		WorkerCount:  confutil.P(5),
		BatchTimeout: confutil.P("75ms"),
		BatchMaxSize: confutil.P(50),
	},
	TransactionCache: cache.Config{
		Capacity: confutil.P(1000),
	},
}

// role of transaction engine:
// 1. owner and the only manipulator of the transaction orchestrators pool
//    - decides how many transaction orchestrators can there be in total at a given time
//    - decides the size of each transaction orchestrator queue
//    - decides signing address of each transaction orchestrator
//    - controls the life cycle for transaction orchestrators based on its latest status
//       - time box transaction orchestrator lifespan
//       - creates transaction orchestrator when necessary
//       - deletes transaction orchestrator when there is no pending transaction for a signing address
//       - pauses (delete) transaction orchestrator when it's in a stuck state
//       - resumes (re-create) transaction orchestrator in a resuming mode (1 transaction to test the water before add more) based on user configuration
// 2. handle external requests of transaction status change
//       - update/delete of a transaction when its signing address not in-flight
//       - signal update/delete of a transaction in-flight to corresponding transaction orchestrator
// 3. auto fueling management - the autofueling transactions
//    - creating auto-fueling transactions when asked by transaction orchestrators
// 4. provides shared functionalities for optimization
//    - handles gas price information which is not signer specific

func (ble *pubTxManager) engineLoop() {
	defer close(ble.engineLoopDone)
	ctx := log.WithLogField(ble.ctx, "role", "engine-loop")
	log.L(ctx).Infof("Engine started polling on interval %s", ble.enginePollingInterval)

	ticker := time.NewTicker(ble.enginePollingInterval)
	for {
		// Wait to be notified, or timeout to run
		select {
		case <-ticker.C:
		case <-ble.InFlightOrchestratorStale:
		case <-ctx.Done():
			ticker.Stop()
			log.L(ctx).Infof("Engine poller exiting")
			return
		}

		polled, total := ble.poll(ctx)
		log.L(ctx).Debugf("Engine polling complete: %d transaction orchestrators were created, there are %d transaction orchestrators in flight", polled, total)
	}
}

func (ble *pubTxManager) poll(ctx context.Context) (polled int, total int) {
	pollStart := time.Now()
	ble.InFlightOrchestratorMux.Lock()
	defer ble.InFlightOrchestratorMux.Unlock()

	oldInFlight := ble.InFlightOrchestrators
	ble.InFlightOrchestrators = make(map[tktypes.EthAddress]*orchestrator)

	inFlightSigningAddresses := make([]tktypes.EthAddress, 0, len(oldInFlight))

	stateCounts := make(map[string]int)
	for _, sName := range AllOrchestratorStates {
		// map for saving number of in flight transaction per stage
		stateCounts[sName] = 0
	}

	// Run through copying across from the old InFlight list to the new one, those that aren't ready to be deleted
	for signingAddress, oc := range oldInFlight {
		log.L(ctx).Debugf("Engine checking orchestrator for %s: state: %s, state duration: %s, number of transactions: %d", oc.signingAddress, oc.state, time.Since(oc.stateEntryTime), len(oc.InFlightTxs))
		if (oc.state == OrchestratorStateStale && time.Since(oc.stateEntryTime) > ble.maxOrchestratorStale) ||
			(oc.state == OrchestratorStateIdle && time.Since(oc.stateEntryTime) > ble.maxOrchestratorIdle) {
			// tell transaction orchestrator to stop, there is a chance we later found new transaction for this address, but we got to make a call at some point
			// so it's here. The transaction orchestrator won't be removed immediately as the state update is async
			oc.Stop()
		}
		if oc.state != OrchestratorStateStopped {
			ble.InFlightOrchestrators[signingAddress] = oc
			oc.MarkInFlightTxStale()
			stateCounts[string(oc.state)] = stateCounts[string(oc.state)] + 1
			inFlightSigningAddresses = append(inFlightSigningAddresses, signingAddress)
		} else {
			log.L(ctx).Infof("Engine removed orchestrator for signing address %s", signingAddress)
		}
	}

	totalBeforePoll := len(ble.InFlightOrchestrators)
	// check and poll new signers from the persistence if there are more transaction orchestrators slots
	spaces := ble.maxInFlightOrchestrators - totalBeforePoll
	if spaces > 0 {

		// Run through the paused orchestrators for fairness control
		for signingAddress, pausedUntil := range ble.SigningAddressesPausedUntil {
			if time.Now().Before(pausedUntil) {
				log.L(ctx).Debugf("Engine excluded orchestrator for signing address %s from polling as it's paused util %s", signingAddress, pausedUntil.String())
				stateCounts[string(OrchestratorStatePaused)] = stateCounts[string(OrchestratorStatePaused)] + 1
				inFlightSigningAddresses = append(inFlightSigningAddresses, signingAddress)
			}
		}

		var additionalNonInFlightSigners []tktypes.EthAddress
		// We retry the get from persistence indefinitely (until the context cancels)
		err := ble.retry.Do(ctx, func(attempt int) (retry bool, err error) {
			// TODO: Fairness algorithm for swapping out orchestrators when there is no space
			q := ble.p.DB().
				WithContext(ctx).
				Distinct("from").
				Joins("Completed").
				Where("Completed__tx_hash IS NULL").
				Limit(spaces)
			if len(inFlightSigningAddresses) > 0 {
				q = q.Where("from NOT IN (?)", inFlightSigningAddresses)
			}
			return true, q.Pluck("from", additionalNonInFlightSigners).Error
		})
		if err != nil {
			log.L(ctx).Infof("Engine polling context cancelled while retrying")
			return -1, len(ble.InFlightOrchestrators)
		}

		log.L(ctx).Debugf("Engine polled %d items to fill in %d empty slots.", len(additionalNonInFlightSigners), spaces)

		for _, from := range additionalNonInFlightSigners {
			if _, exist := ble.InFlightOrchestrators[from]; !exist {
				oc := NewOrchestrator(ble, from, ble.conf)
				ble.InFlightOrchestrators[from] = oc
				stateCounts[string(oc.state)] = stateCounts[string(oc.state)] + 1
				_, _ = oc.Start(ble.ctx)
				log.L(ctx).Infof("Engine added orchestrator for signing address %s", from)
			} else {
				log.L(ctx).Warnf("Engine fetched extra transactions from signing address %s", from)
			}
		}
		total = len(ble.InFlightOrchestrators)
		if total > 0 {
			polled = total - totalBeforePoll
		}
	} else {
		// the in-flight orchestrator pool is full, do the fairness control

		// TODO: don't stop more than required number of slots

		// Run through the existing running orchestrators and stop the ones that exceeded the max process timeout
		for signingAddress, oc := range ble.InFlightOrchestrators {
			if time.Since(oc.orchestratorBirthTime) > ble.maxOverloadProcessTime {
				log.L(ctx).Infof("Engine pause, attempt to stop orchestrator for signing address %s", signingAddress)
				oc.Stop()
				ble.SigningAddressesPausedUntil[signingAddress] = time.Now().Add(ble.maxOverloadProcessTime)
			}
		}
	}
	ble.thMetrics.RecordInFlightOrchestratorPoolMetrics(ctx, stateCounts, ble.maxInFlightOrchestrators-len(ble.InFlightOrchestrators))
	log.L(ctx).Debugf("Engine poll loop took %s", time.Since(pollStart))
	return polled, total
}

func (ble *pubTxManager) MarkInFlightOrchestratorsStale() {
	// try to send an item in `InFlightStale` channel, which has a buffer of 1
	// to trigger a polling event to update the in flight transaction orchestrators
	// if it already has an item in the channel, this function does nothing
	select {
	case ble.InFlightOrchestratorStale <- true:
	default:
	}
}
