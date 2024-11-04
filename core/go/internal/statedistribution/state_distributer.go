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

package statedistribution

import (
	"context"
	"time"

	"github.com/kaleido-io/paladin/config/pkg/pldconf"
	"github.com/kaleido-io/paladin/core/internal/components"
	"github.com/kaleido-io/paladin/core/pkg/persistence"
	pb "github.com/kaleido-io/paladin/core/pkg/proto/engine"
	"github.com/kaleido-io/paladin/toolkit/pkg/log"
	"github.com/kaleido-io/paladin/toolkit/pkg/retry"
	"github.com/kaleido-io/paladin/toolkit/pkg/tktypes"
)

const RETRY_TIMEOUT = 5 * time.Second

func NewStateDistributer(ctx context.Context, nodeID string, transportManager components.TransportManager, stateManager components.StateManager, persistence persistence.Persistence, conf *pldconf.DistributerConfig) StateDistributer {
	sd := &stateDistributer{
		persistence:      persistence,
		inputChan:        make(chan *StateDistribution),
		retryChan:        make(chan string),
		acknowledgedChan: make(chan string),
		pendingMap:       make(map[string]*StateDistribution),
		stateManager:     stateManager,
		transportManager: transportManager,
		nodeID:           nodeID,
		retry:            retry.NewRetryIndefinite(&pldconf.RetryConfig{}, &pldconf.GenericRetryDefaults.RetryConfig),
	}
	sd.acknowledgementWriter = NewAcknowledgementWriter(ctx, sd.persistence, &conf.AcknowledgementWriter)
	sd.receivedStateWriter = NewReceivedStateWriter(ctx, stateManager, persistence, &conf.ReceivedObjectWriter)

	return sd
}

type StateDistributionPersisted struct {
	Created         tktypes.Timestamp  `json:"created" gorm:"column:created;autoCreateTime:nano"`
	ID              string             `json:"id"`
	StateID         tktypes.HexBytes   `json:"stateID"`
	IdentityLocator string             `json:"identityLocator"`
	DomainName      string             `json:"domainName"`
	ContractAddress tktypes.EthAddress `json:"contractAddress"`
}

// A StateDistribution is an intent to send private data for a given state to a remote party
type StateDistribution struct {
	ID              string
	StateID         string
	IdentityLocator string
	Domain          string
	ContractAddress string
	SchemaID        string
	StateDataJson   string
}

/*
StateDistributer is a component that is responsible for distributing state to remote parties

	it runs in its own goroutine and periodically sends states to the intended recipients
	until each recipient has acknowledged receipt of the state.

	This operates on in-memory data but will initialize from persistent storage on startup
*/
type StateDistributer interface {
	Start(ctx context.Context) error
	Stop(ctx context.Context)
	DistributeStates(ctx context.Context, stateDistributions []*StateDistribution)
	HandleStateProducedEvent(ctx context.Context, stateProducedEvent *pb.StateProducedEvent, distributingNode string)
	HandleStateAcknowledgedEvent(ctx context.Context, messagePayload []byte)
}

type stateDistributer struct {
	runCtx                context.Context
	stopRunCtx            context.CancelFunc
	persistence           persistence.Persistence
	stateManager          components.StateManager
	inputChan             chan *StateDistribution
	retryChan             chan string
	acknowledgedChan      chan string
	pendingMap            map[string]*StateDistribution
	acknowledgementWriter *acknowledgementWriter
	receivedStateWriter   *receivedStateWriter
	transportManager      components.TransportManager
	nodeID                string
	retry                 *retry.Retry
}

func (sd *stateDistributer) Start(bgCtx context.Context) error {
	sd.runCtx, sd.stopRunCtx = context.WithCancel(bgCtx)
	ctx := sd.runCtx
	log.L(ctx).Info("stateDistributer:Start")

	sd.acknowledgementWriter.Start()
	sd.receivedStateWriter.Start()

	// TODO: This needs to be a worker per-peer - probably a whole state distributor per peer that can be swapped in/out.
	// Currently it only runs on startup, and pushes all state distributions from before the startup time into the distributor.
	startTime := tktypes.TimestampNow()
	go func() {
		page := 0
		dispatched := 0
		var lastEntry *StateDistributionPersisted
		finished := false
		for !finished {
			err := sd.retry.Do(ctx, func(attempt int) (retryable bool, err error) {
				page++
				var stateDistributions []*StateDistributionPersisted
				query := sd.persistence.DB().Table("state_distributions").
					Select("state_distributions.*").
					Joins("LEFT JOIN state_distribution_acknowledgments ON state_distributions.id = state_distribution_acknowledgments.state_distribution").
					Where("state_distribution_acknowledgments.id IS NULL").
					Where("created < ?", startTime).
					Order("created").
					Limit(100)
				if lastEntry != nil {
					query = query.Where("created > ?", lastEntry.Created)
				}
				err = query.Find(&stateDistributions).Error

				if err != nil {
					log.L(ctx).Errorf("Error getting state distributions: %s", err)
					return true, err
				}

				log.L(ctx).Infof("stateDistributer loaded %d state distributions on startup (page=%d)", len(stateDistributions), page)

				for _, stateDistribution := range stateDistributions {
					state, err := sd.stateManager.GetState(ctx, sd.persistence.DB(), /* no TX for now */
						stateDistribution.DomainName, stateDistribution.ContractAddress, stateDistribution.StateID, true, false)
					if err != nil {
						log.L(ctx).Errorf("Error getting state: %s", err)
						continue
					}

					sd.inputChan <- &StateDistribution{
						ID:              stateDistribution.ID,
						StateID:         stateDistribution.StateID.String(),
						IdentityLocator: stateDistribution.IdentityLocator,
						Domain:          stateDistribution.DomainName,
						ContractAddress: stateDistribution.ContractAddress.String(),
						SchemaID:        state.Schema.String(),
						StateDataJson:   string(state.Data),
					}

					dispatched++
					lastEntry = stateDistribution
				}
				finished = (len(stateDistributions) == 0)
				return false, nil
			})
			if err != nil {
				log.L(ctx).Warnf("exiting before sending all recovered state distributions")
			}
		}
		log.L(ctx).Infof("stateDistributer finished startup recovery after dispatching %d distributions", dispatched)
	}()

	go func() {
		log.L(ctx).Info("stateDistributer:Loop starting loop")
		for {
			log.L(ctx).Debug("stateDistributer:Loop waiting for next event")

			select {
			case <-ctx.Done():
				return
			case stateDistributionID := <-sd.acknowledgedChan:
				_, stillPending := sd.pendingMap[stateDistributionID]
				if stillPending {
					log.L(ctx).Debugf("stateDistributer:Loop processing acknowledgment %s", stateDistributionID)

					delete(sd.pendingMap, stateDistributionID)
				} else {
					log.L(ctx).Debugf("stateDistributer:Loop already received acknowledgment %s", stateDistributionID)

				}
				//if we didn't find it in the map, it was already acknowledged

			case stateDistributionID := <-sd.retryChan:

				pendingDistribution, stillPending := sd.pendingMap[stateDistributionID]
				if stillPending {
					log.L(ctx).Debugf("stateDistributer:Loop retrying %s", stateDistributionID)
					sd.sendState(ctx, pendingDistribution)
				}
				//if we didn't find it in the map, it was already acknowledged

			case stateDistribution := <-sd.inputChan:
				log.L(ctx).Debugf("stateDistributer:Loop new distribution %s", stateDistribution.ID)

				sd.pendingMap[stateDistribution.ID] = stateDistribution
				sd.sendState(ctx, stateDistribution)

			}
		}
	}()
	return nil
}

func (sd *stateDistributer) Stop(ctx context.Context) {
	sd.stopRunCtx()
	sd.acknowledgementWriter.Stop()
	sd.receivedStateWriter.Stop()
}
