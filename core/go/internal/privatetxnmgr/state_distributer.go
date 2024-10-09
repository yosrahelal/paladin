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

package privatetxnmgr

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/kaleido-io/paladin/config/pkg/pldconf"
	"github.com/kaleido-io/paladin/core/internal/components"
	"github.com/kaleido-io/paladin/core/internal/flushwriter"
	"github.com/kaleido-io/paladin/core/internal/privatetxnmgr/privatetxnstore"
	"github.com/kaleido-io/paladin/core/internal/privatetxnmgr/ptmgrtypes"
	"github.com/kaleido-io/paladin/core/pkg/persistence"
	pb "github.com/kaleido-io/paladin/core/pkg/proto/sequence"
	"github.com/kaleido-io/paladin/toolkit/pkg/log"
	"github.com/kaleido-io/paladin/toolkit/pkg/tktypes"
	"google.golang.org/protobuf/proto"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

const RETRY_TIMEOUT = 5 * time.Second

type stateAcknowledgement struct {
	stateID         string
	domainName      string
	contractAddress string
	receivingParty  string
	distributionID  string
}

func NewStateDistributer(ctx context.Context, nodeID string, transportManager components.TransportManager, stateManager components.StateManager, persistence persistence.Persistence, conf *pldconf.FlushWriterConfig) ptmgrtypes.StateDistributer {
	sd := &stateDistributer{
		persistence:      persistence,
		stopChan:         make(chan struct{}),
		inputChan:        make(chan *ptmgrtypes.StateDistribution),
		retryChan:        make(chan string),
		acknowledgedChan: make(chan string),
		pendingMap:       make(map[string]*ptmgrtypes.StateDistribution),
		stateManager:     stateManager,
		transportManager: transportManager,
		nodeID:           nodeID,
	}
	sd.writer = flushwriter.NewWriter(ctx, sd.runBatch, sd.persistence, conf, &pldconf.StateDistributerAcknowledgementWriterConfigDefaults)
	return sd
}

type stateDistributionAcknowledgementWriteOperation struct {
	stateDistributionID string
	contractAddress     string
}

type stateDistributer struct {
	persistence      persistence.Persistence
	stateManager     components.StateManager
	stopChan         chan struct{}
	inputChan        chan *ptmgrtypes.StateDistribution
	retryChan        chan string
	acknowledgedChan chan string
	pendingMap       map[string]*ptmgrtypes.StateDistribution
	writer           flushwriter.Writer[*stateDistributionAcknowledgementWriteOperation, *noResult]
	transportManager components.TransportManager
	nodeID           string
}

func (sda *stateDistributionAcknowledgementWriteOperation) WriteKey() string {
	return sda.contractAddress
}

type noResult struct{}

type stateDistributionAcknowledgement struct {
	stateDistribution string
	id                string
}

func (sd *stateDistributer) runBatch(ctx context.Context, tx *gorm.DB, values []*stateDistributionAcknowledgementWriteOperation) ([]flushwriter.Result[*noResult], error) {
	acknowledgements := make([]*stateDistributionAcknowledgement, 0, len(values))
	for _, value := range values {
		acknowledgements = append(acknowledgements, &stateDistributionAcknowledgement{
			stateDistribution: value.stateDistributionID,
			id:                uuid.New().String(),
		})
	}

	err := tx.
		Table("state_distribution_acknowledgments").
		Clauses(clause.OnConflict{
			DoNothing: true, // immutable
		}).
		Create(acknowledgements).
		Error

	// We don't actually provide any result, so just build an array of nil results
	return make([]flushwriter.Result[*noResult], len(values)), err

}

func (sd *stateDistributer) Start(ctx context.Context) error {
	log.L(ctx).Info("stateDistributer:Start")
	var stateDistributions []privatetxnstore.StateDistributionPersisted
	err := sd.persistence.DB().Table("state_distributions").
		Select("state_distributions.*").
		Joins("LEFT JOIN state_distribution_acknowledgments ON state_distributions.id = state_distribution_acknowledgments.state_distribution").
		Where("state_distribution_acknowledgments.id IS NULL").
		Find(&stateDistributions).Error

	if err != nil {
		log.L(ctx).Errorf("Error getting state distributions: %s", err)
		return err
	}
	log.L(ctx).Infof("stateDistributer:Start loaded %d state distributions on startup", len(stateDistributions))

	for _, stateDistribution := range stateDistributions {
		state, err := sd.stateManager.GetState(ctx, stateDistribution.DomainName, *tktypes.MustEthAddress(stateDistribution.ContractAddress), tktypes.MustParseHexBytes(stateDistribution.StateID), true, false)
		if err != nil {
			log.L(ctx).Errorf("Error getting state: %s", err)
			continue
		}

		sd.inputChan <- &ptmgrtypes.StateDistribution{
			ID:              stateDistribution.ID,
			StateID:         stateDistribution.StateID,
			IdentityLocator: stateDistribution.IdentityLocator,
			Domain:          stateDistribution.DomainName,
			ContractAddress: stateDistribution.ContractAddress,
			SchemaID:        state.Schema.String(),
			StateDataJson:   string(state.Data),
		}
	}

	sd.writer.Start()

	go func() {
		log.L(ctx).Info("stateDistributer:Start starting loop")
		for {
			log.L(ctx).Debug("stateDistributer:Start waiting for next event")

			select {
			case <-ctx.Done():
				return
			case <-sd.stopChan:
				return
			case stateDistributionID := <-sd.acknowledgedChan:
				_, stillPending := sd.pendingMap[stateDistributionID]
				if stillPending {
					log.L(ctx).Debugf("stateDistributer:Start acknowledging %s", stateDistributionID)
					sd.writer.Queue(ctx, &stateDistributionAcknowledgementWriteOperation{
						stateDistributionID: stateDistributionID,
					})
					delete(sd.pendingMap, stateDistributionID)
				}
				//if we didn't find it in the map, it was already acknowledged

			case stateDistributionID := <-sd.retryChan:

				pendingDistribution, stillPending := sd.pendingMap[stateDistributionID]
				if stillPending {
					log.L(ctx).Debugf("stateDistributer:Start retrying %s", stateDistributionID)
					sd.sendState(ctx, pendingDistribution)
				}
				//if we didn't find it in the map, it was already acknowledged

			case stateDistribution := <-sd.inputChan:
				log.L(ctx).Debugf("stateDistributer:Start new distribution %s", stateDistribution.ID)

				sd.pendingMap[stateDistribution.ID] = stateDistribution
				sd.sendState(ctx, stateDistribution)

			}
		}
	}()
	return nil
}

func (sd *stateDistributer) Stop(ctx context.Context) {
	close(sd.stopChan)
}

func (sd *stateDistributer) AcknowledgeState(ctx context.Context, stateDistributionID string) {
	log.L(ctx).Debugf("stateDistributer:AcknowledgeState %s ", stateDistributionID)
	sd.acknowledgedChan <- stateDistributionID
}

func (sd *stateDistributer) DistributeStates(ctx context.Context, stateDistributions []*ptmgrtypes.StateDistribution) {
	log.L(ctx).Debugf("stateDistributer:DistributeStates %d state distributions", len(stateDistributions))
	for _, stateDistribution := range stateDistributions {
		sd.inputChan <- stateDistribution
	}
}

func (sd *stateDistributer) sendState(ctx context.Context, stateDistribution *ptmgrtypes.StateDistribution) {

	stateProducedEvent := &pb.StateProducedEvent{
		DomainName:      stateDistribution.Domain,
		ContractAddress: stateDistribution.ContractAddress,
		SchemaId:        stateDistribution.SchemaID,
		StateId:         stateDistribution.StateID,
		StateDataJson:   stateDistribution.StateDataJson,
		Party:           stateDistribution.IdentityLocator,
	}
	stateProducedEventBytes, err := proto.Marshal(stateProducedEvent)
	if err != nil {
		log.L(ctx).Errorf("Error marshalling delegate transaction message: %s", err)
		return
	}

	targetNode, err := tktypes.PrivateIdentityLocator(stateDistribution.IdentityLocator).Node(ctx, false)
	if err != nil {
		log.L(ctx).Errorf("Error getting node for party %s", stateDistribution.IdentityLocator)
		return
	}

	err = sd.transportManager.Send(ctx, &components.TransportMessage{
		MessageType: "StateProducedEvent",
		Payload:     stateProducedEventBytes,
		Destination: tktypes.PrivateIdentityLocator(fmt.Sprintf("%s@%s", PRIVATE_TX_MANAGER_DESTINATION, targetNode)),
		ReplyTo:     tktypes.PrivateIdentityLocator(fmt.Sprintf("%s@%s", PRIVATE_TX_MANAGER_DESTINATION, sd.nodeID)),
	})
	if err != nil {
		log.L(ctx).Errorf("Error sending state produced event: %s", err)
		return
	}

	go func() {
		time.Sleep(RETRY_TIMEOUT)
		sd.retryChan <- stateDistribution.ID
	}()

}

func (sd *stateDistributer) SendStateAcknowledgement(ctx context.Context, domainName string, contractAddress string, stateId string, receivingParty string, distributingNode string, distributionID string) error {
	stateAcknowledgedEvent := &pb.StateAcknowledgedEvent{
		DomainName:      domainName,
		ContractAddress: contractAddress,
		StateId:         stateId,
		Party:           receivingParty,
		DistributionId:  distributionID,
	}
	stateAcknowledgedEventBytes, err := proto.Marshal(stateAcknowledgedEvent)
	if err != nil {
		log.L(ctx).Errorf("Error marshalling state acknowledgment event: %s", err)
		return err
	}

	err = sd.transportManager.Send(ctx, &components.TransportMessage{
		MessageType: "StateAcknowledgedEvent",
		Payload:     stateAcknowledgedEventBytes,
		Destination: tktypes.PrivateIdentityLocator(fmt.Sprintf("%s@%s", PRIVATE_TX_MANAGER_DESTINATION, distributingNode)),
		ReplyTo:     tktypes.PrivateIdentityLocator(fmt.Sprintf("%s@%s", PRIVATE_TX_MANAGER_DESTINATION, sd.nodeID)),
	})
	if err != nil {
		log.L(ctx).Errorf("Error sending state produced event: %s", err)
		return err
	}

	return nil
}
