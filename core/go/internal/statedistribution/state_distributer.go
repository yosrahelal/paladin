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
	"fmt"
	"time"

	"github.com/kaleido-io/paladin/config/pkg/pldconf"
	"github.com/kaleido-io/paladin/core/internal/components"
	"github.com/kaleido-io/paladin/core/internal/privatetxnmgr/privatetxnstore"
	"github.com/kaleido-io/paladin/core/internal/privatetxnmgr/ptmgrtypes"
	"github.com/kaleido-io/paladin/core/pkg/persistence"
	pb "github.com/kaleido-io/paladin/core/pkg/proto/sequence"
	"github.com/kaleido-io/paladin/toolkit/pkg/log"
	"github.com/kaleido-io/paladin/toolkit/pkg/tktypes"
	"google.golang.org/protobuf/proto"
)

const RETRY_TIMEOUT = 5 * time.Second
const STATE_DISTRIBUTER_DESTINATION = "state-distributer"

func NewStateDistributer(ctx context.Context, nodeID string, transportManager components.TransportManager, stateManager components.StateManager, persistence persistence.Persistence, conf *pldconf.StateDistributerConfig) ptmgrtypes.StateDistributer {
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
	sd.acknowledgementWriter = NewAcknowledgementWriter(ctx, sd.persistence, &conf.AcknowledgementWriter)

	return sd
}

type receivedStateWriteOperation struct {
	DomainName      string
	ContractAddress *tktypes.EthAddress
	SchemaID        tktypes.Bytes32
	StateDataJson   string
}

type stateDistributer struct {
	persistence           persistence.Persistence
	stateManager          components.StateManager
	stopChan              chan struct{}
	inputChan             chan *ptmgrtypes.StateDistribution
	retryChan             chan string
	acknowledgedChan      chan string
	pendingMap            map[string]*ptmgrtypes.StateDistribution
	acknowledgementWriter *acknowledgementWriter
	transportManager      components.TransportManager
	nodeID                string
}

func (sd *stateDistributer) Start(ctx context.Context) error {
	log.L(ctx).Info("stateDistributer:Start")
	err := sd.transportManager.RegisterClient(ctx, sd)
	if err != nil {
		log.L(ctx).Errorf("Error registering transport client: %s", err)
		return err
	}

	var stateDistributions []privatetxnstore.StateDistributionPersisted
	err = sd.persistence.DB().Table("state_distributions").
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

	sd.acknowledgementWriter.Start()

	go func() {
		log.L(ctx).Info("stateDistributer:Loop starting loop")
		for {
			log.L(ctx).Debug("stateDistributer:Loop waiting for next event")

			select {
			case <-ctx.Done():
				return
			case <-sd.stopChan:
				return
			case stateDistributionID := <-sd.acknowledgedChan:
				_, stillPending := sd.pendingMap[stateDistributionID]
				if stillPending {
					log.L(ctx).Debugf("stateDistributer:Loop processing acknowledgment %s", stateDistributionID)

					delete(sd.pendingMap, stateDistributionID)
				} else {
					log.L(ctx).Debugf("stateDistributer:Loop already recieved acknowledgment %s", stateDistributionID)

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
	log.L(ctx).Debugf("stateDistributer:sendState %s", stateDistribution.ID)

	stateProducedEvent := &pb.StateProducedEvent{
		DomainName:      stateDistribution.Domain,
		ContractAddress: stateDistribution.ContractAddress,
		SchemaId:        stateDistribution.SchemaID,
		StateId:         stateDistribution.StateID,
		StateDataJson:   stateDistribution.StateDataJson,
		Party:           stateDistribution.IdentityLocator,
		DistributionId:  stateDistribution.ID,
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
		Destination: tktypes.PrivateIdentityLocator(fmt.Sprintf("%s@%s", STATE_DISTRIBUTER_DESTINATION, targetNode)),
		ReplyTo:     tktypes.PrivateIdentityLocator(fmt.Sprintf("%s@%s", STATE_DISTRIBUTER_DESTINATION, sd.nodeID)),
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

func (sd *stateDistributer) sendStateAcknowledgement(ctx context.Context, domainName string, contractAddress string, stateId string, receivingParty string, distributingNode string, distributionID string) error {
	log.L(ctx).Debugf("stateDistributer:sendStateAcknowledgement %s %s %s %s %s %s", domainName, contractAddress, stateId, receivingParty, distributingNode, distributionID)
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
		Destination: tktypes.PrivateIdentityLocator(fmt.Sprintf("%s@%s", STATE_DISTRIBUTER_DESTINATION, distributingNode)),
		ReplyTo:     tktypes.PrivateIdentityLocator(fmt.Sprintf("%s@%s", STATE_DISTRIBUTER_DESTINATION, sd.nodeID)),
	})
	if err != nil {
		log.L(ctx).Errorf("Error sending state produced event: %s", err)
		return err
	}

	return nil
}

func (sd *stateDistributer) Destination() string {
	return STATE_DISTRIBUTER_DESTINATION
}

func (sd *stateDistributer) ReceiveTransportMessage(ctx context.Context, message *components.TransportMessage) {
	log.L(ctx).Debugf("stateDistributer:ReceiveTransportMessage")
	messagePayload := message.Payload
	replyToDestination := message.ReplyTo

	switch message.MessageType {
	case "StateProducedEvent":
		//Not sure this message really needs to come into the private tx manager, just to be forwarded to the state store.
		distributingNode, err := replyToDestination.Node(ctx, false)
		if err != nil {
			log.L(ctx).Errorf("Error getting node for party %s", replyToDestination)
			return
		}
		go sd.handleStateProducedEvent(ctx, messagePayload, distributingNode)
	case "StateAcknowledgedEvent":
		go sd.handleStateAcknowledgedEvent(ctx, message.Payload)
	default:
		log.L(ctx).Errorf("Unknown message type: %s", message.MessageType)
	}
}

func (sd *stateDistributer) handleStateProducedEvent(ctx context.Context, messagePayload []byte, distributingNode string) {
	log.L(ctx).Debugf("stateDistributer:handleStateProducedEvent")
	stateProducedEvent := &pb.StateProducedEvent{}
	err := proto.Unmarshal(messagePayload, stateProducedEvent)
	if err != nil {
		log.L(ctx).Errorf("Failed to unmarshal StateProducedEvent: %s", err)
		return
	}

	//TODO use a flush writer to batch these up and write them to the state store

	_, err = sd.stateManager.WriteReceivedStates(ctx, sd.persistence.DB(), stateProducedEvent.DomainName, []*components.StateUpsertOutsideContext{
		{
			ContractAddress: *tktypes.MustEthAddress(stateProducedEvent.ContractAddress),
			SchemaID:        tktypes.MustParseBytes32(stateProducedEvent.SchemaId),
			Data:            tktypes.RawJSON(stateProducedEvent.StateDataJson),
		},
	})
	if err != nil {
		log.L(ctx).Errorf("Error writing state: %s", err)
		//don't send the acknowledgement, with a bit of luck, the sender will retry and we will get it next time
		return
	}

	// No error means either this is the first time we have received this state or we already have it an onConflict ignore means we idempotently accept it
	// If the latter, then the sender probably didn't get our previous acknowledgement so either way, we send an acknowledgement

	err = sd.sendStateAcknowledgement(
		ctx,
		stateProducedEvent.DomainName,
		stateProducedEvent.ContractAddress,
		stateProducedEvent.StateId,
		stateProducedEvent.Party,
		distributingNode,
		stateProducedEvent.DistributionId)
	if err != nil {
		log.L(ctx).Errorf("Error sending state acknowledgement: %s", err)
		//not much more we can do here.  The sender will inevitably retry and we will hopefully send the ack next time
	}
}

func (sd *stateDistributer) handleStateAcknowledgedEvent(ctx context.Context, messagePayload []byte) {
	log.L(ctx).Debugf("stateDistributer:handleStateAcknowledgedEvent")
	stateAcknowledgedEvent := &pb.StateAcknowledgedEvent{}
	err := proto.Unmarshal(messagePayload, stateAcknowledgedEvent)
	if err != nil {
		log.L(ctx).Errorf("Failed to unmarshal StateAcknowledgedEvent: %s", err)
		return
	}
	sd.acknowledgementWriter.Queue(ctx, stateAcknowledgedEvent.DistributionId)
	// no need to wait for the flush to complete, we can just stop the in memory loop from retrying
	// worst case scenario, we crash before this is written to the DB, we do some redundant retries after a restart
	// but waiting for the flush here is not going to prevent that
	sd.acknowledgedChan <- stateAcknowledgedEvent.DistributionId

}
