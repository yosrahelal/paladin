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
	"time"

	"github.com/google/uuid"
	"github.com/hyperledger/firefly-common/pkg/i18n"
	"github.com/kaleido-io/paladin/core/internal/components"
	"github.com/kaleido-io/paladin/core/internal/msgs"
	"github.com/kaleido-io/paladin/core/internal/privatetxnmgr/ptmgrtypes"
	"github.com/kaleido-io/paladin/core/internal/privatetxnmgr/syncpoints"
	"github.com/kaleido-io/paladin/core/internal/statedistribution"

	"github.com/kaleido-io/paladin/toolkit/pkg/log"
	"github.com/kaleido-io/paladin/toolkit/pkg/prototk"
	"github.com/kaleido-io/paladin/toolkit/pkg/tktypes"
)

func NewTransactionFlow(ctx context.Context, transaction *components.PrivateTransaction, nodeID string, components components.AllComponents, domainAPI components.DomainSmartContract, publisher ptmgrtypes.Publisher, endorsementGatherer ptmgrtypes.EndorsementGatherer, identityResolver components.IdentityResolver, syncPoints syncpoints.SyncPoints, transportWriter ptmgrtypes.TransportWriter, requestTimeout time.Duration) ptmgrtypes.TransactionFlow {
	return &transactionFlow{
		stageErrorRetry:             10 * time.Second,
		domainAPI:                   domainAPI,
		nodeID:                      nodeID,
		components:                  components,
		publisher:                   publisher,
		endorsementGatherer:         endorsementGatherer,
		transaction:                 transaction,
		status:                      "new",
		identityResolver:            identityResolver,
		syncPoints:                  syncPoints,
		transportWriter:             transportWriter,
		finalizeRequired:            false,
		finalizePending:             false,
		requestedVerifierResolution: false,
		requestedSignatures:         false,
		requestedEndorsementTimes:   make(map[string]map[string]time.Time),
		complete:                    false,
		localCoordinator:            true,
		readyForSequencing:          false,
		dispatched:                  false,
		clock:                       ptmgrtypes.RealClock(),
		requestTimeout:              requestTimeout,
	}
}

type transactionFlow struct {
	stageErrorRetry             time.Duration
	components                  components.AllComponents
	nodeID                      string
	domainAPI                   components.DomainSmartContract
	transaction                 *components.PrivateTransaction
	publisher                   ptmgrtypes.Publisher
	endorsementGatherer         ptmgrtypes.EndorsementGatherer
	status                      string
	latestEvent                 string
	latestError                 string
	identityResolver            components.IdentityResolver
	syncPoints                  syncpoints.SyncPoints
	transportWriter             ptmgrtypes.TransportWriter
	finalizeRevertReason        string
	finalizeRequired            bool
	finalizePending             bool
	complete                    bool
	requestedVerifierResolution bool                            //TODO add precision here so that we can track individual requests and implement retry as per endorsement
	requestedSignatures         bool                            //TODO add precision here so that we can track individual requests and implement retry as per endorsement
	requestedEndorsementTimes   map[string]map[string]time.Time //map of attestationRequest names to a map of parties to the time the most request was made
	localCoordinator            bool
	readyForSequencing          bool
	dispatched                  bool
	clock                       ptmgrtypes.Clock
	requestTimeout              time.Duration
}

func (tf *transactionFlow) GetTxStatus(ctx context.Context) (components.PrivateTxStatus, error) {
	return components.PrivateTxStatus{
		TxID:        tf.transaction.ID.String(),
		Status:      tf.status,
		LatestEvent: tf.latestEvent,
		LatestError: tf.latestError,
	}, nil
}

func (tf *transactionFlow) IsComplete() bool {
	return tf.complete
}

func (tf *transactionFlow) ReadyForSequencing() bool {
	return tf.readyForSequencing
}

func (tf *transactionFlow) Dispatched() bool {
	return tf.dispatched
}

func (tf *transactionFlow) IsEndorsed(ctx context.Context) bool {
	return !tf.hasOutstandingEndorsementRequests(ctx)
}

func (tf *transactionFlow) CoordinatingLocally() bool {
	return tf.localCoordinator
}

func (tf *transactionFlow) PrepareTransaction(ctx context.Context, defaultSigner string) (*components.PrivateTransaction, error) {

	if tf.transaction.Signer == "" {
		log.L(ctx).Infof("Using random signing key from sequencer to prepare transaction: %s", defaultSigner)
		tf.transaction.Signer = defaultSigner
	}

	readTX := tf.components.Persistence().DB() // no DB transaction required here
	prepError := tf.domainAPI.PrepareTransaction(tf.endorsementGatherer.DomainContext(), readTX, tf.transaction)
	if prepError != nil {
		log.L(ctx).Errorf("Error preparing transaction: %s", prepError)
		tf.latestError = i18n.ExpandWithCode(ctx, i18n.MessageKey(msgs.MsgPrivateTxManagerPrepareError), prepError.Error())
		return nil, prepError
	}
	return tf.transaction, nil
}

func toEndorsableList(states []*components.FullState) []*prototk.EndorsableState {
	endorsableList := make([]*prototk.EndorsableState, len(states))
	for i, input := range states {
		endorsableList[i] = &prototk.EndorsableState{
			Id:            input.ID.String(),
			SchemaId:      input.Schema.String(),
			StateDataJson: string(input.Data),
		}
	}
	return endorsableList
}

func (tf *transactionFlow) GetStateDistributions(ctx context.Context) []*statedistribution.StateDistribution {
	log.L(ctx).Debug("transactionFlow:GetStateDistributions")

	stateDistributions := make([]*statedistribution.StateDistribution, 0)
	if tf.transaction.PostAssembly == nil {
		log.L(ctx).Error("PostAssembly is nil")
		return stateDistributions
	}
	if tf.transaction.PostAssembly.OutputStates == nil {
		log.L(ctx).Debug("OutputStates is nil")
		return stateDistributions
	}

	type stateAndDistributionList struct {
		State            *components.FullState
		DistributionList []string
	}

	//need the output state for the state ID and need the outputStatePotential for the distribution list
	statesToDistribute := make([]stateAndDistributionList, 0, len(tf.transaction.PostAssembly.OutputStates)+len(tf.transaction.PostAssembly.OutputStates))
	for stateIndex, outputState := range tf.transaction.PostAssembly.OutputStates {
		statePotential := tf.transaction.PostAssembly.OutputStatesPotential[stateIndex]
		statesToDistribute = append(statesToDistribute, stateAndDistributionList{outputState, statePotential.DistributionList})
	}
	for stateIndex, infoState := range tf.transaction.PostAssembly.InfoStates {
		statePotential := tf.transaction.PostAssembly.InfoStatesPotential[stateIndex]
		statesToDistribute = append(statesToDistribute, stateAndDistributionList{infoState, statePotential.DistributionList})
	}

	for _, s := range statesToDistribute {
		// We don't need to send to our local node
		localNodeName := tf.components.TransportManager().LocalNodeName()
		for _, party := range s.DistributionList {
			nodeName, err := tktypes.PrivateIdentityLocator(party).Node(ctx, true)
			if err != nil || nodeName == "" || nodeName == localNodeName {
				log.L(ctx).Debugf("skipping unnecessary state distribution party='%s' nodeName='%s' localNodeName='%s'", party, nodeName, localNodeName)
				continue
			}

			stateDistributions = append(stateDistributions, &statedistribution.StateDistribution{
				ID:              uuid.New().String(),
				StateID:         s.State.ID.String(),
				IdentityLocator: party,
				Domain:          tf.domainAPI.Domain().Name(),
				ContractAddress: tf.transaction.Inputs.To.String(),
				SchemaID:        s.State.Schema.String(),
				StateDataJson:   string(s.State.Data), // the state data json is available on both but we take it
				// from the outputState to make sure it is the same json that was used to generate the hash
			})
		}
	}
	return stateDistributions
}

func (tf *transactionFlow) InputStateIDs() []string {

	inputStateIDs := make([]string, len(tf.transaction.PostAssembly.InputStates))
	for i, inputState := range tf.transaction.PostAssembly.InputStates {
		inputStateIDs[i] = inputState.ID.String()
	}
	return inputStateIDs
}

func (tf *transactionFlow) OutputStateIDs() []string {

	//We use the output states here not the OutputStatesPotential because it is not possible for another transaction
	// to spend a state unless it has been written to the state store and at that point we have the state ID
	outputStateIDs := make([]string, len(tf.transaction.PostAssembly.OutputStates))
	for i, outputState := range tf.transaction.PostAssembly.OutputStates {
		outputStateIDs[i] = outputState.ID.String()
	}
	return outputStateIDs
}

func (tf *transactionFlow) Signer() string {

	return tf.transaction.Signer
}

func (tf *transactionFlow) ID() uuid.UUID {

	return tf.transaction.ID
}
