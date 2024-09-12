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
	"testing"

	"github.com/google/uuid"
	"github.com/kaleido-io/paladin/core/internal/components"
	"github.com/kaleido-io/paladin/core/mocks/componentmocks"
	"github.com/kaleido-io/paladin/core/mocks/privatetxnmgrmocks"
	"github.com/kaleido-io/paladin/toolkit/pkg/tktypes"
)

type transactionProcessorDepencyMocks struct {
	allComponents        *componentmocks.AllComponents
	domainStateInterface *componentmocks.DomainStateInterface
	domainSmartContract  *componentmocks.DomainSmartContract
	domainMgr            *componentmocks.DomainManager
	transportManager     *componentmocks.TransportManager
	stateStore           *componentmocks.StateStore
	keyManager           *componentmocks.KeyManager
	sequencer            *privatetxnmgrmocks.Sequencer
	endorsementGatherer  *privatetxnmgrmocks.EndorsementGatherer
	publisher            *privatetxnmgrmocks.Publisher
}

func newPaladinTransactionProcessorForTesting(t *testing.T, ctx context.Context, transaction *components.PrivateTransaction) (*PaladinTxProcessor, *transactionProcessorDepencyMocks) {

	mocks := &transactionProcessorDepencyMocks{
		allComponents:        componentmocks.NewAllComponents(t),
		domainStateInterface: componentmocks.NewDomainStateInterface(t),
		domainSmartContract:  componentmocks.NewDomainSmartContract(t),
		domainMgr:            componentmocks.NewDomainManager(t),
		transportManager:     componentmocks.NewTransportManager(t),
		stateStore:           componentmocks.NewStateStore(t),
		keyManager:           componentmocks.NewKeyManager(t),
		sequencer:            privatetxnmgrmocks.NewSequencer(t),
		endorsementGatherer:  privatetxnmgrmocks.NewEndorsementGatherer(t),
		publisher:            privatetxnmgrmocks.NewPublisher(t),
	}
	mocks.allComponents.On("StateStore").Return(mocks.stateStore).Maybe()
	mocks.allComponents.On("DomainManager").Return(mocks.domainMgr).Maybe()
	mocks.allComponents.On("TransportManager").Return(mocks.transportManager).Maybe()
	mocks.allComponents.On("KeyManager").Return(mocks.keyManager).Maybe()

	tp := NewPaladinTransactionProcessor(ctx, transaction, tktypes.RandHex(16), mocks.allComponents, mocks.domainSmartContract, mocks.sequencer, mocks.publisher, mocks.endorsementGatherer)

	return tp.(*PaladinTxProcessor), mocks
}

func TestTransactionProcessor(t *testing.T) {
	ctx := context.Background()
	newTxID := uuid.New()
	testTx := &components.PrivateTransaction{
		ID: newTxID,
	}
	tp, _ := newPaladinTransactionProcessorForTesting(t, ctx, testTx)
	tp.stageController = newTestStageController(ctx)
	//assert.Nil(t, tp.GetStageContext(ctx))
	//assert.Nil(t, tp.GetStageTriggerError(ctx))
}
