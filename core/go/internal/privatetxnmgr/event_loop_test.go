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
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/kaleido-io/paladin/core/internal/components"
	"github.com/kaleido-io/paladin/core/internal/privatetxnmgr/ptmgrtypes"
	"github.com/kaleido-io/paladin/core/mocks/componentmocks"
	"github.com/kaleido-io/paladin/core/mocks/privatetxnmgrmocks"
	"github.com/kaleido-io/paladin/core/pkg/persistence"
	"github.com/kaleido-io/paladin/toolkit/pkg/tktypes"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

type orchestratorDepencyMocks struct {
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

func newOrchestratorForTesting(t *testing.T, ctx context.Context, domainAddress *tktypes.EthAddress) (*Orchestrator, *orchestratorDepencyMocks, <-chan struct{}) {
	if domainAddress == nil {
		domainAddress = tktypes.MustEthAddress(tktypes.RandHex(20))
	}

	mocks := &orchestratorDepencyMocks{
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
	mocks.domainMgr.On("GetSmartContractByAddress", mock.Anything, *domainAddress).Maybe().Return(mocks.domainSmartContract, nil)
	mocks.sequencer.On("SetDispatcher", mock.Anything).Maybe().Return()
	mocks.allComponents.On("Persistence").Return(persistence.NewUnitTestPersistence(ctx)).Maybe()

	o := NewOrchestrator(ctx, tktypes.RandHex(16), domainAddress.String(), &OrchestratorConfig{}, mocks.allComponents, mocks.domainSmartContract, mocks.sequencer, mocks.endorsementGatherer, mocks.publisher)
	ocDone, err := o.Start(ctx)
	require.NoError(t, err)

	return o, mocks, ocDone

}

func TestNewOrchestratorProcessNewTransaction(t *testing.T) {
	ctx := context.Background()

	testOc, dependencyMocks, _ := newOrchestratorForTesting(t, ctx, nil)

	newTxID := uuid.New()
	testTx := &components.PrivateTransaction{
		ID: newTxID,
	}

	waitForAssemble := make(chan bool, 1)
	dependencyMocks.domainSmartContract.On("AssembleTransaction", mock.Anything, mock.Anything).Return(errors.New("fail assembly. Just happy that we got this far")).Run(func(args mock.Arguments) {
		waitForAssemble <- true
	})

	assert.Empty(t, testOc.incompleteTxSProcessMap)

	// when incomplete tx is more than max concurrent
	testOc.maxConcurrentProcess = 0
	assert.True(t, testOc.ProcessNewTransaction(ctx, testTx))

	// gets add when the queue is not full
	testOc.maxConcurrentProcess = 10
	assert.Empty(t, testOc.incompleteTxSProcessMap)
	assert.False(t, testOc.ProcessNewTransaction(ctx, testTx))
	assert.Equal(t, 1, len(testOc.incompleteTxSProcessMap))

	<-waitForAssemble

	// add again doesn't cause a repeat process of the current stage context
	assert.False(t, testOc.ProcessNewTransaction(ctx, testTx))
	assert.Equal(t, 1, len(testOc.incompleteTxSProcessMap))

}

func TestOrchestratorHandleEvents(t *testing.T) {
	newTxID := uuid.New()
	tests := []struct {
		name        string
		handlerName string
		event       ptmgrtypes.PrivateTransactionEvent
	}{
		{
			name:        "TransactionSubmittedEvent",
			handlerName: "HandleTransactionSubmittedEvent",
			event: &ptmgrtypes.TransactionSubmittedEvent{
				PrivateTransactionEventBase: ptmgrtypes.PrivateTransactionEventBase{TransactionID: newTxID.String()},
			},
		},
		{
			name:        "TransactionSignedEvent",
			handlerName: "HandleTransactionSignedEvent",
			event: &ptmgrtypes.TransactionSignedEvent{
				PrivateTransactionEventBase: ptmgrtypes.PrivateTransactionEventBase{TransactionID: newTxID.String()},
			},
		},
		{
			name:        "TransactionEndorsedEvent",
			handlerName: "HandleTransactionEndorsedEvent",
			event: &ptmgrtypes.TransactionEndorsedEvent{
				PrivateTransactionEventBase: ptmgrtypes.PrivateTransactionEventBase{TransactionID: newTxID.String()},
			},
		},
		{
			name:        "TransactionDispatchedEvent",
			handlerName: "HandleTransactionDispatchedEvent",
			event: &ptmgrtypes.TransactionDispatchedEvent{
				PrivateTransactionEventBase: ptmgrtypes.PrivateTransactionEventBase{TransactionID: newTxID.String()},
			},
		},
		{
			name:        "TransactionConfirmedEvent",
			handlerName: "HandleTransactionConfirmedEvent",
			event: &ptmgrtypes.TransactionConfirmedEvent{
				PrivateTransactionEventBase: ptmgrtypes.PrivateTransactionEventBase{TransactionID: newTxID.String()},
			},
		},
		{
			name:        "TransactionRevertedEvent",
			handlerName: "HandleTransactionRevertedEvent",
			event: &ptmgrtypes.TransactionRevertedEvent{
				PrivateTransactionEventBase: ptmgrtypes.PrivateTransactionEventBase{TransactionID: newTxID.String()},
			},
		},
		{
			name:        "TransactionDelegatedEvent",
			handlerName: "HandleTransactionDelegatedEvent",
			event: &ptmgrtypes.TransactionDelegatedEvent{
				PrivateTransactionEventBase: ptmgrtypes.PrivateTransactionEventBase{TransactionID: newTxID.String()},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {

			ctx := context.Background()
			testOc, _, _ := newOrchestratorForTesting(t, ctx, nil)

			waitForAction := make(chan bool, 1)

			//Emulate ProcessNewTransaction with a mockTxProcessor
			mockTxProcessor := privatetxnmgrmocks.NewTxProcessor(t)
			mockTxProcessor.On("GetStatus", mock.Anything).Return(ptmgrtypes.TxProcessorActive)
			mockTxProcessor.On(tt.handlerName, mock.Anything, tt.event).Run(func(args mock.Arguments) {
				waitForAction <- true
			}).Return()

			testOc.incompleteTxSProcessMap[newTxID.String()] = mockTxProcessor
			testOc.pendingEvents <- tt.event

			select {
			case <-waitForAction:
				// Handle the action
			case <-time.After(1 * time.Second):
				t.Fatal("Timeout waiting for action")
			}
			mockTxProcessor.AssertExpectations(t)
		})
	}

}

func TestOrchestratorPollingLoopStop(t *testing.T) {

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	testOc, _, ocDone := newOrchestratorForTesting(t, ctx, nil)
	testOc.TriggerOrchestratorEvaluation()
	testOc.Stop()
	<-ocDone
}

func TestOrchestratorPollingLoopCancelContext(t *testing.T) {

	ctx, cancel := context.WithCancel(context.Background())
	_, _, ocDone := newOrchestratorForTesting(t, ctx, nil)

	cancel()
	<-ocDone
}
