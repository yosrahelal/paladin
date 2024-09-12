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
	"time"

	"github.com/google/uuid"
	"github.com/kaleido-io/paladin/core/internal/components"
	"github.com/kaleido-io/paladin/core/internal/privatetxnmgr/ptmgrtypes"
	"github.com/kaleido-io/paladin/core/mocks/componentmocks"
	"github.com/kaleido-io/paladin/core/mocks/privatetxnmgrmocks"
	"github.com/kaleido-io/paladin/core/pkg/proto/sequence"
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
	emitEvent            EmitEvent
}

func newOrchestratorForTesting(t *testing.T, ctx context.Context, domainAddress *tktypes.EthAddress) (*Orchestrator, *orchestratorDepencyMocks) {
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
		emitEvent:            func(ctx context.Context, event ptmgrtypes.PrivateTransactionEvent) {},
	}
	mocks.allComponents.On("StateStore").Return(mocks.stateStore).Maybe()
	mocks.allComponents.On("DomainManager").Return(mocks.domainMgr).Maybe()
	mocks.allComponents.On("TransportManager").Return(mocks.transportManager).Maybe()
	mocks.allComponents.On("KeyManager").Return(mocks.keyManager).Maybe()
	mocks.domainMgr.On("GetSmartContractByAddress", mock.Anything, *domainAddress).Maybe().Return(mocks.domainSmartContract, nil)

	o := NewOrchestrator(ctx, tktypes.RandHex(16), domainAddress.String(), &OrchestratorConfig{}, mocks.allComponents, mocks.domainSmartContract, mocks.sequencer, mocks.endorsementGatherer, mocks.publisher)

	return o, mocks

}

func TestNewOrchestratorProcessNewTransaction(t *testing.T) {
	ctx := context.Background()

	testOc, _ := newOrchestratorForTesting(t, ctx, nil)
	newTxID := uuid.New()
	testTx := &components.PrivateTransaction{
		ID: newTxID,
	}

	waitForAction := make(chan bool, 1)

	assert.Empty(t, testOc.incompleteTxSProcessMap)

	// when incomplete tx is more than max concurrent
	testOc.maxConcurrentProcess = 0
	assert.True(t, testOc.ProcessNewTransaction(ctx, testTx))

	// gets add when the queue is not full
	testOc.maxConcurrentProcess = 10
	assert.Empty(t, testOc.incompleteTxSProcessMap)
	assert.False(t, testOc.ProcessNewTransaction(ctx, testTx))
	assert.Equal(t, 1, len(testOc.incompleteTxSProcessMap))

	stageContext := testOc.incompleteTxSProcessMap[testTx.ID.String()].GetStageContext(ctx)
	<-waitForAction // no events emitted as no synchronous output was returned
	assert.NotNil(t, stageContext)

	// add again doesn't cause a repeat process of the current stage context
	assert.False(t, testOc.ProcessNewTransaction(ctx, testTx))
	assert.Equal(t, 1, len(testOc.incompleteTxSProcessMap))

	newStageContext := testOc.incompleteTxSProcessMap[testTx.ID.String()].GetStageContext(ctx)
	assert.Equal(t, stageContext, newStageContext)
}

func TestOrchestratorHandleEvents(t *testing.T) {
	ctx := context.Background()
	testOc, _ := newOrchestratorForTesting(t, ctx, nil)
	newTxID := uuid.New()
	testTx := &components.PrivateTransaction{
		ID: newTxID,
	}

	waitForAction := make(chan bool, 1)

	assert.Empty(t, testOc.incompleteTxSProcessMap)

	// gets added when the queue is not full
	testOc.maxConcurrentProcess = 1
	assert.Empty(t, testOc.incompleteTxSProcessMap)
	assert.False(t, testOc.ProcessNewTransaction(ctx, testTx))
	assert.Equal(t, 1, len(testOc.incompleteTxSProcessMap))

	stageContext := testOc.incompleteTxSProcessMap[testTx.ID.String()].GetStageContext(ctx)
	<-waitForAction // no events emitted as no synchronous output was returned
	assert.NotNil(t, stageContext)

	waitForProcessEvent := make(chan bool, 1)
	// feed in an event for process
	testOc.HandleEvent(ctx, &TransactionAssembledEvent{
		privateTransactionEvent: privateTransactionEvent{
			transactionID:   testTx.ID.String(),
			contractAddress: "test",
		},
		TransactionAssembledEvent: sequence.TransactionAssembledEvent{
			TransactionId: testTx.ID.String(),
		},
	})
	<-waitForProcessEvent
	newStageContext := testOc.incompleteTxSProcessMap[testTx.ID.String()].GetStageContext(ctx)
	assert.Equal(t, stageContext, newStageContext)

	delete(testOc.incompleteTxSProcessMap, testTx.ID.String()) // clean up the queue
	assert.Empty(t, testOc.incompleteTxSProcessMap)

	// trigger again which should initiate the tx processor
	testOc.HandleEvent(ctx, &TransactionAssembledEvent{
		privateTransactionEvent: privateTransactionEvent{
			transactionID:   testTx.ID.String(),
			contractAddress: "test",
		},
		TransactionAssembledEvent: sequence.TransactionAssembledEvent{
			TransactionId: testTx.ID.String(),
		},
	})
	<-waitForProcessEvent
	newStageContext = testOc.incompleteTxSProcessMap[testTx.ID.String()].GetStageContext(ctx)
	assert.NotEqual(t, stageContext, newStageContext)

}

func TestOrchestratorPollingLoopStop(t *testing.T) {

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	testOc, _ := newOrchestratorForTesting(t, ctx, nil)
	ocDone, err := testOc.Start(ctx)
	require.NoError(t, err)
	testOc.TriggerOrchestratorEvaluation()
	testOc.Stop()
	<-ocDone
}

func TestOrchestratorPollingLoopCancelContext(t *testing.T) {

	ctx, cancel := context.WithCancel(context.Background())
	testOc, _ := newOrchestratorForTesting(t, ctx, nil)

	cancel()
	ocDone, err := testOc.Start(ctx)
	require.NoError(t, err)
	<-ocDone
}

func TestOrchestratorPollingLoopRemoveCompletedTx(t *testing.T) {

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	newTxID := uuid.New()
	testTx := &components.PrivateTransaction{
		ID: newTxID,
	}
	testOc, _ := newOrchestratorForTesting(t, ctx, nil)

	ocDone, err := testOc.Start(ctx)
	require.NoError(t, err)
	waitForAction := make(chan bool, 1)
	// gets add when the queue is not full
	testOc.maxConcurrentProcess = 10
	assert.Empty(t, testOc.incompleteTxSProcessMap)
	assert.False(t, testOc.ProcessNewTransaction(ctx, testTx))
	<-waitForAction                        // no events emitted as no synchronous output was returned
	testOc.TriggerOrchestratorEvaluation() // this should remove the process from the pool
	//workaround timing condition
	time.Sleep(100 * time.Millisecond)
	testOc.Stop()
	testOc.Stop() // do a second stop to ensure at least one stop has gone through as the channel has buffer size 1
	<-ocDone
	assert.Empty(t, testOc.incompleteTxSProcessMap)
	assert.Equal(t, 1, int(testOc.totalCompleted))
}
