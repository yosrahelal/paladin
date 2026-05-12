/*
 * Copyright © 2025 Kaleido, Inc.
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

package coordinator

import (
	"context"
	"testing"

	"github.com/LFDT-Paladin/paladin/config/pkg/confutil"
	"github.com/LFDT-Paladin/paladin/config/pkg/pldconf"
	"github.com/LFDT-Paladin/paladin/core/internal/sequencer/common"
	"github.com/LFDT-Paladin/paladin/core/internal/sequencer/coordinator/grapher"
	"github.com/LFDT-Paladin/paladin/core/internal/sequencer/coordinator/transaction"
	"github.com/LFDT-Paladin/paladin/core/internal/sequencer/metrics"
	"github.com/LFDT-Paladin/paladin/core/internal/sequencer/testutil"
	"github.com/LFDT-Paladin/paladin/core/internal/sequencer/transport"
	"github.com/LFDT-Paladin/paladin/core/mocks/componentsmocks"
	"github.com/LFDT-Paladin/paladin/core/mocks/sequencercommonmocks"
	"github.com/LFDT-Paladin/paladin/core/mocks/sequencertransportmocks"
	"github.com/LFDT-Paladin/paladin/core/mocks/syncpointsmocks"
	"github.com/LFDT-Paladin/paladin/core/pkg/persistence/mockpersistence"
	"github.com/LFDT-Paladin/paladin/sdk/go/pkg/pldtypes"
	"github.com/LFDT-Paladin/paladin/toolkit/pkg/prototk"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/mock"
)

type CoordinatorBuilderForTesting struct {
	t                                        *testing.T
	state                                    State
	domainAPI                                *componentsmocks.DomainSmartContract
	txManager                                *componentsmocks.TXManager
	sequencerManager                         *componentsmocks.SequencerManager
	contractAddress                          *pldtypes.EthAddress
	contractConfig                           *prototk.ContractConfig
	currentBlockHeight                       *uint64
	transactions                             []transaction.CoordinatorTransaction
	pooledTransactions                       []transaction.CoordinatorTransaction
	coordinatorEndorserPool                  []string
	heartbeatsUntilClosingGracePeriodExpires *int
	metrics                                  metrics.DistributedSequencerMetrics
	sequencerConfig                          *pldconf.SequencerConfig
	originatorNodePool                       *[]string
	preferredActiveCoordinator               *string
	currentActiveCoordinator                 *string
	previousActiveCoordinatorNode            *string
	newBlockRangeEpoch                       *bool
	localNodeName                            string
	heartbeatIntervalsSinceLastReceive       *int
	inactiveGracePeriod                      *int
	heartbeatIntervalsSinceStateChange       *int
	activeCoordinatorState                   *State
	useMockTransportWriter                   bool
	grapher                                  grapher.Grapher
}

type CoordinatorDependencyMocks struct {
	SentMessageRecorder *testutil.SentMessageRecorder
	EngineIntegration   *sequencercommonmocks.EngineIntegration
	SyncPoints          *syncpointsmocks.SyncPoints
	TransportWriter     *sequencertransportmocks.TransportWriter
}

// copySequencerDefaultsForTest returns a deep copy of SequencerDefaults so tests that mutate
// config (e.g. GetSequencerConfig().MaxDispatchAhead = ...) do not affect later tests.
func copySequencerDefaultsForTest() *pldconf.SequencerConfig {
	def := &pldconf.SequencerDefaults
	copy := &pldconf.SequencerConfig{
		Writer: pldconf.FlushWriterConfig{},
	}
	if def.StateTimeout != nil {
		v := *def.StateTimeout
		copy.StateTimeout = &v
	}
	if def.RequestTimeout != nil {
		v := *def.RequestTimeout
		copy.RequestTimeout = &v
	}
	if def.BlockHeightTolerance != nil {
		v := *def.BlockHeightTolerance
		copy.BlockHeightTolerance = &v
	}
	if def.BlockRange != nil {
		v := *def.BlockRange
		copy.BlockRange = &v
	}
	if def.CoordinatorEventQueueSize != nil {
		v := *def.CoordinatorEventQueueSize
		copy.CoordinatorEventQueueSize = &v
	}
	if def.CoordinatorPriorityEventQueueSize != nil {
		v := *def.CoordinatorPriorityEventQueueSize
		copy.CoordinatorPriorityEventQueueSize = &v
	}
	if def.OriginatorEventQueueSize != nil {
		v := *def.OriginatorEventQueueSize
		copy.OriginatorEventQueueSize = &v
	}
	if def.OriginatorPriorityEventQueueSize != nil {
		v := *def.OriginatorPriorityEventQueueSize
		copy.OriginatorPriorityEventQueueSize = &v
	}
	if def.ClosingGracePeriod != nil {
		v := *def.ClosingGracePeriod
		copy.ClosingGracePeriod = &v
	}
	if def.HeartbeatInterval != nil {
		v := *def.HeartbeatInterval
		copy.HeartbeatInterval = &v
	}
	if def.MaxInflightTransactions != nil {
		v := *def.MaxInflightTransactions
		copy.MaxInflightTransactions = &v
	}
	if def.MaxDispatchAhead != nil {
		v := *def.MaxDispatchAhead
		copy.MaxDispatchAhead = &v
	}
	if def.TargetActiveSequencers != nil {
		v := *def.TargetActiveSequencers
		copy.TargetActiveSequencers = &v
	}
	if def.TransactionResumePollInterval != nil {
		v := *def.TransactionResumePollInterval
		copy.TransactionResumePollInterval = &v
	}
	if def.Writer.WorkerCount != nil {
		v := *def.Writer.WorkerCount
		copy.Writer.WorkerCount = &v
	}
	if def.Writer.BatchTimeout != nil {
		v := *def.Writer.BatchTimeout
		copy.Writer.BatchTimeout = &v
	}
	if def.Writer.BatchMaxSize != nil {
		v := *def.Writer.BatchMaxSize
		copy.Writer.BatchMaxSize = &v
	}
	return copy
}

func NewCoordinatorBuilderForTesting(t *testing.T, state State) *CoordinatorBuilderForTesting {

	domainAPI := componentsmocks.NewDomainSmartContract(t)
	txManager := componentsmocks.NewTXManager(t)
	sequencerManager := componentsmocks.NewSequencerManager(t)
	return &CoordinatorBuilderForTesting{
		t:                t,
		state:            state,
		domainAPI:        domainAPI,
		txManager:        txManager,
		sequencerManager: sequencerManager,
		metrics:          metrics.InitMetrics(context.Background(), prometheus.NewRegistry()),
		sequencerConfig:  copySequencerDefaultsForTest(),
	}
}

func (b *CoordinatorBuilderForTesting) ContractAddress(contractAddress *pldtypes.EthAddress) *CoordinatorBuilderForTesting {
	b.contractAddress = contractAddress
	return b
}

func (b *CoordinatorBuilderForTesting) GetContractAddress() pldtypes.EthAddress {
	return *b.contractAddress
}

func (b *CoordinatorBuilderForTesting) CurrentBlockHeight(currentBlockHeight uint64) *CoordinatorBuilderForTesting {
	b.currentBlockHeight = &currentBlockHeight
	return b
}

func (b *CoordinatorBuilderForTesting) Transactions(transactions ...transaction.CoordinatorTransaction) *CoordinatorBuilderForTesting {
	b.transactions = transactions
	return b
}

func (b *CoordinatorBuilderForTesting) PooledTransactions(transactions ...transaction.CoordinatorTransaction) *CoordinatorBuilderForTesting {
	b.pooledTransactions = transactions
	return b
}

func (b *CoordinatorBuilderForTesting) CoordinatorEndorserPool(nodes ...string) *CoordinatorBuilderForTesting {
	b.coordinatorEndorserPool = nodes
	return b
}

func (b *CoordinatorBuilderForTesting) GetDomainAPI() *componentsmocks.DomainSmartContract {
	return b.domainAPI
}

func (b *CoordinatorBuilderForTesting) GetTXManager() *componentsmocks.TXManager {
	return b.txManager
}

func (b *CoordinatorBuilderForTesting) GetSequencerManager() *componentsmocks.SequencerManager {
	return b.sequencerManager
}

func (b *CoordinatorBuilderForTesting) GetSequencerConfig() *pldconf.SequencerConfig {
	return b.sequencerConfig
}

func (b *CoordinatorBuilderForTesting) OverrideSequencerConfig(config *pldconf.SequencerConfig) *CoordinatorBuilderForTesting {
	b.sequencerConfig = config
	return b
}

func (b *CoordinatorBuilderForTesting) OriginatorNodePool(nodes ...string) *CoordinatorBuilderForTesting {
	b.originatorNodePool = &nodes
	return b
}

func (b *CoordinatorBuilderForTesting) DomainContractConfig(cfg *prototk.ContractConfig) *CoordinatorBuilderForTesting {
	b.contractConfig = cfg
	return b
}

func (b *CoordinatorBuilderForTesting) NodeName(name string) *CoordinatorBuilderForTesting {
	b.localNodeName = name
	return b
}

func (b *CoordinatorBuilderForTesting) PreferredActiveCoordinator(node string) *CoordinatorBuilderForTesting {
	b.preferredActiveCoordinator = &node
	return b
}

func (b *CoordinatorBuilderForTesting) CurrentActiveCoordinator(node string) *CoordinatorBuilderForTesting {
	b.currentActiveCoordinator = &node
	return b
}

func (b *CoordinatorBuilderForTesting) PreviousActiveCoordinatorNode(node string) *CoordinatorBuilderForTesting {
	b.previousActiveCoordinatorNode = &node
	return b
}

func (b *CoordinatorBuilderForTesting) CoordinatorSelectionBlockRange(n uint64) *CoordinatorBuilderForTesting {
	b.sequencerConfig.BlockRange = confutil.P(n)
	return b
}

func (b *CoordinatorBuilderForTesting) NewBlockRangeEpoch(v bool) *CoordinatorBuilderForTesting {
	b.newBlockRangeEpoch = &v
	return b
}

func (b *CoordinatorBuilderForTesting) HeartbeatIntervalsSinceLastReceive(n int) *CoordinatorBuilderForTesting {
	b.heartbeatIntervalsSinceLastReceive = &n
	return b
}

func (b *CoordinatorBuilderForTesting) InactiveGracePeriod(n int) *CoordinatorBuilderForTesting {
	b.inactiveGracePeriod = &n
	return b
}

func (b *CoordinatorBuilderForTesting) HeartbeatIntervalsSinceStateChange(n int) *CoordinatorBuilderForTesting {
	b.heartbeatIntervalsSinceStateChange = &n
	return b
}

func (b *CoordinatorBuilderForTesting) ActiveCoordinatorState(state State) *CoordinatorBuilderForTesting {
	b.activeCoordinatorState = &state
	return b
}

func (b *CoordinatorBuilderForTesting) WithMockTransportWriter() *CoordinatorBuilderForTesting {
	b.useMockTransportWriter = true
	return b
}

func (b *CoordinatorBuilderForTesting) AssembleErrorRetryThreshold(n int) *CoordinatorBuilderForTesting {
	b.sequencerConfig.AssembleErrorRetryThreshold = confutil.P(n)
	return b
}

func (b *CoordinatorBuilderForTesting) ClosingGracePeriod(n int) *CoordinatorBuilderForTesting {
	b.sequencerConfig.ClosingGracePeriod = confutil.P(n)
	return b
}

func (b *CoordinatorBuilderForTesting) Grapher(grapher grapher.Grapher) *CoordinatorBuilderForTesting {
	b.grapher = grapher
	return b
}

func (b *CoordinatorBuilderForTesting) Build() (*coordinator, *CoordinatorDependencyMocks) {
	if b.contractAddress == nil {
		b.contractAddress = pldtypes.RandAddress()
	}
	mocks := &CoordinatorDependencyMocks{
		SentMessageRecorder: testutil.NewSentMessageRecorder(),
		EngineIntegration:   sequencercommonmocks.NewEngineIntegration(b.t),
		SyncPoints:          syncpointsmocks.NewSyncPoints(b.t),
	}

	if b.useMockTransportWriter {
		mockTransportWriter := sequencertransportmocks.NewTransportWriter(b.t)
		mockTransportWriter.On("StartLoopbackWriter").Return().Maybe()
		mockTransportWriter.On("StopLoopbackWriter").Return().Maybe()
		mockTransportWriter.On("WaitForDone", mock.Anything).Return().Maybe()
		mocks.TransportWriter = mockTransportWriter
	}

	if b.contractConfig != nil {
		b.domainAPI.On("ContractConfig").Return(b.contractConfig).Maybe()
	} else {
		b.domainAPI.On("ContractConfig").Return(&prototk.ContractConfig{
			CoordinatorSelection: prototk.ContractConfig_COORDINATOR_SENDER,
		}).Maybe()
	}

	allComponents := componentsmocks.NewAllComponents(b.t)
	mp, err := mockpersistence.NewSQLMockProvider()
	if err != nil {
		panic(err)
	}

	localNode := "node1"
	if b.localNodeName != "" {
		localNode = b.localNodeName
	}

	transportManager := componentsmocks.NewTransportManager(b.t)
	transportManager.On("LocalNodeName").Return(localNode).Maybe()
	allComponents.On("TransportManager").Return(transportManager).Maybe()
	allComponents.On("TxManager").Return(b.txManager).Maybe()
	allComponents.On("SequencerManager").Return(b.sequencerManager).Maybe()
	allComponents.On("Persistence").Return(mp.P).Maybe()

	var transportWriter transport.TransportWriter = mocks.SentMessageRecorder
	if mocks.TransportWriter != nil {
		transportWriter = mocks.TransportWriter
	}

	coordinator := NewCoordinator(
		b.contractAddress, // Contract address,
		b.domainAPI,
		nil,
		allComponents,
		nil,
		nil,
		transportWriter,
		common.RealClock(),
		mocks.EngineIntegration,
		mocks.SyncPoints,
		b.sequencerConfig,
		localNode,
		b.metrics,
	)

	// Loops are not started yet — set state and seed transactions directly.
	for _, tx := range b.transactions {
		coordinator.transactionsByID[tx.GetID()] = tx
	}
	if len(b.pooledTransactions) > 0 {
		for _, tx := range b.pooledTransactions {
			coordinator.transactionsByID[tx.GetID()] = tx
			coordinator.pooledTransactions = append(coordinator.pooledTransactions, tx)
		}
	}
	if len(b.coordinatorEndorserPool) > 0 {
		coordinator.coordinatorEndorserPool = b.coordinatorEndorserPool
	}

	coordinator.stateMachineEventLoop.StateMachine().SetCurrentState(b.state)

	if b.currentBlockHeight != nil {
		coordinator.currentBlockHeight = *b.currentBlockHeight
	}
	if b.originatorNodePool != nil {
		coordinator.originatorNodePool = *b.originatorNodePool
	}
	switch {
	case b.currentActiveCoordinator != nil && b.preferredActiveCoordinator != nil:
		coordinator.currentActiveCoordinator = *b.currentActiveCoordinator
		coordinator.preferredActiveCoordinator = *b.preferredActiveCoordinator
	case b.currentActiveCoordinator != nil:
		coordinator.currentActiveCoordinator = *b.currentActiveCoordinator
		coordinator.preferredActiveCoordinator = *b.currentActiveCoordinator
	case b.preferredActiveCoordinator != nil:
		coordinator.preferredActiveCoordinator = *b.preferredActiveCoordinator
		coordinator.currentActiveCoordinator = *b.preferredActiveCoordinator
	}
	if b.previousActiveCoordinatorNode != nil {
		coordinator.previousActiveCoordinatorNode = *b.previousActiveCoordinatorNode
	}
	if b.newBlockRangeEpoch != nil {
		coordinator.newBlockRangeEpoch = *b.newBlockRangeEpoch
	}
	if b.heartbeatIntervalsSinceLastReceive != nil {
		coordinator.heartbeatIntervalsSinceLastReceive = *b.heartbeatIntervalsSinceLastReceive
	}
	if b.inactiveGracePeriod != nil {
		coordinator.inactiveGracePeriod = *b.inactiveGracePeriod
	}
	if b.heartbeatIntervalsSinceStateChange != nil {
		coordinator.heartbeatIntervalsSinceStateChange = *b.heartbeatIntervalsSinceStateChange
	}
	if b.activeCoordinatorState != nil {
		coordinator.activeCoordinatorState = *b.activeCoordinatorState
	}
	if b.grapher != nil {
		coordinator.grapher = b.grapher
	}
	return coordinator, mocks
}
