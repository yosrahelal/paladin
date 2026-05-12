//go:build !generate_mocks

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

package originator

import (
	"context"
	"testing"

	"github.com/LFDT-Paladin/paladin/config/pkg/pldconf"
	"github.com/LFDT-Paladin/paladin/core/internal/sequencer/common"
	"github.com/LFDT-Paladin/paladin/core/internal/sequencer/metrics"
	"github.com/LFDT-Paladin/paladin/core/internal/sequencer/originator/transaction"
	"github.com/LFDT-Paladin/paladin/core/internal/sequencer/transport"
	"github.com/LFDT-Paladin/paladin/core/mocks/componentsmocks"
	"github.com/LFDT-Paladin/paladin/core/mocks/sequencertransportmocks"
	"github.com/LFDT-Paladin/paladin/sdk/go/pkg/pldtypes"
	"github.com/LFDT-Paladin/paladin/toolkit/pkg/prototk"
	"github.com/prometheus/client_golang/prometheus"
)

const (
	TestDefault_HeartbeatThreshold  int = 5
	TestDefault_HeartbeatIntervalMs int = 100
)

type OriginatorBuilderForTesting struct {
	t                                  *testing.T
	state                              State
	nodeName                           *string
	committeeMembers                   []string
	contractAddress                    *pldtypes.EthAddress
	transactionBuilders                []*transaction.TransactionBuilderForTesting
	metrics                            metrics.DistributedSequencerMetrics
	sequencerConfig                    *pldconf.SequencerConfig
	contractConfig                     *prototk.ContractConfig
	blockRangeSize                     *uint64
	currentBlockHeight                 *uint64
	newBlockRangeEpoch                 *bool
	coordinatorEndorserPool            []string
	preferredActiveCoordinator         *string
	currentActiveCoordinator           *string
	previousActiveCoordinatorNode      *string
	watchingPreviousCoordinatorFlush   *bool
	failoverOffset                     *int
	needsRedelegate                    *bool
	heartbeatIntervalsSinceLastReceive *int
	inactiveGracePeriod                *int
	transactions                       []transaction.OriginatorTransaction
	useMockTransportWriter             bool
}

type OriginatorDependencyMocks struct {
	SentMessageRecorder *transport.SentMessageRecorder
	EngineIntegration   *common.FakeEngineIntegrationForTesting
	DomainAPI           *componentsmocks.DomainSmartContract
	TransportWriter     *sequencertransportmocks.TransportWriter
}

func NewOriginatorBuilderForTesting(state State) *OriginatorBuilderForTesting {
	return &OriginatorBuilderForTesting{
		state:           state,
		metrics:         metrics.InitMetrics(context.Background(), prometheus.NewRegistry()),
		sequencerConfig: &pldconf.SequencerDefaults,
	}
}

func (b *OriginatorBuilderForTesting) ContractAddress(contractAddress *pldtypes.EthAddress) *OriginatorBuilderForTesting {
	b.contractAddress = contractAddress
	return b
}

func (b *OriginatorBuilderForTesting) NodeName(nodeName string) *OriginatorBuilderForTesting {
	b.nodeName = &nodeName
	return b
}

func (b *OriginatorBuilderForTesting) CommitteeMembers(committeeMembers ...string) *OriginatorBuilderForTesting {
	b.committeeMembers = committeeMembers
	return b
}

func (b *OriginatorBuilderForTesting) TransactionBuilders(builders ...*transaction.TransactionBuilderForTesting) *OriginatorBuilderForTesting {
	b.transactionBuilders = builders
	return b
}

func (b *OriginatorBuilderForTesting) GetContractAddress() pldtypes.EthAddress {
	return *b.contractAddress
}

func (b *OriginatorBuilderForTesting) GetCoordinatorHeartbeatThresholdMs() int {
	return TestDefault_HeartbeatThreshold * TestDefault_HeartbeatIntervalMs
}

func (b *OriginatorBuilderForTesting) GetSequencerConfig() *pldconf.SequencerConfig {
	return b.sequencerConfig
}

func (b *OriginatorBuilderForTesting) OverrideSequencerConfig(config *pldconf.SequencerConfig) {
	b.sequencerConfig = config
}

func (b *OriginatorBuilderForTesting) BlockRangeSize(n uint64) *OriginatorBuilderForTesting {
	b.blockRangeSize = &n
	return b
}

func (b *OriginatorBuilderForTesting) CurrentBlockHeight(n uint64) *OriginatorBuilderForTesting {
	b.currentBlockHeight = &n
	return b
}

func (b *OriginatorBuilderForTesting) NewBlockRangeEpoch(v bool) *OriginatorBuilderForTesting {
	b.newBlockRangeEpoch = &v
	return b
}

func (b *OriginatorBuilderForTesting) CoordinatorEndorserPool(nodes ...string) *OriginatorBuilderForTesting {
	b.coordinatorEndorserPool = common.DedupeSortedCoordinatorEndorserNodes(append([]string(nil), nodes...))
	return b
}

func (b *OriginatorBuilderForTesting) DomainContractConfig(cfg *prototk.ContractConfig) *OriginatorBuilderForTesting {
	b.contractConfig = cfg
	return b
}

func (b *OriginatorBuilderForTesting) PreferredActiveCoordinator(node string) *OriginatorBuilderForTesting {
	b.preferredActiveCoordinator = &node
	return b
}

func (b *OriginatorBuilderForTesting) CurrentActiveCoordinator(node string) *OriginatorBuilderForTesting {
	b.currentActiveCoordinator = &node
	return b
}

func (b *OriginatorBuilderForTesting) FailoverOffset(offset int) *OriginatorBuilderForTesting {
	b.failoverOffset = &offset
	return b
}

func (b *OriginatorBuilderForTesting) NeedsRedelegate(v bool) *OriginatorBuilderForTesting {
	b.needsRedelegate = &v
	return b
}

func (b *OriginatorBuilderForTesting) PreviousActiveCoordinatorNode(node string) *OriginatorBuilderForTesting {
	b.previousActiveCoordinatorNode = &node
	return b
}

func (b *OriginatorBuilderForTesting) WatchingPreviousCoordinatorFlush(watching bool) *OriginatorBuilderForTesting {
	b.watchingPreviousCoordinatorFlush = &watching
	return b
}

func (b *OriginatorBuilderForTesting) HeartbeatIntervalsSinceLastReceive(n int) *OriginatorBuilderForTesting {
	b.heartbeatIntervalsSinceLastReceive = &n
	return b
}

func (b *OriginatorBuilderForTesting) InactiveGracePeriod(n int) *OriginatorBuilderForTesting {
	b.inactiveGracePeriod = &n
	return b
}

func (b *OriginatorBuilderForTesting) Transactions(txns ...transaction.OriginatorTransaction) *OriginatorBuilderForTesting {
	b.transactions = txns
	return b
}

// WithMockTransportWriter switches the transport writer from the default SentMessageRecorder to a
// full testify mock. This enables per-call assertions (e.g. assert the exact coordinator node that
// a delegation request was sent to). Requires a *testing.T for mock cleanup registration.
func (b *OriginatorBuilderForTesting) WithMockTransportWriter(t *testing.T) *OriginatorBuilderForTesting {
	b.t = t
	b.useMockTransportWriter = true
	return b
}

func (b *OriginatorBuilderForTesting) Build() (*originator, *OriginatorDependencyMocks) {

	if b.nodeName == nil {
		b.nodeName = ptrTo("member1@node1")
	}

	if b.committeeMembers == nil {
		b.committeeMembers = []string{*b.nodeName}
	}

	if b.contractAddress == nil {
		b.contractAddress = pldtypes.RandAddress()
	}
	mocks := &OriginatorDependencyMocks{
		SentMessageRecorder: transport.NewSentMessageRecorder(),
		EngineIntegration:   &common.FakeEngineIntegrationForTesting{},
	}

	if b.useMockTransportWriter {
		mocks.TransportWriter = sequencertransportmocks.NewTransportWriter(b.t)
	}

	domainAPI := &componentsmocks.DomainSmartContract{}
	if b.contractConfig != nil {
		domainAPI.On("ContractConfig").Return(b.contractConfig).Maybe()
	} else {
		domainAPI.On("ContractConfig").Return(&prototk.ContractConfig{
			CoordinatorSelection: prototk.ContractConfig_COORDINATOR_SENDER,
		}).Maybe()
	}

	seqConfig := b.sequencerConfig
	if seqConfig == nil {
		seqConfig = &pldconf.SequencerDefaults
	}

	var tw transport.TransportWriter = mocks.SentMessageRecorder
	if mocks.TransportWriter != nil {
		tw = mocks.TransportWriter
	}

	originator := NewOriginator(
		*b.nodeName,
		tw,
		mocks.EngineIntegration,
		b.contractAddress,
		seqConfig,
		b.metrics,
		domainAPI,
		func(context.Context, string) {},
	)

	for _, txBuilder := range b.transactionBuilders {
		tx := txBuilder.QueueEventsTo(originator.queueEventInternal).Build()
		txID := tx.GetID()
		originator.transactionsByID[txID] = tx
		originator.transactionsOrdered = append(originator.transactionsOrdered, tx)
	}

	for _, tx := range b.transactions {
		txID := tx.GetID()
		originator.transactionsByID[txID] = tx
		originator.transactionsOrdered = append(originator.transactionsOrdered, tx)
	}

	originator.stateMachineEventLoop.StateMachine().SetCurrentState(b.state)
	switch b.state {
	// Any state specific setup can be done here
	}

	switch {
	case b.currentActiveCoordinator != nil && b.preferredActiveCoordinator != nil:
		originator.currentActiveCoordinator = *b.currentActiveCoordinator
		originator.preferredActiveCoordinator = *b.preferredActiveCoordinator
	case b.currentActiveCoordinator != nil:
		originator.currentActiveCoordinator = *b.currentActiveCoordinator
		originator.preferredActiveCoordinator = *b.currentActiveCoordinator
	case b.preferredActiveCoordinator != nil:
		originator.preferredActiveCoordinator = *b.preferredActiveCoordinator
		originator.currentActiveCoordinator = *b.preferredActiveCoordinator
	default:
		originator.currentActiveCoordinator = "coordinator"
		originator.preferredActiveCoordinator = "coordinator"
	}
	if b.failoverOffset != nil {
		originator.failoverOffset = *b.failoverOffset
	}
	if b.needsRedelegate != nil {
		originator.needsRedelegate = *b.needsRedelegate
	}
	if b.blockRangeSize != nil {
		originator.blockRangeSize = *b.blockRangeSize
	}
	if b.currentBlockHeight != nil {
		originator.currentBlockHeight = *b.currentBlockHeight
	}
	if b.newBlockRangeEpoch != nil {
		originator.newBlockRangeEpoch = *b.newBlockRangeEpoch
		originator.needsFailoverOffsetReset = *b.newBlockRangeEpoch
	}
	if b.coordinatorEndorserPool != nil {
		originator.coordinatorEndorserPool = b.coordinatorEndorserPool
	}
	if b.previousActiveCoordinatorNode != nil {
		originator.previousActiveCoordinatorNode = *b.previousActiveCoordinatorNode
	}
	if b.watchingPreviousCoordinatorFlush != nil {
		originator.watchingPreviousCoordinatorFlush = *b.watchingPreviousCoordinatorFlush
	}
	if b.heartbeatIntervalsSinceLastReceive != nil {
		originator.heartbeatIntervalsSinceLastReceive = *b.heartbeatIntervalsSinceLastReceive
	}
	if b.inactiveGracePeriod != nil {
		originator.inactiveGracePeriod = *b.inactiveGracePeriod
	}

	mocks.DomainAPI = domainAPI
	return originator, mocks
}
