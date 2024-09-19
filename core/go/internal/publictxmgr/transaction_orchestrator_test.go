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
	"encoding/json"
	"fmt"
	"math/big"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/hyperledger/firefly-common/pkg/ffapi"
	"github.com/hyperledger/firefly-signer/pkg/ethsigner"
	"github.com/hyperledger/firefly-signer/pkg/ethtypes"
	"github.com/kaleido-io/paladin/core/internal/components"
	"github.com/kaleido-io/paladin/core/mocks/componentmocks"
	"github.com/kaleido-io/paladin/core/pkg/blockindexer"
	"github.com/kaleido-io/paladin/toolkit/pkg/confutil"
	"github.com/kaleido-io/paladin/toolkit/pkg/tktypes"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

func TestNewOrchestratorPolling(t *testing.T) {
	ctx := context.Background()
	mockManagedTx1 := &components.PublicTX{
		ID:     uuid.New(),
		Status: components.PubTxStatusPending,
		Transaction: &ethsigner.Transaction{
			From:  json.RawMessage(testMainSigningAddress),
			Nonce: ethtypes.NewHexInteger64(1),
		},
		Created: confutil.P(tktypes.TimestampNow()),
	}
	mockManagedTx2 := &components.PublicTX{
		ID:     uuid.New(),
		Status: components.PubTxStatusPending,
		Transaction: &ethsigner.Transaction{
			From:  json.RawMessage(testMainSigningAddress),
			Nonce: ethtypes.NewHexInteger64(2),
		},
		Created: confutil.P(tktypes.TimestampNow()),
	}

	qFields := &ffapi.QueryFields{}

	mockTransactionFilter := qFields.NewFilter(ctx)

	ble, _ := NewTestTransactionEngine(t)
	mockBM, mEC, _ := NewTestBalanceManager(ctx, t)
	ble.gasPriceClient = NewTestFixedPriceGasPriceClient(t)
	mBI := componentmocks.NewBlockIndexer(t)
	mTS := componentmocks.NewPublicTransactionStore(t)
	mEN := componentmocks.NewPublicTxEventNotifier(t)
	mKM := componentmocks.NewKeyManager(t)
	ble.Init(ctx, mEC, mKM, mTS, mEN, mBI)
	ble.orchestratorConfig.Set(OrchestratorMaxInFlightTransactionsInt, 10)
	ble.ctx = ctx
	ble.enginePollingInterval = 1 * time.Hour

	oc := NewOrchestrator(ble, string(mockManagedTx1.From), ble.orchestratorConfig)
	oc.balanceManager = mockBM
	mockIT := NewInFlightTransactionStageController(ble, oc, mockManagedTx1)
	oc.InFlightTxs = []*InFlightTransactionStageController{mockIT}
	oc.transactionIDsInStatusUpdate = []string{"randomID"}
	oc.updateConfirmedTxNonce(testMainSigningAddress, big.NewInt(2))
	mTS.On("AddSubStatusAction", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).Run(func(args mock.Arguments) {
		time.Sleep(1 * time.Hour) // make sure the async action never got returned as the test will mock the events
	}).Maybe()
	mTS.On("UpdateTransaction", mock.Anything, mock.Anything, mock.Anything).Run(func(args mock.Arguments) {
		time.Sleep(1 * time.Hour) // make sure the async action never got returned as the test will mock the events
	}).Maybe()
	mTS.On("NewTransactionFilter", mock.Anything).Return(mockTransactionFilter).Maybe()
	mTS.On("ListTransactions", mock.Anything, mock.Anything).Return([]*components.PublicTX{mockManagedTx1, mockManagedTx2}, nil).Once()
	mTS.On("ListTransactions", mock.Anything, mock.Anything).Return([]*components.PublicTX{}, nil).Maybe()
	oc.InFlightTxs = []*InFlightTransactionStageController{
		mockIT}
	addressBalanceChecked := make(chan bool)
	mEC.On("GetBalance", mock.Anything, testMainSigningAddress, "latest").Return(ethtypes.NewHexInteger64(100), nil).Run(func(args mock.Arguments) {
		close(addressBalanceChecked)
	}).Once()
	oc.orchestratorPollingInterval = 1 * time.Hour
	_, _ = oc.Start(ctx)
	<-addressBalanceChecked
}

func TestNewOrchestratorPollingContextCancelled(t *testing.T) {
	ctx, cancelCtx := context.WithCancel(context.Background())
	mockManagedTx1 := &components.PublicTX{
		Transaction: &ethsigner.Transaction{
			From:  json.RawMessage(testMainSigningAddress),
			Nonce: ethtypes.NewHexInteger64(1),
		},
	}

	qFields := &ffapi.QueryFields{}

	mockTransactionFilter := qFields.NewFilter(ctx)

	ble, _ := NewTestTransactionEngine(t)
	mockBM, mEC, _ := NewTestBalanceManager(ctx, t)
	ble.gasPriceClient = NewTestFixedPriceGasPriceClient(t)
	mBI := componentmocks.NewBlockIndexer(t)
	mTS := componentmocks.NewPublicTransactionStore(t)
	mEN := componentmocks.NewPublicTxEventNotifier(t)
	mKM := componentmocks.NewKeyManager(t)
	ble.Init(ctx, mEC, mKM, mTS, mEN, mBI)
	ble.orchestratorConfig.Set(OrchestratorMaxInFlightTransactionsInt, 10)
	ble.ctx = ctx
	ble.enginePollingInterval = 1 * time.Hour

	oc := NewOrchestrator(ble, string(mockManagedTx1.From), ble.orchestratorConfig)

	oc.balanceManager = mockBM

	mTS.On("NewTransactionFilter", mock.Anything).Return(mockTransactionFilter).Maybe()
	mTS.On("ListTransactions", mock.Anything, mock.Anything).Return(nil, fmt.Errorf("list transactions error")).Run(func(args mock.Arguments) {
		cancelCtx()
	}).Once()
	polled, _ := oc.pollAndProcess(ctx)
	assert.Equal(t, -1, polled)
}

func TestNewOrchestratorPollingRemoveCompleted(t *testing.T) {
	ctx := context.Background()
	mockManagedTx1 := &components.PublicTX{
		ID:     uuid.New(),
		Status: components.PubTxStatusFailed,
		Transaction: &ethsigner.Transaction{
			From:  json.RawMessage(testMainSigningAddress),
			Nonce: ethtypes.NewHexInteger64(1),
		},
		Created: confutil.P(tktypes.TimestampNow()),
	}
	mockManagedTx2 := &components.PublicTX{
		ID:     uuid.New(),
		Status: components.PubTxStatusPending,
		Transaction: &ethsigner.Transaction{
			From:  json.RawMessage(testMainSigningAddress),
			Nonce: ethtypes.NewHexInteger64(2),
		},
		Created: confutil.P(tktypes.TimestampNow()),
	}
	qFields := &ffapi.QueryFields{}

	mockTransactionFilter := qFields.NewFilter(ctx)

	ble, _ := NewTestTransactionEngine(t)
	mockBM, mEC, _ := NewTestBalanceManager(ctx, t)
	ble.gasPriceClient = NewTestFixedPriceGasPriceClient(t)
	mBI := componentmocks.NewBlockIndexer(t)
	mTS := componentmocks.NewPublicTransactionStore(t)
	mEN := componentmocks.NewPublicTxEventNotifier(t)
	mKM := componentmocks.NewKeyManager(t)
	ble.Init(ctx, mEC, mKM, mTS, mEN, mBI)
	ble.orchestratorConfig.Set(OrchestratorMaxInFlightTransactionsInt, 10)
	ble.ctx = ctx
	ble.enginePollingInterval = 1 * time.Hour

	oc := NewOrchestrator(ble, string(mockManagedTx1.From), ble.orchestratorConfig)

	oc.balanceManager = mockBM
	mockIT := NewInFlightTransactionStageController(ble, oc, mockManagedTx1)

	mTS.On("NewTransactionFilter", mock.Anything).Return(mockTransactionFilter).Once()
	mTS.On("ListTransactions", mock.Anything, mock.Anything).Return([]*components.PublicTX{mockManagedTx1, mockManagedTx2}, nil).Once()
	oc.InFlightTxs = []*InFlightTransactionStageController{
		mockIT,
	}
	addressBalanceChecked := make(chan bool)
	mEC.On("GetBalance", mock.Anything, testMainSigningAddress, "latest").Return(nil, fmt.Errorf("failed getting balance")).Run(func(args mock.Arguments) {
		close(addressBalanceChecked)
	}).Once()
	oc.orchestratorPollingInterval = 1 * time.Hour
	_, _ = oc.Start(ctx)
	<-addressBalanceChecked
}

func TestNewOrchestratorPollingRemoveSuspended(t *testing.T) {
	ctx := context.Background()
	mockManagedTx1 := &components.PublicTX{
		ID:     uuid.New(),
		Status: components.PubTxStatusSuspended,
		Transaction: &ethsigner.Transaction{
			From:  json.RawMessage(testMainSigningAddress),
			Nonce: ethtypes.NewHexInteger64(1),
		},
		Created: confutil.P(tktypes.TimestampNow()),
	}
	mockManagedTx2 := &components.PublicTX{
		ID:     uuid.New(),
		Status: components.PubTxStatusPending,
		Transaction: &ethsigner.Transaction{
			From:  json.RawMessage(testMainSigningAddress),
			Nonce: ethtypes.NewHexInteger64(2),
		},
		Created: confutil.P(tktypes.TimestampNow()),
	}

	qFields := &ffapi.QueryFields{}

	mockTransactionFilter := qFields.NewFilter(ctx)

	ble, _ := NewTestTransactionEngine(t)
	mockBM, mEC, _ := NewTestBalanceManager(ctx, t)
	ble.gasPriceClient = NewTestFixedPriceGasPriceClient(t)
	mBI := componentmocks.NewBlockIndexer(t)
	mTS := componentmocks.NewPublicTransactionStore(t)
	mEN := componentmocks.NewPublicTxEventNotifier(t)
	mKM := componentmocks.NewKeyManager(t)
	ble.Init(ctx, mEC, mKM, mTS, mEN, mBI)

	ble.orchestratorConfig.Set(OrchestratorMaxInFlightTransactionsInt, 10)
	ble.ctx = ctx
	ble.enginePollingInterval = 1 * time.Hour

	oc := NewOrchestrator(ble, string(mockManagedTx1.From), ble.orchestratorConfig)

	oc.balanceManager = mockBM
	mockIT := NewInFlightTransactionStageController(ble, oc, mockManagedTx1)

	mTS.On("NewTransactionFilter", mock.Anything).Return(mockTransactionFilter).Once()
	mTS.On("ListTransactions", mock.Anything, mock.Anything).Return([]*components.PublicTX{mockManagedTx1, mockManagedTx2}, nil).Once()
	oc.InFlightTxs = []*InFlightTransactionStageController{
		mockIT,
	}

	addressBalanceChecked := make(chan bool)
	mEC.On("GetBalance", mock.Anything, testMainSigningAddress, "latest").Return(nil, fmt.Errorf("failed getting balance")).Run(func(args mock.Arguments) {
		close(addressBalanceChecked)
	}).Once()
	oc.orchestratorPollingInterval = 1 * time.Hour
	_, _ = oc.Start(ctx)
	<-addressBalanceChecked
}

func TestNewOrchestratorPollingMarkStale(t *testing.T) {
	ctx := context.Background()
	mockManagedTx1 := &components.PublicTX{
		ID:     uuid.New(),
		Status: components.PubTxStatusPending,
		Transaction: &ethsigner.Transaction{
			From:  json.RawMessage(testMainSigningAddress),
			Nonce: ethtypes.NewHexInteger64(1),
		},
		Created: confutil.P(tktypes.TimestampNow()),
	}

	qFields := &ffapi.QueryFields{}

	mockTransactionFilter := qFields.NewFilter(ctx)

	ble, _ := NewTestTransactionEngine(t)
	mockBM, mEC, _ := NewTestBalanceManager(ctx, t)
	ble.gasPriceClient = NewTestFixedPriceGasPriceClient(t)
	mBI := componentmocks.NewBlockIndexer(t)
	mTS := componentmocks.NewPublicTransactionStore(t)
	mEN := componentmocks.NewPublicTxEventNotifier(t)
	mKM := componentmocks.NewKeyManager(t)
	ble.Init(ctx, mEC, mKM, mTS, mEN, mBI)
	ble.orchestratorConfig.Set(OrchestratorMaxInFlightTransactionsInt, 10)
	ble.ctx = ctx
	ble.enginePollingInterval = 1 * time.Hour

	oc := NewOrchestrator(ble, string(mockManagedTx1.From), ble.orchestratorConfig)

	oc.balanceManager = mockBM
	oc.lastQueueUpdate = time.Now().Add(-1 * time.Hour)
	mockIT := NewInFlightTransactionStageController(ble, oc, mockManagedTx1)

	mTS.On("NewTransactionFilter", mock.Anything).Return(mockTransactionFilter).Maybe()
	mTS.On("ListTransactions", mock.Anything, mock.Anything).Return([]*components.PublicTX{mockManagedTx1}, nil).Once()
	oc.InFlightTxs = []*InFlightTransactionStageController{
		mockIT,
	}
	addressBalanceChecked := make(chan bool)
	mEC.On("GetBalance", mock.Anything, testMainSigningAddress, "latest").Return(nil, fmt.Errorf("failed getting balance")).Run(func(args mock.Arguments) {
		close(addressBalanceChecked)
	}).Once()
	oc.orchestratorPollingInterval = 1 * time.Hour
	oc.pollAndProcess(ctx)
	<-addressBalanceChecked
	assert.Equal(t, OrchestratorStateStale, oc.state)
}

func TestOrchestratorStop(t *testing.T) {
	ctx, cancelCtx := context.WithCancel(context.Background())

	mockManagedTx1 := &components.PublicTX{
		ID:     uuid.New(),
		Status: components.PubTxStatusSuspended,
		Transaction: &ethsigner.Transaction{
			From:  json.RawMessage(testMainSigningAddress),
			Nonce: ethtypes.NewHexInteger64(1),
		},
		Created: confutil.P(tktypes.TimestampNow()),
	}
	mockManagedTx2 := &components.PublicTX{
		ID:     uuid.New(),
		Status: components.PubTxStatusPending,
		Transaction: &ethsigner.Transaction{
			From:  json.RawMessage(testMainSigningAddress),
			Nonce: ethtypes.NewHexInteger64(2),
		},
		Created: confutil.P(tktypes.TimestampNow()),
	}

	qFields := &ffapi.QueryFields{}

	mockTransactionFilter := qFields.NewFilter(ctx)

	ble, _ := NewTestTransactionEngine(t)

	mTS := componentmocks.NewPublicTransactionStore(t)
	mTS.On("NewTransactionFilter", mock.Anything).Return(mockTransactionFilter).Maybe()
	mTS.On("ListTransactions", mock.Anything, mock.Anything).Return([]*components.PublicTX{mockManagedTx1, mockManagedTx2}, nil).Maybe()
	ble.gasPriceClient = NewTestFixedPriceGasPriceClient(t)
	mBI := componentmocks.NewBlockIndexer(t)
	mEN := componentmocks.NewPublicTxEventNotifier(t)

	mEC := componentmocks.NewEthClient(t)
	mKM := componentmocks.NewKeyManager(t)
	ble.Init(ctx, mEC, mKM, mTS, mEN, mBI)
	ble.orchestratorConfig.Set(OrchestratorMaxInFlightTransactionsInt, 10)
	ble.ctx = ctx
	ble.enginePollingInterval = 1 * time.Hour

	oc := NewOrchestrator(ble, string(mockManagedTx1.From), ble.orchestratorConfig)
	oc.orchestratorPollingInterval = 1 * time.Hour
	oc.ctx = ctx
	oc.orchestratorLoopDone = make(chan struct{})
	go oc.orchestratorLoop()

	//stops OK
	cancelCtx()
	<-oc.orchestratorLoopDone
}

func TestOrchestratorStopWhenBalanceUnavailable(t *testing.T) {
	ctx := context.Background()
	mockManagedTx1 := &components.PublicTX{
		ID:     uuid.New(),
		Status: components.PubTxStatusSucceeded,
		Transaction: &ethsigner.Transaction{
			From:  json.RawMessage(testMainSigningAddress),
			Nonce: ethtypes.NewHexInteger64(1),
		},
		Created: confutil.P(tktypes.TimestampNow()),
	}

	ble, _ := NewTestTransactionEngine(t)
	mockBM, mEC, _ := NewTestBalanceManager(ctx, t)
	ble.gasPriceClient = NewTestFixedPriceGasPriceClient(t)
	mBI := componentmocks.NewBlockIndexer(t)
	mTS := componentmocks.NewPublicTransactionStore(t)
	mEN := componentmocks.NewPublicTxEventNotifier(t)
	mKM := componentmocks.NewKeyManager(t)
	ble.Init(ctx, mEC, mKM, mTS, mEN, mBI)

	ble.orchestratorConfig.Set(OrchestratorMaxInFlightTransactionsInt, 10)
	ble.ctx = ctx
	ble.enginePollingInterval = 1 * time.Hour

	oc := NewOrchestrator(ble, string(mockManagedTx1.From), ble.orchestratorConfig)
	oc.state = OrchestratorStateRunning
	oc.balanceManager = mockBM
	mockIT := NewInFlightTransactionStageController(ble, oc, mockManagedTx1)

	// continue process
	mEC.On("GetBalance", mock.Anything, testMainSigningAddress, "latest").Return(nil, fmt.Errorf("failed getting balance")).Once()
	oc.unavailableBalanceHandlingStrategy = OrchestratorBalanceCheckUnavailableBalanceHandlingStrategyContinue
	waitingForBalance, err := oc.ProcessInFlightTransaction(ctx, []*InFlightTransactionStageController{mockIT})
	require.NoError(t, err)
	assert.False(t, waitingForBalance)
	assert.Equal(t, OrchestratorStateRunning, oc.state)

	// wait for the next round
	mEC.On("GetBalance", mock.Anything, testMainSigningAddress, "latest").Return(nil, fmt.Errorf("failed getting balance")).Once()
	oc.unavailableBalanceHandlingStrategy = OrchestratorBalanceCheckUnavailableBalanceHandlingStrategyWait
	waitingForBalance, err = oc.ProcessInFlightTransaction(ctx, []*InFlightTransactionStageController{mockIT})
	require.NoError(t, err)
	assert.True(t, waitingForBalance)
	assert.Equal(t, OrchestratorStateRunning, oc.state)

	// stop the orchestrator
	mEC.On("GetBalance", mock.Anything, testMainSigningAddress, "latest").Return(nil, fmt.Errorf("failed getting balance")).Once()
	oc.unavailableBalanceHandlingStrategy = OrchestratorBalanceCheckUnavailableBalanceHandlingStrategyStop
	oc.stopProcess = make(chan bool, 1)
	waitingForBalance, err = oc.ProcessInFlightTransaction(ctx, []*InFlightTransactionStageController{mockIT})
	require.NoError(t, err)
	assert.True(t, waitingForBalance)
	<-oc.stopProcess
}

func TestOrchestratorTriggerTopUp(t *testing.T) {
	ctx := context.Background()
	mockManagedTx1 := &components.PublicTX{
		ID:     uuid.New(),
		Status: components.PubTxStatusSucceeded,
		Transaction: &ethsigner.Transaction{
			From:     json.RawMessage(testMainSigningAddress),
			Nonce:    ethtypes.NewHexInteger64(1),
			GasPrice: ethtypes.NewHexInteger64(1000),
			GasLimit: ethtypes.NewHexInteger64(100),
		},
		Created: confutil.P(tktypes.TimestampNow()),
	}

	ble, _ := NewTestTransactionEngine(t)
	mockBM, mEC, mockAFTxEngine := NewTestBalanceManager(ctx, t)
	ble.gasPriceClient = NewTestFixedPriceGasPriceClient(t)
	mBI := componentmocks.NewBlockIndexer(t)
	mTS := componentmocks.NewPublicTransactionStore(t)
	mEN := componentmocks.NewPublicTxEventNotifier(t)
	mKM := componentmocks.NewKeyManager(t)
	ble.Init(ctx, mEC, mKM, mTS, mEN, mBI)
	ble.orchestratorConfig.Set(OrchestratorMaxInFlightTransactionsInt, 10)
	ble.ctx = ctx
	ble.enginePollingInterval = 1 * time.Hour

	oc := NewOrchestrator(ble, string(mockManagedTx1.From), ble.orchestratorConfig)
	oc.state = OrchestratorStateRunning
	oc.balanceManager = mockBM
	mockIT := NewInFlightTransactionStageController(ble, oc, mockManagedTx1)

	// trigger top up if cost is known
	mockAFTxEngine.On("GetPendingFuelingTransaction", mock.Anything, "0x4e598f6e918321dd47c86e7a077b4ab0e7414846", testMainSigningAddress).Return(nil, fmt.Errorf("cannot get tx")).Once()
	mEC.On("GetBalance", mock.Anything, testMainSigningAddress, "latest").Return(ethtypes.NewHexInteger64(100), nil).Once()
	oc.unavailableBalanceHandlingStrategy = OrchestratorBalanceCheckUnavailableBalanceHandlingStrategyContinue
	waitingForBalance, err := oc.ProcessInFlightTransaction(ctx, []*InFlightTransactionStageController{mockIT})
	require.NoError(t, err)
	assert.True(t, waitingForBalance)
	assert.Equal(t, OrchestratorStateRunning, oc.state)

	// skip top up when cost is unknown
	mockManagedTx1.GasPrice = nil
	oc.unavailableBalanceHandlingStrategy = OrchestratorBalanceCheckUnavailableBalanceHandlingStrategyContinue
	waitingForBalance, err = oc.ProcessInFlightTransaction(ctx, []*InFlightTransactionStageController{mockIT})
	require.NoError(t, err)
	assert.False(t, waitingForBalance)
	assert.Equal(t, OrchestratorStateRunning, oc.state)
}

func TestOrchestratorHandleConfirmedTransactions(t *testing.T) {
	ctx, cancelCtx := context.WithCancel(context.Background())
	mockManagedTx0 := &components.PublicTX{
		ID:     uuid.New(),
		Status: components.PubTxStatusPending,
		Transaction: &ethsigner.Transaction{
			From:  json.RawMessage(testMainSigningAddress),
			Nonce: ethtypes.NewHexInteger64(0),
		},
		Created: confutil.P(tktypes.TimestampNow()),
	}
	mockManagedTx1 := &components.PublicTX{
		ID:     uuid.New(),
		Status: components.PubTxStatusPending,
		Transaction: &ethsigner.Transaction{
			From:  json.RawMessage(testMainSigningAddress),
			Nonce: ethtypes.NewHexInteger64(1),
		},
		Created: confutil.P(tktypes.TimestampNow()),
	}
	mockManagedTx2 := &components.PublicTX{
		ID:     uuid.New(),
		Status: components.PubTxStatusPending,
		Transaction: &ethsigner.Transaction{
			From:  json.RawMessage(testMainSigningAddress),
			Nonce: ethtypes.NewHexInteger64(2),
		},
		Created: confutil.P(tktypes.TimestampNow()),
	}
	mockManagedTx3 := &components.PublicTX{
		ID:     uuid.New(),
		Status: components.PubTxStatusPending,
		Transaction: &ethsigner.Transaction{
			From:  json.RawMessage(testMainSigningAddress),
			Nonce: ethtypes.NewHexInteger64(3),
		},
		Created: confutil.P(tktypes.TimestampNow()),
	}
	ble, _ := NewTestTransactionEngine(t)
	mockBM, mEC, _ := NewTestBalanceManager(ctx, t)
	ble.gasPriceClient = NewTestFixedPriceGasPriceClient(t)
	mBI := componentmocks.NewBlockIndexer(t)
	mTS := componentmocks.NewPublicTransactionStore(t)
	mEN := componentmocks.NewPublicTxEventNotifier(t)
	mKM := componentmocks.NewKeyManager(t)
	ble.Init(ctx, mEC, mKM, mTS, mEN, mBI)

	ble.orchestratorConfig.Set(OrchestratorMaxInFlightTransactionsInt, 10)
	ble.ctx = ctx
	ble.enginePollingInterval = 1 * time.Hour

	oc := NewOrchestrator(ble, string(mockManagedTx1.From), ble.orchestratorConfig)

	oc.balanceManager = mockBM
	mockIT1 := NewInFlightTransactionStageController(ble, oc, mockManagedTx1)
	mockIT3 := NewInFlightTransactionStageController(ble, oc, mockManagedTx3)

	oc.InFlightTxs = []*InFlightTransactionStageController{
		mockIT1,
		nil,
		mockIT3, // nonce is bigger than the max nonce, so shouldn't be processed
	}

	assert.Nil(t, oc.confirmedTxNoncePerAddress[testMainSigningAddress])
	oc.orchestratorPollingInterval = 1 * time.Hour
	err := oc.HandleConfirmedTransactions(ctx, map[string]*blockindexer.IndexedTransaction{
		mockManagedTx0.Nonce.BigInt().String(): {}, // already confirmed
		mockManagedTx1.Nonce.BigInt().String(): {}, // in flight, add the confirmation event
		mockManagedTx2.Nonce.BigInt().String(): {}, // not inflight, so shouldn't be processed
	}, big.NewInt(2))
	assert.NoError(t, err)
	assert.Equal(t, big.NewInt(2), oc.confirmedTxNoncePerAddress[testMainSigningAddress]) //record the max nonce

	// cancel context should return with error
	cancelCtx()
	assert.Regexp(t, "PD010301", oc.HandleConfirmedTransactions(ctx, map[string]*blockindexer.IndexedTransaction{
		mockManagedTx0.Nonce.BigInt().String(): {}, // already confirmed
		mockManagedTx1.Nonce.BigInt().String(): {}, // in flight, add the confirmation event
		mockManagedTx2.Nonce.BigInt().String(): {}, // not inflight, so shouldn't be processed
	}, big.NewInt(2)))
}

func TestOrchestratorHandleConfirmedTransactionsNoInflightNotHang(t *testing.T) {
	ctx := context.Background()

	mockManagedTx1 := &components.PublicTX{
		ID:     uuid.New(),
		Status: components.PubTxStatusPending,
		Transaction: &ethsigner.Transaction{
			From:  json.RawMessage(testMainSigningAddress),
			Nonce: ethtypes.NewHexInteger64(1),
		},
		Created: confutil.P(tktypes.TimestampNow()),
	}
	ble, _ := NewTestTransactionEngine(t)
	mockBM, mEC, _ := NewTestBalanceManager(ctx, t)
	ble.gasPriceClient = NewTestFixedPriceGasPriceClient(t)
	mBI := componentmocks.NewBlockIndexer(t)
	mTS := componentmocks.NewPublicTransactionStore(t)
	mEN := componentmocks.NewPublicTxEventNotifier(t)
	mKM := componentmocks.NewKeyManager(t)
	ble.Init(ctx, mEC, mKM, mTS, mEN, mBI)

	ble.orchestratorConfig.Set(OrchestratorMaxInFlightTransactionsInt, 10)
	ble.ctx = ctx
	ble.enginePollingInterval = 1 * time.Hour

	oc := NewOrchestrator(ble, string(mockManagedTx1.From), ble.orchestratorConfig)

	oc.balanceManager = mockBM

	oc.InFlightTxs = []*InFlightTransactionStageController{}

	assert.Nil(t, oc.confirmedTxNoncePerAddress[testMainSigningAddress])
	oc.orchestratorPollingInterval = 1 * time.Hour
	err := oc.HandleConfirmedTransactions(ctx, map[string]*blockindexer.IndexedTransaction{
		mockManagedTx1.Nonce.BigInt().String(): {},
	}, big.NewInt(1))
	assert.NoError(t, err)
	assert.Equal(t, big.NewInt(1), oc.confirmedTxNoncePerAddress[testMainSigningAddress]) //record the max nonce

}
