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

package baseledgertx

import (
	"context"
	"fmt"
	"math/big"
	"testing"
	"time"

	"github.com/hyperledger/firefly-common/pkg/fftypes"
	"github.com/hyperledger/firefly-common/pkg/retry"
	"github.com/hyperledger/firefly-signer/pkg/ethtypes"
	baseTypes "github.com/kaleido-io/paladin/core/internal/engine/enginespi"
	"github.com/kaleido-io/paladin/core/mocks/componentmocks"
	"github.com/kaleido-io/paladin/core/mocks/enginemocks"
	"github.com/kaleido-io/paladin/core/pkg/blockindexer"
	"github.com/kaleido-io/paladin/toolkit/pkg/tktypes"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

type testInFlightTransactionStateManagerWithMocks struct {
	stateManager    baseTypes.InFlightTransactionStateManager
	mEC             *componentmocks.EthClient
	mTS             *enginemocks.TransactionStore
	mBI             *componentmocks.BlockIndexer
	mBM             baseTypes.BalanceManager
	mAT             *enginemocks.InFlightStageActionTriggers
	inMemoryTxState baseTypes.InMemoryTxStateManager
}

func newTestInFlightTransactionStateManager(t *testing.T) *testInFlightTransactionStateManagerWithMocks {
	mBM, mEC, _ := NewTestBalanceManager(context.Background(), t)
	mockInMemoryState := NewTestInMemoryTxState(t)
	mockActionTriggers := enginemocks.NewInFlightStageActionTriggers(t)
	mTS := enginemocks.NewTransactionStore(t)
	mBI := componentmocks.NewBlockIndexer(t)
	iftxs := NewInFlightTransactionStateManager(&baseLedgerTxEngineMetrics{}, mBM, mTS, mBI, mockActionTriggers, mockInMemoryState, &retry.Retry{
		InitialDelay: 1 * time.Millisecond,
		MaximumDelay: 100 * time.Millisecond,
		Factor:       2.0,
	}, false, false)
	return &testInFlightTransactionStateManagerWithMocks{
		iftxs,
		mEC,
		mTS,
		mBI,
		mBM,
		mockActionTriggers,
		mockInMemoryState,
	}

}

func TestStateManagerStageManagementBasic(t *testing.T) {
	ctx := context.Background()
	testStateManagerWithMocks := newTestInFlightTransactionStateManager(t)
	stateManager := testStateManagerWithMocks.stateManager
	assert.Nil(t, stateManager.GetRunningStageContext(ctx))
	assert.Nil(t, stateManager.GetStageTriggerError(ctx))
	assert.Empty(t, stateManager.GetStage(ctx))
	assert.NotNil(t, stateManager.GetStageStartTime(ctx))
	assert.False(t, stateManager.ValidatedTransactionHashMatchState(ctx))
	stateManager.SetValidatedTransactionHashMatchState(ctx, true)
	assert.True(t, stateManager.ValidatedTransactionHashMatchState(ctx))
	stateManager.SetValidatedTransactionHashMatchState(ctx, false)
	assert.False(t, stateManager.ValidatedTransactionHashMatchState(ctx))
}

func TestStateManagerStageManagementCanSubmit(t *testing.T) {
	ctx := context.Background()
	testStateManagerWithMocks := newTestInFlightTransactionStateManager(t)
	stateManager := testStateManagerWithMocks.stateManager
	stateManager.SetOrchestratorContext(ctx, &baseTypes.OrchestratorContext{
		PreviousNonceCostUnknown: false,
		// no available to spent provided, this means we don't need to check balance
	})
	assert.True(t, testStateManagerWithMocks.stateManager.CanSubmit(context.Background(), big.NewInt(0)))
	stateManager.SetOrchestratorContext(ctx, &baseTypes.OrchestratorContext{
		PreviousNonceCostUnknown: false,
		AvailableToSpend:         big.NewInt(30),
	})
	assert.True(t, testStateManagerWithMocks.stateManager.CanSubmit(context.Background(), big.NewInt(29)))
	assert.True(t, testStateManagerWithMocks.stateManager.CanSubmit(context.Background(), big.NewInt(30)))
	assert.False(t, testStateManagerWithMocks.stateManager.CanSubmit(context.Background(), big.NewInt(31)))
	assert.False(t, testStateManagerWithMocks.stateManager.CanSubmit(context.Background(), nil)) //unknown cost for the current transaction

	stateManager.SetOrchestratorContext(ctx, &baseTypes.OrchestratorContext{
		PreviousNonceCostUnknown: true,
		AvailableToSpend:         big.NewInt(30),
	})

	assert.False(t, testStateManagerWithMocks.stateManager.CanSubmit(context.Background(), big.NewInt(29)))

}

func TestStateManagerStageManagementTransactionFromRetrieveGasPriceToTracking(t *testing.T) {
	testStateManagerWithMocks := newTestInFlightTransactionStateManager(t)

	ctx := context.Background()
	stateManager := testStateManagerWithMocks.stateManager

	mockActionTriggers := testStateManagerWithMocks.mAT
	defer mockActionTriggers.AssertExpectations(t)
	// retrieve gas price errored
	mockActionTriggers.On("TriggerRetrieveGasPrice", mock.Anything).Return(fmt.Errorf("gasPriceError")).Once()
	stateManager.StartNewStageContext(ctx, baseTypes.InFlightTxStageRetrieveGasPrice, baseTypes.BaseTxSubStatusReceived)
	assert.Regexp(t, "gasPriceError", stateManager.GetStageTriggerError(ctx))
	// retrieve gas price success
	mockActionTriggers.On("TriggerRetrieveGasPrice", mock.Anything).Return(nil).Once()
	stateManager.StartNewStageContext(ctx, baseTypes.InFlightTxStageRetrieveGasPrice, baseTypes.BaseTxSubStatusReceived)
	assert.Nil(t, stateManager.GetStageTriggerError(ctx))

	var nilBytes []byte
	// scenario A: no signer configured, do submission
	mockActionTriggers.On("TriggerSubmitTx", mock.Anything, nilBytes).Return(nil).Once()

	stateManager.StartNewStageContext(ctx, baseTypes.InFlightTxStageSubmitting, baseTypes.BaseTxSubStatusReceived)
	assert.Nil(t, stateManager.GetStageTriggerError(ctx))

	// scenario B: signer configured sign the data
	mockActionTriggers.On("TriggerSignTx", mock.Anything).Return(nil).Once()
	stateManager.StartNewStageContext(ctx, baseTypes.InFlightTxStageSigning, baseTypes.BaseTxSubStatusReceived)
	assert.Nil(t, stateManager.GetStageTriggerError(ctx))
	// persist the signed data as transient output
	testSignedData := []byte("test signed data")
	stateManager.SetTransientPreviousStageOutputs(&baseTypes.TransientPreviousStageOutputs{
		SignedMessage: testSignedData,
	})
	// do the submission
	mockActionTriggers.On("TriggerSubmitTx", mock.Anything, testSignedData).Return(nil).Once()
	stateManager.StartNewStageContext(ctx, baseTypes.InFlightTxStageSubmitting, baseTypes.BaseTxSubStatusReceived)
	assert.Nil(t, stateManager.GetStageTriggerError(ctx))

	// start tracking  no actions need to be triggered
	stateManager.StartNewStageContext(ctx, baseTypes.InFlightTxStageConfirming, baseTypes.BaseTxSubStatusTracking)
	assert.Nil(t, stateManager.GetStageTriggerError(ctx))

	// test clear running stage context
	assert.NotNil(t, stateManager.GetRunningStageContext(ctx))
	stateManager.ClearRunningStageContext(ctx)
	assert.Nil(t, stateManager.GetRunningStageContext(ctx))
	// try to clear running stage context when there isn't one shouldn't throw error
	stateManager.ClearRunningStageContext(ctx)
	assert.Nil(t, stateManager.GetRunningStageContext(ctx))

}

func TestStateManagerStageOutputManagement(t *testing.T) {
	ctx := context.Background()
	testStateManagerWithMocks := newTestInFlightTransactionStateManager(t)
	stateManager := testStateManagerWithMocks.stateManager
	expectedNumberOfPersistenceSuccessOutput := 342
	expectedNumberOfPersistenceErrorOutput := 50
	expectedNumberOfSubmitSuccessOutput := 234
	expectedNumberOfSubmitErrorOutput := 67
	expectedNumberOfSignSuccessOutput := 843
	expectedNumberOfSignErrorOutput := 452
	expectedNumberOfGasPriceSuccessOutput := 123
	expectedNumberOfGasPriceErrorOutput := 34
	expectedNumberOfConfirmationsOutput := 47
	expectedNumberOfPanicOutput := 19
	totalOutputAdd := expectedNumberOfPersistenceSuccessOutput + expectedNumberOfPersistenceErrorOutput + expectedNumberOfSubmitSuccessOutput + expectedNumberOfSubmitErrorOutput + expectedNumberOfSignSuccessOutput + expectedNumberOfSignErrorOutput + expectedNumberOfGasPriceSuccessOutput + expectedNumberOfGasPriceErrorOutput + expectedNumberOfConfirmationsOutput + expectedNumberOfPanicOutput
	countChanel := make(chan bool, totalOutputAdd)

	go func() {
		for i := 0; i < expectedNumberOfPersistenceSuccessOutput; i++ {
			go func() {
				stateManager.AddPersistenceOutput(ctx, baseTypes.InFlightTxStageConfirming, time.Now(), nil)
				countChanel <- true
			}()
		}
	}()
	go func() {
		for i := 0; i < expectedNumberOfPersistenceErrorOutput; i++ {
			go func() {
				stateManager.AddPersistenceOutput(ctx, baseTypes.InFlightTxStageConfirming, time.Now(), fmt.Errorf("error"))
				countChanel <- true
			}()
		}

	}()
	go func() {
		for i := 0; i < expectedNumberOfSubmitSuccessOutput; i++ {
			go func() {
				stateManager.AddSubmitOutput(ctx, "txHash", fftypes.Now(), baseTypes.SubmissionOutcomeAlreadyKnown, "", nil)
				countChanel <- true
			}()
		}

	}()
	go func() {
		for i := 0; i < expectedNumberOfSubmitErrorOutput; i++ {
			go func() {
				stateManager.AddSubmitOutput(ctx, "", fftypes.Now(), baseTypes.SubmissionOutcomeFailedRequiresRetry, "error", fmt.Errorf("error"))
				countChanel <- true
			}()
		}

	}()
	go func() {
		for i := 0; i < expectedNumberOfSignSuccessOutput; i++ {
			go func() {
				stateManager.AddSignOutput(ctx, []byte("data"), "txHash", nil)
				countChanel <- true
			}()
		}
	}()
	go func() {
		for i := 0; i < expectedNumberOfSignErrorOutput; i++ {
			go func() {
				stateManager.AddSignOutput(ctx, nil, "", fmt.Errorf("error"))
				countChanel <- true
			}()
		}
	}()
	go func() {
		for i := 0; i < expectedNumberOfGasPriceSuccessOutput; i++ {
			go func() {
				stateManager.AddGasPriceOutput(ctx, &baseTypes.GasPriceObject{
					GasPrice: big.NewInt(100),
				}, nil)
				countChanel <- true
			}()
		}
	}()
	go func() {
		for i := 0; i < expectedNumberOfGasPriceErrorOutput; i++ {
			go func() {
				stateManager.AddGasPriceOutput(ctx, nil, fmt.Errorf("error"))
				countChanel <- true
			}()
		}
	}()
	go func() {
		for i := 0; i < expectedNumberOfConfirmationsOutput; i++ {
			go func() {
				stateManager.AddConfirmationsOutput(ctx, nil)
				countChanel <- true
			}()
		}
	}()
	go func() {
		for i := 0; i < expectedNumberOfPanicOutput; i++ {
			go func() {
				stateManager.AddPanicOutput(ctx, baseTypes.InFlightTxStageConfirming)
				countChanel <- true
			}()
		}
	}()
	resultCount := 0

	// wait for all add output to complete
	for {
		select {
		case <-countChanel:
			resultCount++
		case <-ctx.Done():
			return
		}
		if resultCount == totalOutputAdd {
			break
		}
	}

	var actualNumberOfPersistenceSuccessOutput,
		actualNumberOfPersistenceErrorOutput,
		actualNumberOfSubmitSuccessOutput,
		actualNumberOfSubmitErrorOutput,
		actualNumberOfSignSuccessOutput,
		actualNumberOfSignErrorOutput,
		actualNumberOfGasPriceSuccessOutput,
		actualNumberOfGasPriceErrorOutput,
		actualNumberOfConfirmationsOutput,
		actualNumberOfPanicOutput int

	stateManager.ProcessStageOutputs(ctx, func(stageOutputs []*baseTypes.StageOutput) (unprocessedStageOutputs []*baseTypes.StageOutput) {
		unprocessedStageOutputs = make([]*baseTypes.StageOutput, 0)
		for _, stageOutput := range stageOutputs {
			if stageOutput.ConfirmationOutput != nil {
				actualNumberOfConfirmationsOutput++
			} else if stageOutput.GasPriceOutput != nil {
				if stageOutput.GasPriceOutput.Err == nil {
					actualNumberOfGasPriceSuccessOutput++
				} else {
					actualNumberOfGasPriceErrorOutput++
				}
			} else if stageOutput.SubmitOutput != nil {
				if stageOutput.SubmitOutput.Err == nil {
					actualNumberOfSubmitSuccessOutput++
				} else {
					actualNumberOfSubmitErrorOutput++
				}
			} else if stageOutput.SignOutput != nil {
				if stageOutput.SignOutput.Err == nil {
					actualNumberOfSignSuccessOutput++
				} else {
					actualNumberOfSignErrorOutput++
				}
			} else if stageOutput.PersistenceOutput != nil {
				if stageOutput.PersistenceOutput.PersistenceError == nil {
					actualNumberOfPersistenceSuccessOutput++
				} else {
					actualNumberOfPersistenceErrorOutput++
				}
			} else {
				actualNumberOfPanicOutput++
				// pretend we don't want to process the panic out
				unprocessedStageOutputs = append(unprocessedStageOutputs, stageOutput)
			}
		}
		assert.Equal(t, expectedNumberOfConfirmationsOutput, actualNumberOfConfirmationsOutput)
		assert.Equal(t, expectedNumberOfPanicOutput, actualNumberOfPanicOutput)
		assert.Equal(t, expectedNumberOfGasPriceSuccessOutput, actualNumberOfGasPriceSuccessOutput)
		assert.Equal(t, expectedNumberOfGasPriceErrorOutput, actualNumberOfGasPriceErrorOutput)
		assert.Equal(t, expectedNumberOfSignSuccessOutput, actualNumberOfSignSuccessOutput)
		assert.Equal(t, expectedNumberOfSignErrorOutput, actualNumberOfSignErrorOutput)
		assert.Equal(t, expectedNumberOfSubmitSuccessOutput, actualNumberOfSubmitSuccessOutput)
		assert.Equal(t, expectedNumberOfSubmitErrorOutput, actualNumberOfSubmitErrorOutput)
		assert.Equal(t, expectedNumberOfPersistenceSuccessOutput, actualNumberOfPersistenceSuccessOutput)
		assert.Equal(t, expectedNumberOfPersistenceErrorOutput, actualNumberOfPersistenceErrorOutput)
		return
	})

	stateManager.ProcessStageOutputs(ctx, func(stageOutputs []*baseTypes.StageOutput) (unprocessedStageOutputs []*baseTypes.StageOutput) {
		// only panic outputs aren't processed
		assert.Equal(t, expectedNumberOfPanicOutput, len(stageOutputs))
		return
	})
}

func TestStateManagerTxPersistenceManagementTransactionConfirmed(t *testing.T) {
	ctx := context.Background()
	testStateManagerWithMocks := newTestInFlightTransactionStateManager(t)

	stateManager := testStateManagerWithMocks.stateManager

	// cannot persist when there is no running context
	_, _, err := stateManager.PersistTxState(ctx)
	assert.NotNil(t, err)
	assert.Regexp(t, "PD011918", err)

	// set a running context
	mockActionTriggers := testStateManagerWithMocks.mAT
	defer mockActionTriggers.AssertExpectations(t)
	stateManager.StartNewStageContext(ctx, baseTypes.InFlightTxStageConfirming, baseTypes.BaseTxSubStatusTracking)

	// cannot persist when running context hasn't set persistence output
	_, _, err = stateManager.PersistTxState(ctx)
	assert.NotNil(t, err)
	assert.Regexp(t, "PD011918", err)

	rsc := stateManager.GetRunningStageContext(ctx)
	rsc.SetNewPersistenceUpdateOutput()
	// now test different combinations of persistence
	_, _, err = stateManager.PersistTxState(ctx)
	assert.Nil(t, err)

	inMemoryTxState := testStateManagerWithMocks.inMemoryTxState

	assert.Equal(t, stateManager.GetTxID(), inMemoryTxState.GetTxID())
	assert.False(t, inMemoryTxState.IsComplete())

	newTime := fftypes.Now()
	newTxHash := tktypes.Bytes32Keccak([]byte("0x00003")).String()
	newSubmittedHashes := []string{
		tktypes.Bytes32Keccak([]byte("0x00000")).String(),
		tktypes.Bytes32Keccak([]byte("0x00001")).String(),
		tktypes.Bytes32Keccak([]byte("0x00002")).String(),
		tktypes.Bytes32Keccak([]byte("0x00003")).String(),
	}
	newStatus := baseTypes.BaseTxStatusSucceeded
	newGas := ethtypes.NewHexInteger64(111)
	newGasPrice := ethtypes.NewHexInteger64(111)

	testConfirmedTx := &blockindexer.IndexedTransaction{
		BlockNumber:      int64(1233),
		TransactionIndex: int64(23),
		Hash:             tktypes.MustParseBytes32(newTxHash),
		Result:           blockindexer.TXResult_SUCCESS.Enum(),
	}

	rsc.StageOutputsToBePersisted.ConfirmedTransaction = testConfirmedTx
	rsc.StageOutputsToBePersisted.TxUpdates = &baseTypes.BaseTXUpdates{
		Status:          &newStatus,
		DeleteRequested: newTime,
		GasPrice:        newGasPrice,
		TransactionHash: &newTxHash,
		FirstSubmit:     newTime,
		LastSubmit:      newTime,
		GasLimit:        newGas,
	}
	mTS := testStateManagerWithMocks.mTS
	txID := stateManager.GetTxID()
	mTS.On("SetConfirmedTransaction", mock.Anything, txID, testConfirmedTx).Return(nil).Once()
	mTS.On("AddSubStatusAction", mock.Anything, txID, baseTypes.BaseTxSubStatusTracking, baseTypes.BaseTxActionConfirmTransaction, (*fftypes.JSONAny)(nil), (*fftypes.JSONAny)(nil), mock.Anything).Return(nil).Once()
	mTS.On("UpdateTransaction", mock.Anything, txID, rsc.StageOutputsToBePersisted.TxUpdates).Return(nil).Once()
	_, _, err = stateManager.PersistTxState(ctx)
	assert.Nil(t, err)
	assert.Equal(t, stateManager.GetTxID(), inMemoryTxState.GetTxID())

	assert.Equal(t, newTime, inMemoryTxState.GetDeleteRequestedTime())
	assert.Equal(t, testConfirmedTx, inMemoryTxState.GetConfirmedTransaction())
	assert.Equal(t, newTxHash, inMemoryTxState.GetTransactionHash())
	assert.Equal(t, newStatus, inMemoryTxState.GetStatus())
	assert.Equal(t, newGasPrice.BigInt(), inMemoryTxState.GetGasPriceObject().GasPrice)
	assert.Equal(t, newTime, inMemoryTxState.GetFirstSubmit())
	assert.Equal(t, newTime, inMemoryTxState.GetLastSubmitTime())
	assert.Equal(t, newSubmittedHashes, inMemoryTxState.GetSubmittedHashes())
	assert.Equal(t, newGas.BigInt(), inMemoryTxState.GetGasLimit())
	assert.True(t, inMemoryTxState.IsComplete())

	// only mark the transaction as can be removed when there is no longer a running stage
	assert.NotNil(t, stateManager.GetRunningStageContext(ctx))
	assert.False(t, stateManager.CanBeRemoved(ctx))

	stateManager.ClearRunningStageContext(ctx)
	assert.True(t, stateManager.CanBeRemoved(ctx))
}

func TestStateManagerTxPersistenceManagementTransactionConfirmedOnPreviousHash(t *testing.T) {
	ctx := context.Background()
	testStateManagerWithMocks := newTestInFlightTransactionStateManager(t)

	stateManager := testStateManagerWithMocks.stateManager

	// cannot persist when there is no running context
	_, _, err := stateManager.PersistTxState(ctx)
	assert.NotNil(t, err)
	assert.Regexp(t, "PD011918", err)

	// set a running context
	mockActionTriggers := testStateManagerWithMocks.mAT
	defer mockActionTriggers.AssertExpectations(t)
	stateManager.StartNewStageContext(ctx, baseTypes.InFlightTxStageConfirming, baseTypes.BaseTxSubStatusTracking)

	// cannot persist when running context hasn't set persistence output
	_, _, err = stateManager.PersistTxState(ctx)
	assert.NotNil(t, err)
	assert.Regexp(t, "PD011918", err)

	rsc := stateManager.GetRunningStageContext(ctx)
	rsc.SetNewPersistenceUpdateOutput()
	// now test different combinations of persistence
	_, _, err = stateManager.PersistTxState(ctx)
	assert.Nil(t, err)

	inMemoryTxState := testStateManagerWithMocks.inMemoryTxState

	assert.Equal(t, stateManager.GetTxID(), inMemoryTxState.GetTxID())
	assert.False(t, inMemoryTxState.IsComplete())

	newTime := fftypes.Now()
	newTxHash := tktypes.Bytes32Keccak([]byte("0x00002")).String()
	newSubmittedHashes := []string{
		tktypes.Bytes32Keccak([]byte("0x00000")).String(),
		tktypes.Bytes32Keccak([]byte("0x00001")).String(),
		tktypes.Bytes32Keccak([]byte("0x00002")).String(),
	}
	newStatus := baseTypes.BaseTxStatusSucceeded
	newGas := ethtypes.NewHexInteger64(111)
	newGasPrice := ethtypes.NewHexInteger64(111)

	testConfirmedTx := &blockindexer.IndexedTransaction{
		BlockNumber:      int64(1233),
		TransactionIndex: int64(23),
		Hash:             tktypes.Bytes32Keccak([]byte("0x00001")),
		Result:           blockindexer.TXResult_SUCCESS.Enum(),
	}

	rsc.StageOutputsToBePersisted.ConfirmedTransaction = testConfirmedTx
	rsc.StageOutputsToBePersisted.TxUpdates = &baseTypes.BaseTXUpdates{
		Status:          &newStatus,
		DeleteRequested: newTime,
		GasPrice:        newGasPrice,
		TransactionHash: &newTxHash,
		FirstSubmit:     newTime,
		LastSubmit:      newTime,
		GasLimit:        newGas,
	}
	mTS := testStateManagerWithMocks.mTS
	txID := stateManager.GetTxID()
	mTS.On("SetConfirmedTransaction", mock.Anything, txID, testConfirmedTx).Return(nil).Once()
	mTS.On("AddSubStatusAction", mock.Anything, txID, baseTypes.BaseTxSubStatusTracking, baseTypes.BaseTxActionConfirmTransaction, (*fftypes.JSONAny)(nil), (*fftypes.JSONAny)(nil), mock.Anything).Return(nil).Once()
	mTS.On("UpdateTransaction", mock.Anything, txID, rsc.StageOutputsToBePersisted.TxUpdates).Return(nil).Once()
	_, _, err = stateManager.PersistTxState(ctx)
	assert.Nil(t, err)
	assert.Equal(t, stateManager.GetTxID(), inMemoryTxState.GetTxID())

	assert.Equal(t, newTime, inMemoryTxState.GetDeleteRequestedTime())
	assert.Equal(t, testConfirmedTx, inMemoryTxState.GetConfirmedTransaction())
	assert.Equal(t, newTxHash, inMemoryTxState.GetTransactionHash())
	assert.Equal(t, newStatus, inMemoryTxState.GetStatus())
	assert.Equal(t, newGasPrice.BigInt(), inMemoryTxState.GetGasPriceObject().GasPrice)
	assert.Equal(t, newTime, inMemoryTxState.GetFirstSubmit())
	assert.Equal(t, newTime, inMemoryTxState.GetLastSubmitTime())
	assert.Equal(t, newSubmittedHashes, inMemoryTxState.GetSubmittedHashes())
	assert.Equal(t, newGas.BigInt(), inMemoryTxState.GetGasLimit())
	assert.True(t, inMemoryTxState.IsComplete())

	// only mark the transaction as can be removed when there is no longer a running stage
	assert.NotNil(t, stateManager.GetRunningStageContext(ctx))
	assert.False(t, stateManager.CanBeRemoved(ctx))

	stateManager.ClearRunningStageContext(ctx)
	assert.True(t, stateManager.CanBeRemoved(ctx))
}

func TestStateManagerTxPersistenceManagementTransactionConfirmedRetrieveConfirmedTXAndTxFailed(t *testing.T) {
	ctx := context.Background()
	testStateManagerWithMocks := newTestInFlightTransactionStateManager(t)

	stateManager := testStateManagerWithMocks.stateManager

	// cannot persist when there is no running context
	_, _, err := stateManager.PersistTxState(ctx)
	assert.NotNil(t, err)
	assert.Regexp(t, "PD011918", err)

	// set a running context
	stateManager.StartNewStageContext(ctx, baseTypes.InFlightTxStageConfirming, baseTypes.BaseTxSubStatusTracking)

	// cannot persist when running context hasn't set persistence output
	_, _, err = stateManager.PersistTxState(ctx)
	assert.NotNil(t, err)
	assert.Regexp(t, "PD011918", err)

	rsc := stateManager.GetRunningStageContext(ctx)
	rsc.SetNewPersistenceUpdateOutput()
	// now test different combinations of persistence
	_, _, err = stateManager.PersistTxState(ctx)
	assert.Nil(t, err)

	inMemoryTxState := testStateManagerWithMocks.inMemoryTxState

	assert.Equal(t, stateManager.GetTxID(), inMemoryTxState.GetTxID())
	assert.False(t, inMemoryTxState.IsComplete())

	newTime := fftypes.Now()
	newStatus := baseTypes.BaseTxStatusFailed
	newGas := ethtypes.NewHexInteger64(111)
	newGasPrice := ethtypes.NewHexInteger64(111)
	newTxHash := tktypes.Bytes32Keccak([]byte("0x00003")).String()
	newSubmittedHashes := []string{
		tktypes.Bytes32Keccak([]byte("0x00000")).String(),
		tktypes.Bytes32Keccak([]byte("0x00001")).String(),
		tktypes.Bytes32Keccak([]byte("0x00002")).String(),
	}
	testConfirmedTx := &blockindexer.IndexedTransaction{
		BlockNumber:      int64(1233),
		TransactionIndex: int64(23),
		Hash:             tktypes.MustParseBytes32(newTxHash),
		Result:           blockindexer.TXResult_FAILURE.Enum(),
	}

	rsc.StageOutputsToBePersisted.ConfirmedTransaction = testConfirmedTx
	rsc.StageOutputsToBePersisted.TxUpdates = &baseTypes.BaseTXUpdates{
		Status:          &newStatus,
		DeleteRequested: newTime,
		GasPrice:        newGasPrice,
		TransactionHash: &newTxHash,
		FirstSubmit:     newTime,
		LastSubmit:      newTime,
		SubmittedHashes: newSubmittedHashes,
		GasLimit:        newGas,
	}

	mTS := testStateManagerWithMocks.mTS
	txID := stateManager.GetTxID()
	mTS.On("SetConfirmedTransaction", mock.Anything, txID, testConfirmedTx).Return(nil).Once()
	mTS.On("AddSubStatusAction", mock.Anything, txID, baseTypes.BaseTxSubStatusTracking, baseTypes.BaseTxActionConfirmTransaction, (*fftypes.JSONAny)(nil), (*fftypes.JSONAny)(nil), mock.Anything).Return(nil).Once()
	mTS.On("UpdateTransaction", mock.Anything, txID, rsc.StageOutputsToBePersisted.TxUpdates).Return(nil).Once()
	_, _, err = stateManager.PersistTxState(ctx)
	assert.Nil(t, err)
	assert.Equal(t, stateManager.GetTxID(), inMemoryTxState.GetTxID())

	assert.Equal(t, newTime, inMemoryTxState.GetDeleteRequestedTime())
	assert.Equal(t, testConfirmedTx, inMemoryTxState.GetConfirmedTransaction())
	assert.Equal(t, newTxHash, inMemoryTxState.GetTransactionHash())
	assert.Equal(t, newStatus, inMemoryTxState.GetStatus())
	assert.Equal(t, newGasPrice.BigInt(), inMemoryTxState.GetGasPriceObject().GasPrice)
	assert.Equal(t, newTime, inMemoryTxState.GetFirstSubmit())
	assert.Equal(t, newTime, inMemoryTxState.GetLastSubmitTime())
	assert.Equal(t, append(newSubmittedHashes[:], newTxHash), inMemoryTxState.GetSubmittedHashes())
	assert.Equal(t, newGas.BigInt(), inMemoryTxState.GetGasLimit())
	assert.True(t, inMemoryTxState.IsComplete())
}

func TestStateManagerTxPersistenceManagementUpdateErrors(t *testing.T) {
	ctx := context.Background()
	testStateManagerWithMocks := newTestInFlightTransactionStateManager(t)

	stateManager := testStateManagerWithMocks.stateManager

	// cannot persist when there is no running context
	_, _, err := stateManager.PersistTxState(ctx)
	assert.NotNil(t, err)
	assert.Regexp(t, "PD011918", err)

	// set a running context
	stateManager.StartNewStageContext(ctx, baseTypes.InFlightTxStageConfirming, baseTypes.BaseTxSubStatusTracking)

	// cannot persist when running context hasn't set persistence output
	_, _, err = stateManager.PersistTxState(ctx)
	assert.NotNil(t, err)
	assert.Regexp(t, "PD011918", err)

	rsc := stateManager.GetRunningStageContext(ctx)
	rsc.SetNewPersistenceUpdateOutput()
	// now test different combinations of persistence
	_, _, err = stateManager.PersistTxState(ctx)
	assert.Nil(t, err)

	inMemoryTxState := testStateManagerWithMocks.inMemoryTxState

	assert.Equal(t, stateManager.GetTxID(), inMemoryTxState.GetTxID())
	assert.False(t, inMemoryTxState.IsComplete())

	newTxHash := tktypes.Bytes32Keccak([]byte("0x00003")).String()
	// confirmed tx update error
	newSubmittedHashes := []string{
		tktypes.Bytes32Keccak([]byte("0x00000")).String(),
		tktypes.Bytes32Keccak([]byte("0x00001")).String(),
		tktypes.Bytes32Keccak([]byte("0x00002")).String(),
	}
	testConfirmedTx := &blockindexer.IndexedTransaction{
		BlockNumber:      int64(1233),
		TransactionIndex: int64(23),
		Hash:             tktypes.MustParseBytes32(newTxHash),
		Result:           blockindexer.TXResult_SUCCESS.Enum(),
	}

	rsc.StageOutputsToBePersisted.ConfirmedTransaction = testConfirmedTx
	rsc.StageOutputsToBePersisted.TxUpdates = &baseTypes.BaseTXUpdates{
		SubmittedHashes: newSubmittedHashes,
	}

	mTS := testStateManagerWithMocks.mTS
	txID := stateManager.GetTxID()
	// set confirmed tx fail
	mTS.On("SetConfirmedTransaction", mock.Anything, txID, testConfirmedTx).Return(fmt.Errorf("SetConfirmedTransaction error")).Once()
	_, _, err = stateManager.PersistTxState(ctx)
	assert.NotNil(t, err)
	assert.Regexp(t, "SetConfirmedTransaction error", err)

	mBI := testStateManagerWithMocks.mBI

	// get confirmed tx fail
	rsc.StageOutputsToBePersisted.ConfirmedTransaction = nil
	rsc.StageOutputsToBePersisted.MissedConfirmationEvent = true
	mBI.On("GetIndexedTransactionByNonce", mock.Anything, *tktypes.MustEthAddress(stateManager.GetFrom()), stateManager.GetNonce().Uint64()).Return(nil, fmt.Errorf("GetIndexedTransactionByNonce error")).Once() // recovered by retry
	mBI.On("GetIndexedTransactionByNonce", mock.Anything, *tktypes.MustEthAddress(stateManager.GetFrom()), stateManager.GetNonce().Uint64()).Return(nil, nil).Once()                                              // triggers the not found error
	_, _, err = stateManager.PersistTxState(ctx)
	assert.NotNil(t, err)
	assert.Regexp(t, "PD011930", err)

	// history update fail
	mBI.On("GetIndexedTransactionByNonce", mock.Anything, *tktypes.MustEthAddress(stateManager.GetFrom()), stateManager.GetNonce().Uint64()).Return(testConfirmedTx, nil)
	mTS.On("SetConfirmedTransaction", mock.Anything, txID, testConfirmedTx).Return(nil)
	mTS.On("AddSubStatusAction", mock.Anything, txID, baseTypes.BaseTxSubStatusTracking, baseTypes.BaseTxActionConfirmTransaction, (*fftypes.JSONAny)(nil), (*fftypes.JSONAny)(nil), mock.Anything).Return(fmt.Errorf("AddSubStatusAction error")).Once()
	_, _, err = stateManager.PersistTxState(ctx)
	assert.NotNil(t, err)
	assert.Regexp(t, "AddSubStatusAction error", err)

	// update transaction fail
	mTS.On("AddSubStatusAction", mock.Anything, txID, baseTypes.BaseTxSubStatusTracking, baseTypes.BaseTxActionConfirmTransaction, (*fftypes.JSONAny)(nil), (*fftypes.JSONAny)(nil), mock.Anything).Return(nil).Once()
	mTS.On("UpdateTransaction", mock.Anything, txID, rsc.StageOutputsToBePersisted.TxUpdates).Return(fmt.Errorf("UpdateTransaction error")).Once()
	_, _, err = stateManager.PersistTxState(ctx)
	assert.NotNil(t, err)
	assert.Regexp(t, "UpdateTransaction error", err)
}
