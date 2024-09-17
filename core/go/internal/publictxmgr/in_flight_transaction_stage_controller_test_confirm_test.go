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
	"fmt"
	"math/big"
	"testing"
	"time"

	"github.com/hyperledger/firefly-common/pkg/fftypes"
	"github.com/kaleido-io/paladin/core/internal/components"
	baseTypes "github.com/kaleido-io/paladin/core/internal/engine/enginespi"
	"github.com/kaleido-io/paladin/core/pkg/blockindexer"
	"github.com/kaleido-io/paladin/toolkit/pkg/tktypes"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

func TestProduceLatestInFlightStageContextConfirming(t *testing.T) {
	ctx := context.Background()
	testInFlightTransactionStateManagerWithMocks := NewTestInFlightTransactionWithMocks(t)
	it := testInFlightTransactionStateManagerWithMocks.it

	inFlightStageMananger := it.stateManager.(*inFlightTransactionState)

	// set validated to enter tracking
	it.stateManager.SetValidatedTransactionHashMatchState(ctx, true)
	tOut := it.ProduceLatestInFlightStageContext(ctx, &baseTypes.OrchestratorContext{
		AvailableToSpend:         nil,
		PreviousNonceCostUnknown: false,
	})
	assert.NotEmpty(t, *tOut)
	assert.Equal(t, "20000", tOut.Cost.String())
	assert.True(t, tOut.TransactionSubmitted)
	assert.Equal(t, baseTypes.InFlightTxStageConfirming, inFlightStageMananger.stage)

	// move to confirming
	it.stateManager.AddPersistenceOutput(ctx, baseTypes.InFlightTxStageConfirming, time.Now(), nil)
	tOut = it.ProduceLatestInFlightStageContext(ctx, &baseTypes.OrchestratorContext{
		AvailableToSpend:         nil,
		PreviousNonceCostUnknown: true,
	})
	assert.NotEmpty(t, *tOut)
	assert.Equal(t, "20000", tOut.Cost.String())
	assert.True(t, tOut.TransactionSubmitted)
	assert.Equal(t, baseTypes.InFlightTxStageConfirming, inFlightStageMananger.stage)

	mTS := testInFlightTransactionStateManagerWithMocks.mTS
	defer mTS.AssertExpectations(t)
	testConfirmedTx := &blockindexer.IndexedTransaction{
		BlockNumber:      int64(1233),
		TransactionIndex: int64(23),
		Hash:             tktypes.Bytes32Keccak([]byte("test")),
		Result:           blockindexer.TXResult_SUCCESS.Enum(),
	}

	// persist confirmation
	inFlightStageMananger.bufferedStageOutputs = make([]*baseTypes.StageOutput, 0)
	rsc := it.stateManager.GetRunningStageContext(ctx)
	rsc.SetNewPersistenceUpdateOutput()
	it.stateManager.AddConfirmationsOutput(ctx, testConfirmedTx)
	assert.GreaterOrEqual(t, len(inFlightStageMananger.bufferedStageOutputs), 1)
	tOut = it.ProduceLatestInFlightStageContext(ctx, &baseTypes.OrchestratorContext{
		AvailableToSpend:         nil,
		PreviousNonceCostUnknown: false,
	})
	assert.NotEmpty(t, *tOut)
	assert.Equal(t, "20000", tOut.Cost.String())
	assert.True(t, tOut.TransactionSubmitted)
	assert.NotNil(t, rsc.StageOutputsToBePersisted)
	assert.Equal(t, testConfirmedTx, rsc.StageOutputsToBePersisted.ConfirmedTransaction)

	// persisting error waiting for persistence retry timeout
	rsc.StageErrored = false
	it.persistenceRetryTimeout = 5 * time.Second
	inFlightStageMananger.bufferedStageOutputs = make([]*baseTypes.StageOutput, 0)
	it.stateManager.AddPersistenceOutput(ctx, baseTypes.InFlightTxStageConfirming, time.Now().Add(it.persistenceRetryTimeout*2), fmt.Errorf("persist confirmation error"))
	tOut = it.ProduceLatestInFlightStageContext(ctx, &baseTypes.OrchestratorContext{
		AvailableToSpend:         nil,
		PreviousNonceCostUnknown: true,
	})
	assert.NotEmpty(t, *tOut)
	assert.Equal(t, "20000", tOut.Cost.String())
	assert.True(t, tOut.TransactionSubmitted)

	// persisting error retrying
	assert.False(t, rsc.StageErrored)
	it.persistenceRetryTimeout = 0
	inFlightStageMananger.bufferedStageOutputs = make([]*baseTypes.StageOutput, 0)
	it.stateManager.AddPersistenceOutput(ctx, baseTypes.InFlightTxStageConfirming, time.Now(), fmt.Errorf("persist confirmation error"))
	tOut = it.ProduceLatestInFlightStageContext(ctx, &baseTypes.OrchestratorContext{
		AvailableToSpend:         nil,
		PreviousNonceCostUnknown: true,
	})
	assert.NotEmpty(t, *tOut)
	assert.Equal(t, "20000", tOut.Cost.String())
	assert.True(t, tOut.TransactionSubmitted)
	it.persistenceRetryTimeout = 5 * time.Second

	// persisted stage success and wait for more confirmations
	inFlightStageMananger.bufferedStageOutputs = make([]*baseTypes.StageOutput, 0)
	it.stateManager.AddPersistenceOutput(ctx, baseTypes.InFlightTxStageConfirming, time.Now(), nil)
	rsc.StageErrored = false
	it.stateManager.SetValidatedTransactionHashMatchState(ctx, true)
	tOut = it.ProduceLatestInFlightStageContext(ctx, &baseTypes.OrchestratorContext{
		AvailableToSpend:         nil,
		PreviousNonceCostUnknown: true,
	})
	assert.NotEmpty(t, *tOut)
	assert.Equal(t, "20000", tOut.Cost.String())
	assert.True(t, tOut.TransactionSubmitted)
	rsc = it.stateManager.GetRunningStageContext(ctx)
	assert.Nil(t, rsc.StageOutputsToBePersisted)
}

func TestProduceLatestInFlightStageContextConfirmingTxFailed(t *testing.T) {
	ctx := context.Background()
	testInFlightTransactionStateManagerWithMocks := NewTestInFlightTransactionWithMocks(t)
	it := testInFlightTransactionStateManagerWithMocks.it

	inFlightStageMananger := it.stateManager.(*inFlightTransactionState)

	// set validated to enter tracking
	it.stateManager.SetValidatedTransactionHashMatchState(ctx, true)
	tOut := it.ProduceLatestInFlightStageContext(ctx, &baseTypes.OrchestratorContext{
		AvailableToSpend:         nil,
		PreviousNonceCostUnknown: false,
	})
	assert.NotEmpty(t, *tOut)
	assert.Equal(t, "20000", tOut.Cost.String())
	assert.True(t, tOut.TransactionSubmitted)
	assert.Equal(t, baseTypes.InFlightTxStageConfirming, inFlightStageMananger.stage)
	mtx := it.stateManager.GetTx()
	// move to confirming
	it.stateManager.AddPersistenceOutput(ctx, baseTypes.InFlightTxStageConfirming, time.Now(), nil)
	tOut = it.ProduceLatestInFlightStageContext(ctx, &baseTypes.OrchestratorContext{
		AvailableToSpend:         nil,
		PreviousNonceCostUnknown: true,
	})
	assert.NotEmpty(t, *tOut)
	assert.Equal(t, "20000", tOut.Cost.String())
	assert.True(t, tOut.TransactionSubmitted)
	assert.Equal(t, baseTypes.InFlightTxStageConfirming, inFlightStageMananger.stage)
	mEN := testInFlightTransactionStateManagerWithMocks.mEN

	rsc := it.stateManager.GetRunningStageContext(ctx)
	// persisted stage success and transaction completed with error
	notifyMock := mEN.On("Notify", ctx, mock.Anything)

	notifyMock.Run(func(args mock.Arguments) {
		transactionEvent := args[1].(components.ManagedTransactionEvent)
		assert.Equal(t, components.ManagedTXProcessFailed, transactionEvent.Type)
		notifyMock.Return(nil)
	}).Once()
	inFlightStageMananger.bufferedStageOutputs = make([]*baseTypes.StageOutput, 0)
	it.stateManager.AddPersistenceOutput(ctx, baseTypes.InFlightTxStageConfirming, time.Now(), nil)
	mtx.Status = components.BaseTxStatusFailed
	it.stateManager.SetValidatedTransactionHashMatchState(ctx, true)
	tOut = it.ProduceLatestInFlightStageContext(ctx, &baseTypes.OrchestratorContext{
		AvailableToSpend:         nil,
		PreviousNonceCostUnknown: true,
	})
	assert.NotEmpty(t, *tOut)
	assert.Equal(t, "20000", tOut.Cost.String())
	assert.True(t, tOut.TransactionSubmitted)
	// switched running stage context
	assert.NotEqual(t, rsc, it.stateManager.GetRunningStageContext(ctx))

}

func TestProduceLatestInFlightStageContextConfirmingTxSucceeded(t *testing.T) {
	ctx := context.Background()
	testInFlightTransactionStateManagerWithMocks := NewTestInFlightTransactionWithMocks(t)
	it := testInFlightTransactionStateManagerWithMocks.it
	inFlightStageMananger := it.stateManager.(*inFlightTransactionState)
	mtx := it.stateManager.GetTx()
	mEN := testInFlightTransactionStateManagerWithMocks.mEN
	// set validated to enter tracking
	it.stateManager.SetValidatedTransactionHashMatchState(ctx, true)
	tOut := it.ProduceLatestInFlightStageContext(ctx, &baseTypes.OrchestratorContext{
		AvailableToSpend:         nil,
		PreviousNonceCostUnknown: false,
	})
	assert.NotEmpty(t, *tOut)
	assert.Equal(t, "20000", tOut.Cost.String())
	assert.True(t, tOut.TransactionSubmitted)
	assert.Equal(t, baseTypes.InFlightTxStageConfirming, inFlightStageMananger.stage)

	// move to confirming
	it.stateManager.AddPersistenceOutput(ctx, baseTypes.InFlightTxStageConfirming, time.Now(), nil)
	tOut = it.ProduceLatestInFlightStageContext(ctx, &baseTypes.OrchestratorContext{
		AvailableToSpend:         nil,
		PreviousNonceCostUnknown: true,
	})
	assert.NotEmpty(t, *tOut)
	assert.Equal(t, "20000", tOut.Cost.String())
	assert.True(t, tOut.TransactionSubmitted)
	assert.Equal(t, baseTypes.InFlightTxStageConfirming, inFlightStageMananger.stage)

	rsc := it.stateManager.GetRunningStageContext(ctx)
	// persisted stage success and transaction completed without error
	notifyMock := mEN.On("Notify", ctx, mock.Anything)

	notifyMock.Run(func(args mock.Arguments) {
		transactionEvent := args[1].(components.ManagedTransactionEvent)
		assert.Equal(t, components.ManagedTXProcessSucceeded, transactionEvent.Type)
		notifyMock.Return(nil)
	}).Once()
	inFlightStageMananger.bufferedStageOutputs = make([]*baseTypes.StageOutput, 0)
	it.stateManager.AddPersistenceOutput(ctx, baseTypes.InFlightTxStageConfirming, time.Now(), nil)
	mtx.Status = components.BaseTxStatusSucceeded
	rsc.StageErrored = false
	it.stateManager.SetValidatedTransactionHashMatchState(ctx, true)
	tOut = it.ProduceLatestInFlightStageContext(ctx, &baseTypes.OrchestratorContext{
		AvailableToSpend:         nil,
		PreviousNonceCostUnknown: true,
	})
	assert.NotEmpty(t, *tOut)
	assert.Equal(t, "20000", tOut.Cost.String())
	assert.True(t, tOut.TransactionSubmitted)
	// switched running stage context
	assert.NotEqual(t, rsc, inFlightStageMananger.GetRunningStageContext(ctx))
}

func TestProduceLatestInFlightStageContextTriggerResubmissionForStaledConfirmation(t *testing.T) {
	ctx := context.Background()
	testInFlightTransactionStateManagerWithMocks := NewTestInFlightTransactionWithMocks(t)
	it := testInFlightTransactionStateManagerWithMocks.it

	inFlightStageMananger := it.stateManager.(*inFlightTransactionState)
	inFlightStageMananger.testOnlyNoEventMode = true
	it.testOnlyNoActionMode = true
	it.testOnlyNoEventMode = true
	mtx := it.stateManager.GetTx()
	// set validated to enter tracking
	it.stateManager.SetValidatedTransactionHashMatchState(ctx, true)
	tOut := it.ProduceLatestInFlightStageContext(ctx, &baseTypes.OrchestratorContext{
		AvailableToSpend:         nil,
		PreviousNonceCostUnknown: false,
	})
	assert.NotEmpty(t, *tOut)
	assert.Equal(t, "20000", tOut.Cost.String())
	assert.True(t, tOut.TransactionSubmitted)
	assert.Equal(t, baseTypes.InFlightTxStageConfirming, inFlightStageMananger.stage)

	// set last submit to trigger resubmission
	inThePast := fftypes.ZeroTime()
	mtx.LastSubmit = &inThePast
	it.resubmitInterval = 0
	tOut = it.ProduceLatestInFlightStageContext(ctx, &baseTypes.OrchestratorContext{
		AvailableToSpend:         nil,
		PreviousNonceCostUnknown: false,
	})
	assert.NotEmpty(t, *tOut)
	assert.Equal(t, "20000", tOut.Cost.String())
	assert.True(t, tOut.TransactionSubmitted)
	assert.Equal(t, baseTypes.InFlightTxStageRetrieveGasPrice, inFlightStageMananger.stage)

}

func TestProduceLatestInFlightStageContextConfirmingTxThatMissedConfirmationEvent(t *testing.T) {
	ctx := context.Background()
	testInFlightTransactionStateManagerWithMocks := NewTestInFlightTransactionWithMocks(t)
	it := testInFlightTransactionStateManagerWithMocks.it

	inFlightStageMananger := it.stateManager.(*inFlightTransactionState)

	mTS := testInFlightTransactionStateManagerWithMocks.mTS
	defer mTS.AssertExpectations(t)
	// trigger confirmation due to missed event
	inFlightStageMananger.bufferedStageOutputs = make([]*baseTypes.StageOutput, 0)

	tOut := it.ProduceLatestInFlightStageContext(ctx, &baseTypes.OrchestratorContext{
		AvailableToSpend:         nil,
		PreviousNonceCostUnknown: false,
		CurrentConfirmedNonce:    new(big.Int).SetUint64(it.stateManager.GetNonce().Uint64() + 1),
	})
	assert.NotEmpty(t, *tOut)
	assert.Equal(t, "20000", tOut.Cost.String())
	assert.True(t, tOut.TransactionSubmitted)
	for len(inFlightStageMananger.bufferedStageOutputs) == 0 {
		// wait for the confirmation output to be added
	}
	assert.NotNil(t, inFlightStageMananger.bufferedStageOutputs[0].ConfirmationOutput)
	assert.Nil(t, inFlightStageMananger.bufferedStageOutputs[0].ConfirmationOutput.ConfirmedTransaction)
	assert.Equal(t, baseTypes.InFlightTxStageConfirming, inFlightStageMananger.stage)
}
func TestProduceLatestInFlightStageContextConfirmingPanic(t *testing.T) {
	ctx := context.Background()
	testInFlightTransactionStateManagerWithMocks := NewTestInFlightTransactionWithMocks(t)
	it := testInFlightTransactionStateManagerWithMocks.it

	inFlightStageMananger := it.stateManager.(*inFlightTransactionState)

	// set validated to enter tracking
	it.stateManager.SetValidatedTransactionHashMatchState(ctx, true)
	tOut := it.ProduceLatestInFlightStageContext(ctx, &baseTypes.OrchestratorContext{
		AvailableToSpend:         nil,
		PreviousNonceCostUnknown: false,
	})
	assert.NotEmpty(t, *tOut)
	assert.Equal(t, "20000", tOut.Cost.String())
	assert.True(t, tOut.TransactionSubmitted)
	assert.Equal(t, baseTypes.InFlightTxStageConfirming, inFlightStageMananger.stage)

	// move to confirming
	it.stateManager.AddPersistenceOutput(ctx, baseTypes.InFlightTxStageConfirming, time.Now(), nil)
	tOut = it.ProduceLatestInFlightStageContext(ctx, &baseTypes.OrchestratorContext{
		AvailableToSpend:         nil,
		PreviousNonceCostUnknown: true,
	})
	assert.NotEmpty(t, *tOut)
	assert.Equal(t, "20000", tOut.Cost.String())
	assert.True(t, tOut.TransactionSubmitted)
	assert.Equal(t, baseTypes.InFlightTxStageConfirming, inFlightStageMananger.stage)

	// mTS := testInFlightTransactionStateManagerWithMocks.mTS
	// defer mTS.AssertExpectations(t)

	// unexpected error
	inFlightStageMananger.bufferedStageOutputs = make([]*baseTypes.StageOutput, 0)
	it.stateManager.AddPanicOutput(ctx, baseTypes.InFlightTxStageConfirming)
	tOut = it.ProduceLatestInFlightStageContext(ctx, &baseTypes.OrchestratorContext{
		AvailableToSpend:         nil,
		PreviousNonceCostUnknown: false,
	})
	assert.NotEmpty(t, *tOut)
	assert.Equal(t, "20000", tOut.Cost.String())
	assert.True(t, tOut.TransactionSubmitted)
	assert.Regexp(t, "PD011919", tOut.Error)
	// re-enters tracking straight-away when panicked
	assert.Equal(t, baseTypes.InFlightTxStageConfirming, inFlightStageMananger.stage)
}

func TestProduceLatestInFlightStageContextSanityChecksForCompletedTransactions(t *testing.T) {
	ctx := context.Background()
	testInFlightTransactionStateManagerWithMocks := NewTestInFlightTransactionWithMocks(t)
	it := testInFlightTransactionStateManagerWithMocks.it
	inFlightStageMananger := it.stateManager.(*inFlightTransactionState)

	imtxs := inFlightStageMananger.InMemoryTxStateManager.(*inMemoryTxState)

	mtx := it.stateManager.GetTx()
	mtx.Status = components.BaseTxStatusSucceeded
	testConfirmedTx := &blockindexer.IndexedTransaction{
		BlockNumber:      int64(1233),
		TransactionIndex: int64(23),
		Hash:             tktypes.Bytes32Keccak([]byte("test")),
		Result:           blockindexer.TXResult_SUCCESS.Enum(),
	}

	imtxs.ConfirmedTransaction = testConfirmedTx
	tOut := it.ProduceLatestInFlightStageContext(ctx, &baseTypes.OrchestratorContext{
		AvailableToSpend:         nil,
		PreviousNonceCostUnknown: false,
	})
	assert.Empty(t, tOut.Cost) // cost for completed transaction should be 0
	assert.True(t, tOut.TransactionSubmitted)

}

func TestProduceLatestInFlightStageContextConfirmErroredAndExceededStageTimeout(t *testing.T) {
	ctx := context.Background()
	testInFlightTransactionStateManagerWithMocks := NewTestInFlightTransactionWithMocks(t)
	it := testInFlightTransactionStateManagerWithMocks.it
	inFlightStageMananger := it.stateManager.(*inFlightTransactionState)

	// set validated to enter tracking
	it.stateManager.SetValidatedTransactionHashMatchState(ctx, true)
	tOut := it.ProduceLatestInFlightStageContext(ctx, &baseTypes.OrchestratorContext{
		AvailableToSpend:         nil,
		PreviousNonceCostUnknown: false,
	})
	assert.NotEmpty(t, *tOut)
	assert.Equal(t, "20000", tOut.Cost.String())
	assert.True(t, tOut.TransactionSubmitted)

	assert.Equal(t, baseTypes.InFlightTxStageConfirming, inFlightStageMananger.stage)
	// stage errored and reached stage retry timeout
	it.stageRetryTimeout = 0
	rsc := it.stateManager.GetRunningStageContext(ctx)
	rsc.StageErrored = true
	assert.NotNil(t, rsc)
	assert.Equal(t, baseTypes.InFlightTxStageConfirming, rsc.Stage)
	tOut = it.ProduceLatestInFlightStageContext(ctx, &baseTypes.OrchestratorContext{
		AvailableToSpend:         nil,
		PreviousNonceCostUnknown: false,
	})
	assert.NotEmpty(t, *tOut)
	assert.Equal(t, "20000", tOut.Cost.String())
	assert.True(t, tOut.TransactionSubmitted)

	assert.NotEqual(t, rsc, it.stateManager.GetRunningStageContext(ctx))
	rsc = it.stateManager.GetRunningStageContext(ctx)
	assert.Equal(t, baseTypes.InFlightTxStageConfirming, rsc.Stage)
}
