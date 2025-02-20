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

// import (
// 	"fmt"
// 	"testing"
// 	"time"

// 	"github.com/stretchr/testify/assert"
// 	"github.com/stretchr/testify/require"
// )

// func TestProduceLatestInFlightStageContextTriggerStageError(t *testing.T) {
// 	ctx, o, _, done := newTestOrchestrator(t)
// 	defer done()
// 	it, _ := newInflightTransaction(o, 1)

// 	assert.Nil(t, it.stateManager.GetRunningStageContext(ctx))
// 	tOut := it.ProduceLatestInFlightStageContext(ctx, &OrchestratorContext{
// 		AvailableToSpend:         nil,
// 		PreviousNonceCostUnknown: true,
// 	})
// 	assert.Empty(t, *tOut)
// 	assert.NotNil(t, it.stateManager.GetRunningStageContext(ctx))
// 	rsc := it.stateManager.GetRunningStageContext(ctx)

// 	assert.Equal(t, InFlightTxStageRetrieveGasPrice, rsc.Stage)

// 	inFlightStageManager := it.stateManager.(*inFlightTransactionState)
// 	inFlightStageManager.stageTriggerError = fmt.Errorf("trigger stage error")

// 	tOut = it.ProduceLatestInFlightStageContext(ctx, &OrchestratorContext{
// 		AvailableToSpend:         nil,
// 		PreviousNonceCostUnknown: true,
// 	})
// 	assert.Empty(t, *tOut)
// 	assert.NotEqual(t, rsc, it.stateManager.GetRunningStageContext(ctx))
// 	assert.Nil(t, inFlightStageManager.stageTriggerError) // check stage trigger error has been reset
// }

// func TestProduceLatestInFlightStageContextStatusChange(t *testing.T) {
// 	ctx, o, _, done := newTestOrchestrator(t)
// 	defer done()
// 	it, ifts := newInflightTransaction(o, 1)

// 	// trigger status change
// 	assert.Nil(t, it.stateManager.GetRunningStageContext(ctx))
// 	suspended := InFlightStatusSuspending
// 	it.newStatus = &suspended
// 	iftxms := it.stateManager.(*inFlightTransactionState)
// 	iftxms.runningStageContext = NewRunningStageContext(ctx, InFlightTxStageStatusUpdate, BaseTxSubStatusReceived, iftxms)

// 	assert.NotNil(t, it.stateManager.GetRunningStageContext(ctx))
// 	rsc := it.stateManager.GetRunningStageContext(ctx)

// 	assert.Equal(t, InFlightTxStageStatusUpdate, rsc.Stage)

// 	inFlightStageMananger := it.stateManager.(*inFlightTransactionState)

// 	// persisting error waiting for persistence retry timeout
// 	it.persistenceRetryTimeout = 5 * time.Second
// 	inFlightStageMananger.bufferedStageOutputs = make([]*StageOutput, 0)
// 	it.stateManager.AddPersistenceOutput(ctx, InFlightTxStageStatusUpdate, time.Now().Add(it.persistenceRetryTimeout*2), fmt.Errorf("persist gas price error"))
// 	tOut := it.ProduceLatestInFlightStageContext(ctx, &OrchestratorContext{
// 		AvailableToSpend:         nil,
// 		PreviousNonceCostUnknown: true,
// 	})
// 	assert.Empty(t, *tOut)
// 	// persisting error retrying
// 	it.persistenceRetryTimeout = 0
// 	inFlightStageMananger.bufferedStageOutputs = make([]*StageOutput, 0)
// 	it.stateManager.AddPersistenceOutput(ctx, InFlightTxStageStatusUpdate, time.Now(), fmt.Errorf("persist gas price error"))
// 	tOut = it.ProduceLatestInFlightStageContext(ctx, &OrchestratorContext{
// 		AvailableToSpend:         nil,
// 		PreviousNonceCostUnknown: true,
// 	})
// 	assert.Empty(t, *tOut)
// 	it.persistenceRetryTimeout = 5 * time.Second

// 	// persisted stage success and move on
// 	ifts.ApplyInMemoryUpdates(ctx, &BaseTXUpdates{
// 		InFlightStatus: &suspended,
// 	})
// 	inFlightStageMananger.bufferedStageOutputs = make([]*StageOutput, 0)
// 	it.stateManager.AddPersistenceOutput(ctx, InFlightTxStageStatusUpdate, time.Now(), nil)
// 	tOut = it.ProduceLatestInFlightStageContext(ctx, &OrchestratorContext{
// 		AvailableToSpend:         nil,
// 		PreviousNonceCostUnknown: true,
// 	})
// 	assert.Empty(t, *tOut)
// 	assert.Nil(t, it.newStatus)
// 	// switched running stage context
// 	assert.NotEqual(t, rsc, it.stateManager.GetRunningStageContext(ctx))
// }

// func TestProduceLatestInFlightStageContextTriggerStatusUpdate(t *testing.T) {
// 	ctx, o, _, done := newTestOrchestrator(t)
// 	defer done()
// 	it, _ := newInflightTransaction(o, 1)
// 	it.testOnlyNoActionMode = false
// 	it.testOnlyNoEventMode = false
// 	// trigger signing
// 	assert.Nil(t, it.stateManager.GetRunningStageContext(ctx))
// 	err := it.TriggerStatusUpdate(ctx)
// 	require.NoError(t, err)
// 	inFlightStageMananger := it.stateManager.(*inFlightTransactionState)
// 	for len(inFlightStageMananger.bufferedStageOutputs) == 0 {
// 		// wait for event
// 	}
// 	assert.Len(t, inFlightStageMananger.bufferedStageOutputs, 1)
// 	assert.Nil(t, inFlightStageMananger.bufferedStageOutputs[0].PersistenceOutput) // panicked
// }

// func TestProduceLatestInFlightStageContextStatusUpdatePanic(t *testing.T) {
// 	ctx, o, _, done := newTestOrchestrator(t)
// 	defer done()
// 	it, _ := newInflightTransaction(o, 1)

// 	// trigger status change
// 	assert.Nil(t, it.stateManager.GetRunningStageContext(ctx))
// 	suspend := InFlightStatusSuspending
// 	it.newStatus = &suspend
// 	tOut := it.ProduceLatestInFlightStageContext(ctx, &OrchestratorContext{
// 		AvailableToSpend:         nil,
// 		PreviousNonceCostUnknown: true,
// 	})
// 	assert.Empty(t, *tOut)

// 	assert.NotNil(t, it.stateManager.GetRunningStageContext(ctx))
// 	rsc := it.stateManager.GetRunningStageContext(ctx)

// 	assert.Equal(t, InFlightTxStageStatusUpdate, rsc.Stage)

// 	inFlightStageMananger := it.stateManager.(*inFlightTransactionState)

// 	// unexpected error
// 	rsc = it.stateManager.GetRunningStageContext(ctx)
// 	inFlightStageMananger.bufferedStageOutputs = make([]*StageOutput, 0)
// 	it.stateManager.AddPanicOutput(ctx, InFlightTxStageStatusUpdate)
// 	tOut = it.ProduceLatestInFlightStageContext(ctx, &OrchestratorContext{
// 		AvailableToSpend:         nil,
// 		PreviousNonceCostUnknown: true,
// 	})
// 	assert.NotEmpty(t, *tOut)
// 	assert.Regexp(t, "PD011919", tOut.Error)
// 	assert.NotEqual(t, rsc, it.stateManager.GetRunningStageContext(ctx))
// 	inFlightStageMananger.bufferedStageOutputs = make([]*StageOutput, 0)
// }
