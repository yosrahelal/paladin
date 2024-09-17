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
	"math/big"
	"time"

	"github.com/kaleido-io/paladin/toolkit/pkg/log"

	"github.com/hyperledger/firefly-common/pkg/fftypes"
	"github.com/kaleido-io/paladin/core/internal/components"
	baseTypes "github.com/kaleido-io/paladin/core/internal/engine/enginespi"
	"github.com/kaleido-io/paladin/core/pkg/blockindexer"
)

type inMemoryTxState struct {
	// managed transaction in the only input for creating an inflight transaction
	mtx *components.PublicTX

	// the value of the following properties are populated during transaction processing but not during initialization
	//  the process logic will determine whether confirmed transaction requires to be fetched
	ConfirmedTransaction *blockindexer.IndexedTransaction
}

func NewInMemoryTxStateMananger(ctx context.Context, mtx *components.PublicTX) baseTypes.InMemoryTxStateManager {
	return &inMemoryTxState{
		mtx: mtx,
	}
}

func (imtxs *inMemoryTxState) SetConfirmedTransaction(ctx context.Context, iTX *blockindexer.IndexedTransaction) {
	imtxs.ConfirmedTransaction = iTX
}

func (imtxs *inMemoryTxState) ApplyTxUpdates(ctx context.Context, txUpdates *components.BaseTXUpdates) {
	mtx := imtxs.mtx

	if txUpdates.From != nil || txUpdates.To != nil || txUpdates.Nonce != nil || txUpdates.Value != nil {
		log.L(ctx).Warnf("ApplyTxUpdates received fields that are not expected to be updated: %+v", txUpdates)
	}

	if txUpdates.DeleteRequested != nil {
		mtx.DeleteRequested = txUpdates.DeleteRequested
	}

	if txUpdates.ErrorMessage != nil {
		mtx.ErrorMessage = *txUpdates.ErrorMessage
	}

	if txUpdates.FirstSubmit != nil {
		mtx.FirstSubmit = txUpdates.FirstSubmit
	}

	if txUpdates.GasLimit != nil {
		mtx.GasLimit = txUpdates.GasLimit
	}

	if txUpdates.GasPrice != nil {
		mtx.GasPrice = txUpdates.GasPrice
		mtx.MaxFeePerGas = nil
		mtx.MaxPriorityFeePerGas = nil
	} else {
		switchedGasPrice := false
		if txUpdates.MaxFeePerGas != nil {
			switchedGasPrice = true
			mtx.MaxFeePerGas = txUpdates.MaxFeePerGas
		}

		if txUpdates.MaxPriorityFeePerGas != nil {
			switchedGasPrice = true
			mtx.MaxPriorityFeePerGas = txUpdates.MaxPriorityFeePerGas
		}
		if switchedGasPrice {
			mtx.GasPrice = nil
		}
	}

	if txUpdates.SubmittedHashes != nil {
		mtx.SubmittedHashes = txUpdates.SubmittedHashes
	}

	if txUpdates.LastSubmit != nil {
		mtx.LastSubmit = txUpdates.LastSubmit
	}

	if txUpdates.Status != nil {
		mtx.Status = *txUpdates.Status
	}

	if txUpdates.TransactionHash != nil {
		mtx.TransactionHash = *txUpdates.TransactionHash
	}
}

func (imtxs *inMemoryTxState) GetTx() *components.PublicTX {
	return imtxs.mtx
}

func (imtxs *inMemoryTxState) GetTxID() string {
	return imtxs.mtx.ID
}

func (imtxs *inMemoryTxState) GetCreatedTime() *fftypes.FFTime {
	return imtxs.mtx.Created
}

func (imtxs *inMemoryTxState) GetDeleteRequestedTime() *fftypes.FFTime {
	return imtxs.mtx.DeleteRequested
}

func (imtxs *inMemoryTxState) GetTransactionHash() string {
	return imtxs.mtx.TransactionHash
}
func (imtxs *inMemoryTxState) GetStatus() components.BaseTxStatus {
	return imtxs.mtx.Status
}

func (imtxs *inMemoryTxState) GetNonce() *big.Int {
	return imtxs.mtx.Nonce.BigInt()
}
func (imtxs *inMemoryTxState) GetFrom() string {
	return string(imtxs.mtx.From)
}

func (imtxs *inMemoryTxState) GetFirstSubmit() *fftypes.FFTime {
	return imtxs.mtx.FirstSubmit
}

func (imtxs *inMemoryTxState) GetGasPriceObject() *baseTypes.GasPriceObject {
	if imtxs.mtx.GasPrice == nil && imtxs.mtx.MaxFeePerGas == nil && imtxs.mtx.MaxPriorityFeePerGas == nil {
		// no gas price set yet, return nil, down stream logic relies on `nil` to know a transaction has never been assigned any gas price.
		return nil
	}
	gpo := &baseTypes.GasPriceObject{}
	if imtxs.mtx.GasPrice != nil {
		gpo.GasPrice = big.NewInt(imtxs.mtx.GasPrice.BigInt().Int64())
	}
	if imtxs.mtx.MaxPriorityFeePerGas != nil {
		gpo.MaxPriorityFeePerGas = big.NewInt(imtxs.mtx.MaxPriorityFeePerGas.BigInt().Int64())
	}
	if imtxs.mtx.MaxFeePerGas != nil {
		gpo.MaxFeePerGas = big.NewInt(imtxs.mtx.MaxFeePerGas.BigInt().Int64())
	}
	return gpo
}
func (imtxs *inMemoryTxState) GetLastSubmitTime() *fftypes.FFTime {
	return imtxs.mtx.LastSubmit
}

func (imtxs *inMemoryTxState) GetSubmittedHashes() []string {
	return imtxs.mtx.SubmittedHashes
}
func (imtxs *inMemoryTxState) GetGasLimit() *big.Int {
	return imtxs.mtx.GasLimit.BigInt()
}

func (imtxs *inMemoryTxState) GetConfirmedTransaction() *blockindexer.IndexedTransaction {
	return imtxs.ConfirmedTransaction
}

func (imtxs *inMemoryTxState) IsComplete() bool {
	return imtxs.mtx.Status == components.BaseTxStatusFailed || imtxs.mtx.Status == components.BaseTxStatusSucceeded
}

func (imtxs *inMemoryTxState) IsSuspended() bool {
	return imtxs.mtx.Status == components.BaseTxStatusSuspended
}

func NewRunningStageContext(ctx context.Context, stage baseTypes.InFlightTxStage, substatus components.BaseTxSubStatus, imtxs baseTypes.InMemoryTxStateManager) *baseTypes.RunningStageContext {
	return &baseTypes.RunningStageContext{
		Stage:          stage,
		SubStatus:      substatus,
		StageOutput:    &baseTypes.StageOutput{},
		Context:        ctx,
		StageStartTime: time.Now(),
		InMemoryTx:     imtxs,
	}
}
