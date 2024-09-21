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
	"time"

	"github.com/kaleido-io/paladin/toolkit/pkg/ptxapi"
	"github.com/kaleido-io/paladin/toolkit/pkg/tktypes"

	"github.com/kaleido-io/paladin/core/pkg/blockindexer"
)

type managedTx struct {
	// immutable parts of the transaction as it was loaded from the DB
	ptx *persistedPubTx

	// the list of submissions that are individually immutable, but this list can grow
	flushedSubmissions []*persistedTxSubmission

	// We can have exactly one submission waiting to be flushed to the DB
	unflushedSubmission *persistedTxSubmission

	// In-memory state that we update as we process the transaction in an active orchestrator
	// TODO: Validate that all of these fields are actively used
	GasPricing      *ptxapi.PublicTxGasPricing // the most recently used gas pricing information
	Status          BaseTxStatus               `json:"status"`                    // high level lifecycle status for the transaction
	TransactionHash *tktypes.Bytes32           `json:"transactionHash,omitempty"` // the most recently submitted transaction hash (not guaranteed to be the one mined)
	FirstSubmit     *tktypes.Timestamp         `json:"firstSubmit,omitempty"`     // the time this runtime instance first did a submit JSON/RPC call (for success or failure)
	LastSubmit      *tktypes.Timestamp         `json:"lastSubmit,omitempty"`      // the last time runtime instance first did a submit JSON/RPC call (for success or failure)
	ErrorMessage    *string                    `json:"errorMessage,omitempty"`    // ???
}

type inMemoryTxState struct {
	idString string // generated ID that uniquely represents this transaction in in-memory processing
	// managed transaction in the only input for creating an inflight transaction
	mtx *managedTx

	// the value of the following properties are populated during transaction processing but not during initialization
	//  the process logic will determine whether confirmed transaction requires to be fetched
	ConfirmedTransaction *blockindexer.IndexedTransaction
}

func NewInMemoryTxStateManager(ctx context.Context, ptx *persistedPubTx, submissions []*persistedTxSubmission) InMemoryTxStateManager {

	return &inMemoryTxState{
		mtx: &managedTx{
			ptx: ptx,
			// When we load in a transaction this is the state we assume
			Status: BaseTxStatusPending,
		},
	}
}

func (imtxs *inMemoryTxState) SetConfirmedTransaction(ctx context.Context, iTX *blockindexer.IndexedTransaction) {
	imtxs.ConfirmedTransaction = iTX
}

func (imtxs *inMemoryTxState) ApplyInMemoryUpdates(ctx context.Context, txUpdates *BaseTXUpdates) {
	mtx := imtxs.mtx
	if txUpdates.ErrorMessage != nil {
		mtx.ErrorMessage = txUpdates.ErrorMessage
	}

	if txUpdates.FirstSubmit != nil {
		mtx.FirstSubmit = txUpdates.FirstSubmit
	}

	if txUpdates.GasLimit != nil {
		// TODO: Can this really be updated per submit? If so, this challenges the fact we store it in the
		//       transaction object (rather than the submission object)
		panic("attempt to modify gas limit")
	}

	if txUpdates.GasPricing != nil {
		mtx.GasPricing = txUpdates.GasPricing
	}

	if txUpdates.NewSubmission != nil {
		imtxs.mtx.unflushedSubmission = txUpdates.NewSubmission
	}
	if txUpdates.FlushedSubmission != nil {
		// We're being notified some of the unflushed submissions have been flushed to persistence
		// We clear the flushing list and merge in these new ones
		dup := false
		for _, existing := range mtx.flushedSubmissions {
			if existing.TransactionHash.Equals(txUpdates.FlushedSubmission.TransactionHash) {
				dup = true
				break
			}
		}
		if !dup {
			mtx.flushedSubmissions = append(mtx.flushedSubmissions, txUpdates.FlushedSubmission)
		}
	}

	if txUpdates.LastSubmit != nil {
		mtx.LastSubmit = txUpdates.LastSubmit
	}

	if txUpdates.Status != nil {
		mtx.Status = *txUpdates.Status
	}

	if txUpdates.TransactionHash != nil {
		mtx.TransactionHash = txUpdates.TransactionHash
	}
}

func (imtxs *inMemoryTxState) GetTxID() string {
	if imtxs.idString == "" {
		imtxs.idString = fmt.Sprintf("%s:%d[%s:%d]",
			imtxs.mtx.ptx.Transaction, imtxs.mtx.ptx.ResubmitIndex,
			imtxs.mtx.ptx.From, imtxs.mtx.ptx.Nonce)
	}
	return imtxs.idString
}

func (imtxs *inMemoryTxState) GetCreatedTime() *tktypes.Timestamp {
	return &imtxs.mtx.ptx.Created
}

func (imtxs *inMemoryTxState) GetTransactionHash() *tktypes.Bytes32 {
	return imtxs.mtx.TransactionHash
}

func (imtxs *inMemoryTxState) GetStatus() BaseTxStatus {
	return imtxs.mtx.Status
}

func (imtxs *inMemoryTxState) GetNonce() uint64 {
	return imtxs.mtx.ptx.Nonce
}

func (imtxs *inMemoryTxState) GetFrom() tktypes.EthAddress {
	return imtxs.mtx.ptx.From
}

func (imtxs *inMemoryTxState) GetFirstSubmit() *tktypes.Timestamp {
	return imtxs.mtx.FirstSubmit
}

func (imtxs *inMemoryTxState) GetGasPriceObject() *ptxapi.PublicTxGasPricing {
	// no gas price set yet, return nil, down stream logic relies on `nil` to know a transaction has never been assigned any gas price.
	return imtxs.mtx.GasPricing
}

func (imtxs *inMemoryTxState) GetLastSubmitTime() *tktypes.Timestamp {
	return imtxs.mtx.LastSubmit
}

func (imtxs *inMemoryTxState) GetUnflushedSubmission() *persistedTxSubmission {
	return imtxs.mtx.unflushedSubmission
}

func (imtxs *inMemoryTxState) GetGasLimit() uint64 {
	return imtxs.mtx.ptx.Gas
}

func (imtxs *inMemoryTxState) GetConfirmedTransaction() *blockindexer.IndexedTransaction {
	return imtxs.ConfirmedTransaction
}

func (imtxs *inMemoryTxState) IsComplete() bool {
	return imtxs.mtx.Status == BaseTxStatusFailed || imtxs.mtx.Status == BaseTxStatusSucceeded
}

func (imtxs *inMemoryTxState) IsSuspended() bool {
	return imtxs.mtx.Status == BaseTxStatusSuspended
}

func NewRunningStageContext(ctx context.Context, stage InFlightTxStage, substatus BaseTxSubStatus, imtxs InMemoryTxStateManager) *RunningStageContext {
	return &RunningStageContext{
		Stage:          stage,
		SubStatus:      substatus,
		StageOutput:    &StageOutput{},
		Context:        ctx,
		StageStartTime: time.Now(),
		InMemoryTx:     imtxs,
	}
}
