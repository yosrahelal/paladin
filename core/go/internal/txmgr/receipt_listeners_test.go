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

package txmgr

import (
	"context"
	"testing"

	"github.com/google/uuid"
	"github.com/hyperledger/firefly-signer/pkg/abi"
	"github.com/kaleido-io/paladin/config/pkg/pldconf"
	"github.com/kaleido-io/paladin/core/internal/components"
	"github.com/kaleido-io/paladin/toolkit/pkg/pldapi"
	"github.com/kaleido-io/paladin/toolkit/pkg/tktypes"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

type testReceiptReceiver struct {
	err      error
	receipts chan *pldapi.TransactionReceiptFull
}

func (trr *testReceiptReceiver) DeliverReceiptBatch(ctx context.Context, receipts []*pldapi.TransactionReceiptFull) error {
	if trr.err != nil {
		return trr.err
	}
	for _, r := range receipts {
		trr.receipts <- r
	}
	return nil
}

func newTestReceiptReceiver(err error) *testReceiptReceiver {
	return &testReceiptReceiver{
		err:      err,
		receipts: make(chan *pldapi.TransactionReceiptFull),
	}
}

var defaultErrorABI = &abi.Entry{
	Type: abi.Error,
	Name: "Error",
	Inputs: abi.ParameterArray{
		{Name: "message", Type: "string"},
	},
}

func mockTxStatesAllAvailable(conf *pldconf.TxManagerConfig, mc *mockComponents) {
	mc.stateMgr.On("GetTransactionStates", mock.Anything, mock.Anything, mock.Anything).
		Return(&pldapi.TransactionStates{
			Spent:     []*pldapi.StateBase{},
			Read:      []*pldapi.StateBase{},
			Confirmed: []*pldapi.StateBase{},
			Info:      []*pldapi.StateBase{},
		}, nil)
}

func TestE2EReceiptListenerDeliveryLateAttach(t *testing.T) {
	ctx, txm, done := newTestTransactionManager(t, true, mockTxStatesAllAvailable)
	defer done()

	// Create listener (started)
	err := txm.CreateReceiptListener(ctx, &pldapi.TransactionReceiptListener{
		Name: "listener1",
	})
	require.NoError(t, err)

	// Write some receipts (before we attach to the listener to consume events)
	contractAddr1 := tktypes.RandAddress()
	contractAddr2 := tktypes.RandAddress()
	crackleData, err := defaultErrorABI.EncodeCallDataJSON([]byte(`{
	    "message": "crackle"
	}`))
	require.NoError(t, err)
	popData, err := defaultErrorABI.EncodeCallDataJSON([]byte(`{
	    "message": "pop"
	}`))
	require.NoError(t, err)
	receiptInputs := []*components.ReceiptInput{
		{
			ReceiptType:    components.RT_FailedWithMessage,
			Domain:         "", // public, failed without making it to chain
			TransactionID:  uuid.New(),
			FailureMessage: "snap",
		},
		{
			ReceiptType:   components.RT_FailedOnChainWithRevertData,
			Domain:        "domain1", // private, failed on-chain
			TransactionID: uuid.New(),
			RevertData:    crackleData,
			OnChain: tktypes.OnChainLocation{
				Type:             tktypes.OnChainEvent,
				TransactionHash:  tktypes.Bytes32(tktypes.RandBytes(32)),
				BlockNumber:      12345,
				TransactionIndex: 20,
				LogIndex:         10,
				Source:           contractAddr1,
			},
		},
		{
			ReceiptType:   components.RT_FailedOnChainWithRevertData,
			Domain:        "", // public, failed on-chain
			TransactionID: uuid.New(),
			RevertData:    popData,
			OnChain: tktypes.OnChainLocation{
				Type:             tktypes.OnChainTransaction,
				TransactionHash:  tktypes.Bytes32(tktypes.RandBytes(32)),
				BlockNumber:      12345,
				TransactionIndex: 10,
				Source:           contractAddr2,
			},
		},
	}
	postCommit, err := txm.FinalizeTransactions(ctx, txm.p.DB(), receiptInputs)
	require.NoError(t, err)
	postCommit()

	// Create a receiver and check we get everything delivered
	receipts := newTestReceiptReceiver(nil)
	closeReceiver, err := txm.AddReceiptReceiver(ctx, "listener1", receipts)
	require.NoError(t, err)
	defer closeReceiver.Close()

	r := <-receipts.receipts
	assert.Equal(t, r.ID, receiptInputs[0].TransactionID)
	assert.Regexp(t, "snap", r.FailureMessage)
	r = <-receipts.receipts
	assert.Equal(t, r.ID, receiptInputs[1].TransactionID)
	assert.Regexp(t, "crackle", r.FailureMessage)
	r = <-receipts.receipts
	assert.Equal(t, r.ID, receiptInputs[2].TransactionID)
	assert.Regexp(t, "pop", r.FailureMessage)

}
