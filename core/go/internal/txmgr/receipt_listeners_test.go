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
	"database/sql/driver"
	"fmt"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/google/uuid"
	"github.com/hyperledger/firefly-signer/pkg/abi"
	"github.com/kaleido-io/paladin/config/pkg/confutil"
	"github.com/kaleido-io/paladin/config/pkg/pldconf"
	"github.com/kaleido-io/paladin/core/internal/components"
	"github.com/kaleido-io/paladin/toolkit/pkg/pldapi"
	"github.com/kaleido-io/paladin/toolkit/pkg/tktypes"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

type testReceiptReceiver struct {
	err       error
	callCount int
	called    chan struct{}
	receipts  chan *pldapi.TransactionReceiptFull
}

func (trr *testReceiptReceiver) DeliverReceiptBatch(ctx context.Context, receipts []*pldapi.TransactionReceiptFull) error {
	if trr.callCount == 0 {
		close(trr.called)
	}
	trr.callCount++
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
		called:   make(chan struct{}),
		receipts: make(chan *pldapi.TransactionReceiptFull, 1),
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

	// These will have all ended up in a single batch, as they were committed together
	r := <-receipts.receipts
	assert.Equal(t, r.ID, receiptInputs[0].TransactionID)
	assert.Regexp(t, "snap", r.FailureMessage)
	r = <-receipts.receipts
	assert.Equal(t, r.ID, receiptInputs[1].TransactionID)
	assert.Regexp(t, "crackle", r.FailureMessage)
	r = <-receipts.receipts
	assert.Equal(t, r.ID, receiptInputs[2].TransactionID)
	assert.Regexp(t, "pop", r.FailureMessage)

	// Now send another - we make this one successful
	receiptInputs2 := []*components.ReceiptInput{
		{
			ReceiptType:   components.RT_Success,
			Domain:        "", // public, success
			TransactionID: uuid.New(),
			OnChain: tktypes.OnChainLocation{
				Type:             tktypes.OnChainTransaction,
				TransactionHash:  tktypes.Bytes32(tktypes.RandBytes(32)),
				BlockNumber:      23456,
				TransactionIndex: 30,
				Source:           contractAddr2,
			},
		},
	}
	postCommit, err = txm.FinalizeTransactions(ctx, txm.p.DB(), receiptInputs2)
	require.NoError(t, err)
	postCommit()

	// This one is assured to be in a new batch
	r = <-receipts.receipts
	assert.Equal(t, r.ID, receiptInputs2[0].TransactionID)
	assert.Empty(t, r.FailureMessage)
}

func randOnChain() tktypes.OnChainLocation {
	return tktypes.OnChainLocation{
		Type:             tktypes.OnChainTransaction,
		TransactionHash:  tktypes.Bytes32(tktypes.RandBytes(32)),
		BlockNumber:      23456,
		TransactionIndex: 30,
		Source:           tktypes.RandAddress(),
	}
}

func TestLoadListenersMultiPageFilters(t *testing.T) {
	ctx, txm, done := newTestTransactionManager(t, true, mockTxStatesAllAvailable)
	defer done()

	err := txm.CreateReceiptListener(ctx, &pldapi.TransactionReceiptListener{
		Name:    "listener1",
		Started: confutil.P(false),
		Filters: pldapi.TransactionReceiptFilters{
			Type:   confutil.P(pldapi.TransactionTypePrivate.Enum()),
			Domain: "domain1",
		},
	})
	require.NoError(t, err)
	err = txm.CreateReceiptListener(ctx, &pldapi.TransactionReceiptListener{
		Name:    "listener2",
		Started: confutil.P(false),
		Filters: pldapi.TransactionReceiptFilters{
			Type: confutil.P(pldapi.TransactionTypePrivate.Enum()),
		},
	})
	require.NoError(t, err)
	err = txm.CreateReceiptListener(ctx, &pldapi.TransactionReceiptListener{
		Name:    "listener3",
		Started: confutil.P(false),
		Filters: pldapi.TransactionReceiptFilters{
			Type: confutil.P(pldapi.TransactionTypePublic.Enum()),
		},
	})
	require.NoError(t, err)
	err = txm.CreateReceiptListener(ctx, &pldapi.TransactionReceiptListener{
		Name:    "listener4",
		Started: confutil.P(false),
		Filters: pldapi.TransactionReceiptFilters{
			SequenceAbove: confutil.P(uint64(100000)), // will ignore all, even though no other filters
		},
	})
	require.NoError(t, err)

	txm.receiptsInit()
	txm.receiptListenersLoadPageSize = 1

	err = txm.loadReceiptListeners()
	require.NoError(t, err)

	require.Len(t, txm.receiptListeners, 4)

	// for variation we register before start here
	r1 := newTestReceiptReceiver(nil)
	close1, err := txm.AddReceiptReceiver(ctx, "listener1", r1)
	require.NoError(t, err)
	defer close1.Close()
	r2 := newTestReceiptReceiver(nil)
	close2, err := txm.AddReceiptReceiver(ctx, "listener2", r2)
	require.NoError(t, err)
	defer close2.Close()
	r3 := newTestReceiptReceiver(nil)
	close3, err := txm.AddReceiptReceiver(ctx, "listener3", r3)
	require.NoError(t, err)
	defer close3.Close()
	r4 := newTestReceiptReceiver(nil)
	close4, err := txm.AddReceiptReceiver(ctx, "listener4", r4)
	require.NoError(t, err)
	defer close4.Close()

	// Now start them all
	err = txm.StartReceiptListener(ctx, "listener1")
	require.NoError(t, err)
	err = txm.StartReceiptListener(ctx, "listener2")
	require.NoError(t, err)
	err = txm.StartReceiptListener(ctx, "listener3")
	require.NoError(t, err)
	err = txm.StartReceiptListener(ctx, "listener4")
	require.NoError(t, err)

	// Private domain2 to listener2 only
	tx1 := uuid.New()
	postCommit, err := txm.FinalizeTransactions(ctx, txm.p.DB(), []*components.ReceiptInput{
		{
			ReceiptType:   components.RT_Success,
			Domain:        "domain2",
			TransactionID: tx1,
			OnChain:       randOnChain(),
		},
	})
	require.NoError(t, err)
	postCommit()
	require.Equal(t, tx1, (<-r2.receipts).ID)

	// Private domain1 to listener 1&2
	tx2 := uuid.New()
	postCommit, err = txm.FinalizeTransactions(ctx, txm.p.DB(), []*components.ReceiptInput{
		{
			ReceiptType:   components.RT_Success,
			Domain:        "domain1",
			TransactionID: tx2,
			OnChain:       randOnChain(),
		},
	})
	require.NoError(t, err)
	postCommit()
	require.Equal(t, tx2, (<-r1.receipts).ID)
	require.Equal(t, tx2, (<-r2.receipts).ID)

	// Public to listener3
	tx3 := uuid.New()
	postCommit, err = txm.FinalizeTransactions(ctx, txm.p.DB(), []*components.ReceiptInput{
		{
			ReceiptType:   components.RT_Success,
			Domain:        "",
			TransactionID: tx3,
			OnChain:       randOnChain(),
		},
	})
	require.NoError(t, err)
	postCommit()
	require.Equal(t, tx3, (<-r3.receipts).ID)

	// Nothing should have gone to 4
	select {
	case <-r4.receipts:
		require.Fail(t, "received receipt")
	default:
	}

	// Wait for checkpoint
	for txm.receiptListeners["listener3"].checkpoint == nil {
		time.Sleep(10 * time.Millisecond)
	}

	// restart and deliver next
	txm.stopReceiptListeners()
	txm.startReceiptListeners()

	// Public to listener3 again
	tx4 := uuid.New()
	postCommit, err = txm.FinalizeTransactions(ctx, txm.p.DB(), []*components.ReceiptInput{
		{
			ReceiptType:   components.RT_Success,
			Domain:        "",
			TransactionID: tx4,
			OnChain:       randOnChain(),
		},
	})
	require.NoError(t, err)
	postCommit()
	require.Equal(t, tx4, (<-r3.receipts).ID)

}

func TestLoadListenersFailRead(t *testing.T) {
	_, txm, done := newTestTransactionManager(t, false, func(conf *pldconf.TxManagerConfig, mc *mockComponents) {
		mc.db.ExpectQuery("SELECT.*receipt_listeners").WillReturnRows(mc.db.NewRows([]string{}))
		// 2nd load fails
		mc.db.ExpectQuery("SELECT.*receipt_listeners").WillReturnError(fmt.Errorf("pop"))
	})
	defer done()

	txm.receiptsInit()

	err := txm.loadReceiptListeners()
	require.Regexp(t, "pop", err)
}

func TestLoadListenersFailBadListener(t *testing.T) {
	_, txm, done := newTestTransactionManager(t, false, func(conf *pldconf.TxManagerConfig, mc *mockComponents) {
		mc.db.ExpectQuery("SELECT.*receipt_listeners").WillReturnRows(mc.db.NewRows([]string{}))
		// 2nd load gives bad data
		mc.db.ExpectQuery("SELECT.*receipt_listeners").WillReturnRows(mc.db.NewRows([]string{
			"name", "filters", "options",
		}).AddRow(
			"" /* bad name */, "{}", "{}",
		))
	})
	defer done()

	txm.receiptsInit()

	err := txm.loadReceiptListeners()
	require.Regexp(t, "PD020005", err)
}

func TestCreateBadListener(t *testing.T) {
	ctx, txm, done := newTestTransactionManager(t, false,
		mockEmptyReceiptListeners,
	)
	defer done()

	err := txm.CreateReceiptListener(ctx, &pldapi.TransactionReceiptListener{
		Name: "badly-behaved",
		Options: pldapi.TransactionReceiptListenerOptions{
			IncompleteStateReceiptBehavior: tktypes.Enum[pldapi.IncompleteStateReceiptBehavior]("misbehave"),
		},
	})
	require.Regexp(t, "PD020003", err)
}

func TestCreateListenerFail(t *testing.T) {
	ctx, txm, done := newTestTransactionManager(t, false,
		mockEmptyReceiptListeners,
		func(conf *pldconf.TxManagerConfig, mc *mockComponents) {
			mc.db.ExpectExec("INSERT.*receipt_listeners").WillReturnError(fmt.Errorf("pop"))
		},
	)
	defer done()

	err := txm.CreateReceiptListener(ctx, &pldapi.TransactionReceiptListener{
		Name: "test1",
	})
	require.Regexp(t, "pop", err)
}

func TestAddReceiptReceiverNotFound(t *testing.T) {
	ctx, txm, done := newTestTransactionManager(t, false,
		mockEmptyReceiptListeners,
	)
	defer done()

	_, err := txm.AddReceiptReceiver(ctx, "test1", newTestReceiptReceiver(nil))
	require.Regexp(t, "PD012238.*test1", err)
}

func TestStopReceiptListenerNotFound(t *testing.T) {
	ctx, txm, done := newTestTransactionManager(t, false,
		mockEmptyReceiptListeners,
	)
	defer done()

	err := txm.StopReceiptListener(ctx, "test1")
	require.Regexp(t, "PD012238.*test1", err)
}

func TestStartReceiptListenerNotFound(t *testing.T) {
	ctx, txm, done := newTestTransactionManager(t, false,
		mockEmptyReceiptListeners,
	)
	defer done()

	err := txm.StartReceiptListener(ctx, "test1")
	require.Regexp(t, "PD012238.*test1", err)
}

func TestStartReceiptListenerFail(t *testing.T) {
	ctx, txm, done := newTestTransactionManager(t, false,
		mockEmptyReceiptListeners,
		func(conf *pldconf.TxManagerConfig, mc *mockComponents) {
			mc.db.ExpectExec("INSERT.*receipt_listeners").WillReturnResult(driver.ResultNoRows)
			mc.db.ExpectExec("UPDATE.*receipt_listeners").WillReturnError(fmt.Errorf("pop"))
		},
	)
	defer done()

	err := txm.CreateReceiptListener(ctx, &pldapi.TransactionReceiptListener{
		Name:    "test1",
		Started: confutil.P(false),
	})
	require.NoError(t, err)

	err = txm.StartReceiptListener(ctx, "test1")
	require.Regexp(t, "pop", err)
}

func TestDeleteReceiptListenerNotFound(t *testing.T) {
	ctx, txm, done := newTestTransactionManager(t, false,
		mockEmptyReceiptListeners,
	)
	defer done()

	err := txm.DeleteReceiptListener(ctx, "test1")
	require.Regexp(t, "PD012238.*test1", err)
}

func TestDeleteReceiptListenerFail(t *testing.T) {
	ctx, txm, done := newTestTransactionManager(t, false,
		mockEmptyReceiptListeners,
		func(conf *pldconf.TxManagerConfig, mc *mockComponents) {
			mc.db.ExpectExec("INSERT.*receipt_listeners").WillReturnResult(driver.ResultNoRows)
			mc.db.ExpectExec("DELETE.*receipt_listeners").WillReturnError(fmt.Errorf("pop"))
		},
	)
	defer done()

	err := txm.CreateReceiptListener(ctx, &pldapi.TransactionReceiptListener{
		Name:    "test1",
		Started: confutil.P(false),
	})
	require.NoError(t, err)

	_, err = txm.loadListener(ctx, &persistedReceiptListener{Name: "test1", Filters: tktypes.RawJSON(`{}`), Options: tktypes.RawJSON(`{}`)})
	assert.Regexp(t, "PD012235", err)

	err = txm.DeleteReceiptListener(ctx, "test1")
	require.Regexp(t, "pop", err)
}

func TestBuildListenerDBQueryFailBadTypeDomainFilterCombos(t *testing.T) {
	ctx, txm, done := newTestTransactionManager(t, false, mockEmptyReceiptListeners)
	defer done()

	_, err := txm.buildListenerDBQuery(ctx, &pldapi.TransactionReceiptListener{
		Filters: pldapi.TransactionReceiptFilters{
			Domain: "not-private-filtered",
		},
	}, txm.p.DB())
	require.Regexp(t, "PD012236", err)

	_, err = txm.buildListenerDBQuery(ctx, &pldapi.TransactionReceiptListener{
		Filters: pldapi.TransactionReceiptFilters{
			Type:   confutil.P(pldapi.TransactionTypePublic.Enum()),
			Domain: "not-private",
		},
	}, txm.p.DB())
	require.Regexp(t, "PD012236", err)

	_, err = txm.buildListenerDBQuery(ctx, &pldapi.TransactionReceiptListener{
		Filters: pldapi.TransactionReceiptFilters{
			Type: confutil.P(pldapi.TransactionType("badness").Enum()),
		},
	}, txm.p.DB())
	require.Regexp(t, "PD012236", err)
}

func TestCheckMatchBadTypeFalse(t *testing.T) {
	ctx, txm, done := newTestTransactionManager(t, false,
		mockEmptyReceiptListeners,
		func(conf *pldconf.TxManagerConfig, mc *mockComponents) {
			mc.db.ExpectExec("INSERT.*receipt_listeners").WillReturnResult(driver.ResultNoRows)
		},
	)
	defer done()

	err := txm.CreateReceiptListener(ctx, &pldapi.TransactionReceiptListener{
		Name:    "listener1",
		Started: confutil.P(false),
	})
	require.NoError(t, err)

	l := txm.receiptListeners["listener1"]
	l.spec.Filters.Type = confutil.P(pldapi.TransactionType("wrong").Enum())

	require.False(t, l.checkMatch(&transactionReceipt{}))

}

func TestCreateListenerBadOptions(t *testing.T) {
	ctx, txm, done := newTestTransactionManager(t, false,
		mockEmptyReceiptListeners,
	)
	defer done()

	_, err := txm.loadListener(ctx, &persistedReceiptListener{
		Filters: tktypes.RawJSON(`{ !badness`),
	})
	assert.Regexp(t, "PD012233", err)

	_, err = txm.loadListener(ctx, &persistedReceiptListener{
		Filters: tktypes.RawJSON(`{}`),
		Options: tktypes.RawJSON(`{ !badness`),
	})
	assert.Regexp(t, "PD012234", err)

}

func TestAddReceiverNoBlock(t *testing.T) {
	ctx, txm, done := newTestTransactionManager(t, false,
		mockEmptyReceiptListeners,
		func(conf *pldconf.TxManagerConfig, mc *mockComponents) {
			mc.db.ExpectExec("INSERT.*receipt_listeners").WillReturnResult(driver.ResultNoRows)
		},
	)
	defer done()

	err := txm.CreateReceiptListener(ctx, &pldapi.TransactionReceiptListener{
		Name:    "listener1",
		Started: confutil.P(false),
	})
	require.NoError(t, err)

	r1, err := txm.AddReceiptReceiver(ctx, "listener1", newTestReceiptReceiver(nil))
	require.NoError(t, err)
	defer r1.Close()

	r2, err := txm.AddReceiptReceiver(ctx, "listener1", newTestReceiptReceiver(nil))
	require.NoError(t, err)
	defer r2.Close()
}

func TestNotifyNewReceiptsNoBlock(t *testing.T) {
	ctx, txm, done := newTestTransactionManager(t, false,
		mockEmptyReceiptListeners,
		func(conf *pldconf.TxManagerConfig, mc *mockComponents) {
			mc.db.ExpectExec("INSERT.*receipt_listeners").WillReturnResult(driver.ResultNoRows)
		},
	)
	defer done()

	err := txm.CreateReceiptListener(ctx, &pldapi.TransactionReceiptListener{
		Name:    "listener1",
		Started: confutil.P(false),
	})
	require.NoError(t, err)

	txm.receiptListeners["listener1"].notifyNewReceipts()
	txm.receiptListeners["listener1"].notifyNewReceipts()
}

func TestClosedRetryingLoadingCheckpoint(t *testing.T) {
	ctx, txm, done := newTestTransactionManager(t, false,
		mockEmptyReceiptListeners,
		func(conf *pldconf.TxManagerConfig, mc *mockComponents) {
			mc.db.ExpectExec("INSERT.*receipt_listeners").WillReturnResult(driver.ResultNoRows)
			mc.db.ExpectQuery("SELECT.*receipt_listener_checkpoints").WillReturnError(fmt.Errorf("pop"))
		},
	)
	defer done()

	err := txm.CreateReceiptListener(ctx, &pldapi.TransactionReceiptListener{
		Name:    "listener1",
		Started: confutil.P(false),
	})
	require.NoError(t, err)

	txm.receiptsRetry.UTSetMaxAttempts(1)
	l := txm.receiptListeners["listener1"]
	l.initStart()
	l.runListener()
}

func TestClosedRetryingBatchDeliver(t *testing.T) {
	ctx, txm, done := newTestTransactionManager(t, false,
		mockEmptyReceiptListeners,
		func(conf *pldconf.TxManagerConfig, mc *mockComponents) {
			mc.db.ExpectExec("INSERT.*receipt_listeners").WillReturnResult(driver.ResultNoRows)
			mc.db.ExpectQuery("SELECT.*receipt_listener_checkpoints").WillReturnRows(sqlmock.NewRows([]string{}))
			mc.db.ExpectQuery("SELECT.*transaction_receipts").WillReturnRows(sqlmock.
				NewRows([]string{
					"transaction",
					"sequence",
					"tx_hash",
				}).
				AddRow(
					uuid.NewString(),
					int64(1000),
					tktypes.RandHex(32),
				))
		},
	)
	defer done()

	err := txm.CreateReceiptListener(ctx, &pldapi.TransactionReceiptListener{
		Name:    "listener1",
		Started: confutil.P(false),
	})
	require.NoError(t, err)

	trr := newTestReceiptReceiver(fmt.Errorf("pop"))
	r, err := txm.AddReceiptReceiver(ctx, "listener1", trr)
	require.NoError(t, err)
	defer r.Close()

	txm.receiptsRetry.UTSetMaxAttempts(1)
	l := txm.receiptListeners["listener1"]
	l.initStart()
	l.runListener()
	<-trr.called
}

func TestClosedRetryingWritingCheckpoint(t *testing.T) {
	ctx, txm, done := newTestTransactionManager(t, false,
		mockEmptyReceiptListeners,
		func(conf *pldconf.TxManagerConfig, mc *mockComponents) {
			mc.db.ExpectExec("INSERT.*receipt_listeners").WillReturnResult(driver.ResultNoRows)
			mc.db.ExpectQuery("SELECT.*receipt_listener_checkpoints").WillReturnRows(sqlmock.NewRows([]string{}))
			mc.db.ExpectQuery("SELECT.*transaction_receipts").WillReturnRows(sqlmock.
				NewRows([]string{
					"transaction",
					"sequence",
					"tx_hash",
				}).
				AddRow(
					uuid.NewString(),
					int64(1000),
					tktypes.RandHex(32),
				))
			mc.db.ExpectExec("INSERT.*receipt_listener_checkpoints").WillReturnError(fmt.Errorf("pop"))
		},
	)
	defer done()

	err := txm.CreateReceiptListener(ctx, &pldapi.TransactionReceiptListener{
		Name:    "listener1",
		Started: confutil.P(false),
	})
	require.NoError(t, err)

	trr := newTestReceiptReceiver(nil)
	r, err := txm.AddReceiptReceiver(ctx, "listener1", trr)
	require.NoError(t, err)
	defer r.Close()

	txm.receiptsRetry.UTSetMaxAttempts(1)
	l := txm.receiptListeners["listener1"]
	l.initStart()
	l.runListener()
	<-trr.receipts
}

func TestClosedRetryingQueryReceiptStates(t *testing.T) {
	ctx, txm, done := newTestTransactionManager(t, false,
		mockEmptyReceiptListeners,
		func(conf *pldconf.TxManagerConfig, mc *mockComponents) {
			mc.db.ExpectExec("INSERT.*receipt_listeners").WillReturnResult(driver.ResultNoRows)
			mc.db.ExpectQuery("SELECT.*receipt_listener_checkpoints").WillReturnRows(sqlmock.NewRows([]string{}))
			mc.db.ExpectQuery("SELECT.*transaction_receipts").WillReturnRows(sqlmock.
				NewRows([]string{
					"transaction",
					"sequence",
					"tx_hash",
					"domain",
				}).
				AddRow(
					uuid.NewString(),
					int64(1000),
					tktypes.RandHex(32),
					"domain1",
				))
			mc.stateMgr.On("GetTransactionStates", mock.Anything, mock.Anything, mock.Anything).Return(nil, fmt.Errorf("pop"))
		},
	)
	defer done()

	err := txm.CreateReceiptListener(ctx, &pldapi.TransactionReceiptListener{
		Name:    "listener1",
		Started: confutil.P(false),
	})
	require.NoError(t, err)

	txm.receiptsRetry.UTSetMaxAttempts(1)
	l := txm.receiptListeners["listener1"]
	l.initStart()
	l.runListener()
}

func TestClosedRetryingQueryReceipts(t *testing.T) {
	ctx, txm, done := newTestTransactionManager(t, false,
		mockEmptyReceiptListeners,
		func(conf *pldconf.TxManagerConfig, mc *mockComponents) {
			mc.db.ExpectExec("INSERT.*receipt_listeners").WillReturnResult(driver.ResultNoRows)
			mc.db.ExpectQuery("SELECT.*receipt_listener_checkpoints").WillReturnRows(sqlmock.NewRows([]string{}))
			mc.db.ExpectQuery("SELECT.*transaction_receipts").WillReturnError(fmt.Errorf("pop"))
		},
	)
	defer done()

	err := txm.CreateReceiptListener(ctx, &pldapi.TransactionReceiptListener{
		Name:    "listener1",
		Started: confutil.P(false),
	})
	require.NoError(t, err)

	txm.receiptsRetry.UTSetMaxAttempts(1)
	l := txm.receiptListeners["listener1"]
	l.initStart()
	l.runListener()
}

func TestDeliverBatchCancelledCtxNoReceiver(t *testing.T) {
	ctx, txm, done := newTestTransactionManager(t, false,
		mockEmptyReceiptListeners,
		func(conf *pldconf.TxManagerConfig, mc *mockComponents) {
			mc.db.ExpectExec("INSERT.*receipt_listeners").WillReturnResult(driver.ResultNoRows)
		},
	)
	defer done()

	err := txm.CreateReceiptListener(ctx, &pldapi.TransactionReceiptListener{
		Name:    "listener1",
		Started: confutil.P(false),
	})
	require.NoError(t, err)

	l := txm.receiptListeners["listener1"]
	l.ctx, l.cancelCtx = context.WithCancel(ctx)
	l.cancelCtx()
	err = l.deliverBatch(&receiptDeliveryBatch{})
	require.Regexp(t, "PD010301", err)
}

func TestDeliverBatchCancelledCtxNotifyReceiver(t *testing.T) {
	ctx, txm, done := newTestTransactionManager(t, false,
		mockEmptyReceiptListeners,
		func(conf *pldconf.TxManagerConfig, mc *mockComponents) {
			mc.db.ExpectExec("INSERT.*receipt_listeners").WillReturnResult(driver.ResultNoRows)
		},
	)
	defer done()

	err := txm.CreateReceiptListener(ctx, &pldapi.TransactionReceiptListener{
		Name:    "listener1",
		Started: confutil.P(false),
	})
	require.NoError(t, err)

	l := txm.receiptListeners["listener1"]
	l.initStart()

	go func() {
		time.Sleep(10 * time.Millisecond)
		receipts := newTestReceiptReceiver(nil)
		closeReceiver, err := txm.AddReceiptReceiver(ctx, "listener1", receipts)
		require.NoError(t, err)
		t.Cleanup(func() { closeReceiver.Close() })
	}()

	r, err := l.nextReceiver(&receiptDeliveryBatch{})
	require.NoError(t, err)
	require.NotNil(t, r)
	close(l.done)

}

func TestProcessPersistedReceiptPostFilter(t *testing.T) {
	ctx, txm, done := newTestTransactionManager(t, false,
		mockEmptyReceiptListeners,
		func(conf *pldconf.TxManagerConfig, mc *mockComponents) {
			mc.db.ExpectExec("INSERT.*receipt_listeners").WillReturnResult(driver.ResultNoRows)
		},
	)
	defer done()

	err := txm.CreateReceiptListener(ctx, &pldapi.TransactionReceiptListener{
		Name:    "listener1",
		Started: confutil.P(false),
		Filters: pldapi.TransactionReceiptFilters{
			SequenceAbove: confutil.P(uint64(10000)),
		},
	})
	require.NoError(t, err)

	l := txm.receiptListeners["listener1"]
	l.initStart()

	err = l.processPersistedReceipt(&receiptDeliveryBatch{}, &transactionReceipt{})
	require.NoError(t, err)
	close(l.done)

}
