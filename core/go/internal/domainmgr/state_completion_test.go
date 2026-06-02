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

package domainmgr

import (
	"context"
	"fmt"
	"testing"

	"github.com/LFDT-Paladin/paladin/core/mocks/componentsmocks"
	"github.com/LFDT-Paladin/paladin/core/pkg/persistence"
	"github.com/LFDT-Paladin/paladin/sdk/go/pkg/pldapi"
	"github.com/LFDT-Paladin/paladin/sdk/go/pkg/pldtypes"
	"github.com/LFDT-Paladin/paladin/toolkit/pkg/prototk"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// completionTestContext wraps the necessary state for completion index tests.
type completionTestContext struct {
	ctx          context.Context
	td           *testDomainContext
	mockSS       *componentsmocks.StateManager
	contractAddr pldtypes.EthAddress
}

// newCompletionTestContext creates a real SQLite domain manager with a registered contract,
// replacing the real state store with a mock so GetTransactionStates is controllable.
func newCompletionTestContext(t *testing.T) (*completionTestContext, func()) {
	td, done := newTestDomain(t, true /* real SQLite */, goodDomainConf())

	// Replace the real state manager with a mock so tests control GetTransactionStates.
	// Tests are in the same package, so dm fields are accessible directly.
	mockSS := componentsmocks.NewStateManager(t)
	td.dm.stateStore = mockSS

	// Register a contract so GetSmartContractByAddress works in UpdateStateCompletion.
	_, contractAddr := registerTestSmartContract(t, td)

	return &completionTestContext{
		ctx:          td.ctx,
		td:           td,
		mockSS:       mockSS,
		contractAddr: contractAddr,
	}, done
}

// queryCompletionRows retrieves all rows from private_state_completion for asserting DB state.
func queryCompletionRows(t *testing.T, tc *completionTestContext) []privateStateCompletion {
	t.Helper()
	var rows []privateStateCompletion
	err := tc.td.dm.persistence.DB().
		Find(&rows).
		Error
	require.NoError(t, err)
	return rows
}

// insertCompletionRow inserts a test row directly (bypassing the business logic).
func insertCompletionRow(t *testing.T, tc *completionTestContext, contract string, txID uuid.UUID, blockNumber int64, nextMissing pldtypes.HexBytes) {
	t.Helper()
	err := tc.td.dm.persistence.DB().
		Create(&privateStateCompletion{
			Contract:         contract,
			TransactionID:    txID.String(),
			BlockNumber:      blockNumber,
			NextMissingState: nextMissing.String(),
		}).
		Error
	require.NoError(t, err)
}

// ─── WriteStateCompletionForTx ────────────────────────────────────────

func TestWriteStateCompletionForTx_Complete(t *testing.T) {
	tc, done := newCompletionTestContext(t)
	defer done()

	txID := uuid.New()
	txStates := &pldapi.TransactionStates{Confirmed: []*pldapi.StateBase{{ID: pldtypes.RandBytes(32)}}}

	mockDomain := componentsmocks.NewDomain(t)
	tc.mockSS.On("GetTransactionStates", mock.Anything, mock.Anything, txID).Return(txStates, nil).Once()
	mockDomain.On("CheckStateCompletion", mock.Anything, mock.Anything, txID, txStates).Return(pldtypes.HexBytes(nil), nil).Once()

	psc := componentsmocks.NewDomainSmartContract(t)
	psc.On("Domain").Return(mockDomain).Once()
	psc.On("Address").Return(tc.contractAddr).Once()

	err := tc.td.dm.persistence.Transaction(tc.ctx, func(ctx context.Context, dbTX persistence.DBTX) error {
		return tc.td.dm.WriteStateCompletionForTx(ctx, dbTX, psc, txID, 100)
	})
	require.NoError(t, err)

	// No row should be present — transaction is complete.
	rows := queryCompletionRows(t, tc)
	assert.Empty(t, rows)
}

func TestWriteStateCompletionForTx_MissingState(t *testing.T) {
	tc, done := newCompletionTestContext(t)
	defer done()

	txID := uuid.New()
	missingID := pldtypes.HexBytes(pldtypes.RandBytes(32))
	txStates := &pldapi.TransactionStates{}

	mockDomain := componentsmocks.NewDomain(t)
	tc.mockSS.On("GetTransactionStates", mock.Anything, mock.Anything, txID).Return(txStates, nil).Once()
	mockDomain.On("CheckStateCompletion", mock.Anything, mock.Anything, txID, txStates).Return(missingID, nil).Once()

	psc := componentsmocks.NewDomainSmartContract(t)
	psc.On("Domain").Return(mockDomain).Once()
	psc.On("Address").Return(tc.contractAddr).Once()

	err := tc.td.dm.persistence.Transaction(tc.ctx, func(ctx context.Context, dbTX persistence.DBTX) error {
		return tc.td.dm.WriteStateCompletionForTx(ctx, dbTX, psc, txID, 200)
	})
	require.NoError(t, err)

	rows := queryCompletionRows(t, tc)
	require.Len(t, rows, 1)
	assert.Equal(t, tc.contractAddr.String(), rows[0].Contract)
	assert.Equal(t, txID.String(), rows[0].TransactionID)
	assert.Equal(t, int64(200), rows[0].BlockNumber)
	assert.Equal(t, missingID.String(), rows[0].NextMissingState)
}

func TestWriteStateCompletionForTx_Upsert(t *testing.T) {
	// Writing twice for the same txID must result in a single row, not a duplicate.
	tc, done := newCompletionTestContext(t)
	defer done()

	txID := uuid.New()
	missingID1 := pldtypes.HexBytes(pldtypes.RandBytes(32))
	missingID2 := pldtypes.HexBytes(pldtypes.RandBytes(32))
	txStates := &pldapi.TransactionStates{}

	mockDomain := componentsmocks.NewDomain(t)
	tc.mockSS.On("GetTransactionStates", mock.Anything, mock.Anything, txID).Return(txStates, nil)
	mockDomain.On("CheckStateCompletion", mock.Anything, mock.Anything, txID, txStates).
		Return(missingID1, nil).Once()
	mockDomain.On("CheckStateCompletion", mock.Anything, mock.Anything, txID, txStates).
		Return(missingID2, nil).Once()

	psc := componentsmocks.NewDomainSmartContract(t)
	psc.On("Domain").Return(mockDomain).Times(2)
	psc.On("Address").Return(tc.contractAddr).Times(2)

	err := tc.td.dm.persistence.Transaction(tc.ctx, func(ctx context.Context, dbTX persistence.DBTX) error {
		if err := tc.td.dm.WriteStateCompletionForTx(ctx, dbTX, psc, txID, 10); err != nil {
			return err
		}
		return tc.td.dm.WriteStateCompletionForTx(ctx, dbTX, psc, txID, 10)
	})
	require.NoError(t, err)

	// Only one row; NextMissingState is from the second call.
	rows := queryCompletionRows(t, tc)
	require.Len(t, rows, 1)
	assert.Equal(t, missingID2.String(), rows[0].NextMissingState)
}

func TestWriteStateCompletionForTx_CompleteDeletesExistingRow(t *testing.T) {
	// If a row already exists for a txID and CheckStateCompletion now returns complete, the row is removed.
	tc, done := newCompletionTestContext(t)
	defer done()

	txID := uuid.New()
	missingID := pldtypes.HexBytes(pldtypes.RandBytes(32))

	// Pre-insert a stale row.
	insertCompletionRow(t, tc, tc.contractAddr.String(), txID, 50, missingID)

	txStates := &pldapi.TransactionStates{}
	mockDomain := componentsmocks.NewDomain(t)
	tc.mockSS.On("GetTransactionStates", mock.Anything, mock.Anything, txID).Return(txStates, nil).Once()
	mockDomain.On("CheckStateCompletion", mock.Anything, mock.Anything, txID, txStates).Return(pldtypes.HexBytes(nil), nil).Once()

	psc := componentsmocks.NewDomainSmartContract(t)
	psc.On("Domain").Return(mockDomain).Once()
	psc.On("Address").Return(tc.contractAddr).Once()

	err := tc.td.dm.persistence.Transaction(tc.ctx, func(ctx context.Context, dbTX persistence.DBTX) error {
		return tc.td.dm.WriteStateCompletionForTx(ctx, dbTX, psc, txID, 50)
	})
	require.NoError(t, err)

	rows := queryCompletionRows(t, tc)
	assert.Empty(t, rows)
}

func TestWriteStateCompletionForTx_GetStatesFail(t *testing.T) {
	// GetTransactionStates fails before Domain() or Address() are ever reached.
	tc, done := newCompletionTestContext(t)
	defer done()

	txID := uuid.New()
	tc.mockSS.On("GetTransactionStates", mock.Anything, mock.Anything, txID).Return(nil, fmt.Errorf("db error")).Once()

	psc := componentsmocks.NewDomainSmartContract(t)

	err := tc.td.dm.persistence.Transaction(tc.ctx, func(ctx context.Context, dbTX persistence.DBTX) error {
		return tc.td.dm.WriteStateCompletionForTx(ctx, dbTX, psc, txID, 10)
	})
	require.ErrorContains(t, err, "db error")
}

func TestWriteStateCompletionForTx_CheckCompletionFail(t *testing.T) {
	// Domain().CheckStateCompletion fails before Address() is reached.
	tc, done := newCompletionTestContext(t)
	defer done()

	txID := uuid.New()
	txStates := &pldapi.TransactionStates{}
	mockDomain := componentsmocks.NewDomain(t)
	tc.mockSS.On("GetTransactionStates", mock.Anything, mock.Anything, txID).Return(txStates, nil).Once()
	mockDomain.On("CheckStateCompletion", mock.Anything, mock.Anything, txID, txStates).Return(nil, fmt.Errorf("domain error")).Once()

	psc := componentsmocks.NewDomainSmartContract(t)
	psc.On("Domain").Return(mockDomain).Once()

	err := tc.td.dm.persistence.Transaction(tc.ctx, func(ctx context.Context, dbTX persistence.DBTX) error {
		return tc.td.dm.WriteStateCompletionForTx(ctx, dbTX, psc, txID, 10)
	})
	require.ErrorContains(t, err, "domain error")
}

// ─── UpdateStateCompletion ─────────────────────────────────

func TestUpdateStateCompletion_EmptyList(t *testing.T) {
	tc, done := newCompletionTestContext(t)
	defer done()

	// Insert a row that must remain untouched.
	txID := uuid.New()
	insertCompletionRow(t, tc, tc.contractAddr.String(), txID, 10, pldtypes.HexBytes(pldtypes.RandBytes(32)))

	err := tc.td.dm.persistence.Transaction(tc.ctx, func(ctx context.Context, dbTX persistence.DBTX) error {
		return tc.td.dm.UpdateStateCompletion(ctx, dbTX, nil)
	})
	require.NoError(t, err)

	// Row must be untouched — empty list is a no-op.
	rows := queryCompletionRows(t, tc)
	require.Len(t, rows, 1)
}

func TestUpdateStateCompletion_NoMatchingRows(t *testing.T) {
	tc, done := newCompletionTestContext(t)
	defer done()

	// Row with a next_missing_state that won't match any arrived ID.
	txID := uuid.New()
	otherState := pldtypes.HexBytes(pldtypes.RandBytes(32))
	insertCompletionRow(t, tc, tc.contractAddr.String(), txID, 10, otherState)

	arrivedState := pldtypes.HexBytes(pldtypes.RandBytes(32)) // different state
	err := tc.td.dm.persistence.Transaction(tc.ctx, func(ctx context.Context, dbTX persistence.DBTX) error {
		return tc.td.dm.UpdateStateCompletion(ctx, dbTX, []pldtypes.HexBytes{arrivedState})
	})
	require.NoError(t, err)

	// Row untouched.
	rows := queryCompletionRows(t, tc)
	require.Len(t, rows, 1)
	assert.Equal(t, otherState.String(), rows[0].NextMissingState)
}

func TestUpdateStateCompletion_StateArrives_TxNowComplete(t *testing.T) {
	tc, done := newCompletionTestContext(t)
	defer done()

	txID := uuid.New()
	missingID := pldtypes.HexBytes(pldtypes.RandBytes(32))
	insertCompletionRow(t, tc, tc.contractAddr.String(), txID, 10, missingID)

	txStates := &pldapi.TransactionStates{}
	tc.mockSS.On("GetTransactionStates", mock.Anything, mock.Anything, txID).Return(txStates, nil)
	// Domain confirms everything is now complete.
	tc.td.tp.Functions.CheckStateCompletion = func(_ context.Context, req *prototk.CheckStateCompletionRequest) (*prototk.CheckStateCompletionResponse, error) {
		return &prototk.CheckStateCompletionResponse{}, nil // NextMissingStateId == nil => complete
	}

	err := tc.td.dm.persistence.Transaction(tc.ctx, func(ctx context.Context, dbTX persistence.DBTX) error {
		return tc.td.dm.UpdateStateCompletion(ctx, dbTX, []pldtypes.HexBytes{missingID})
	})
	require.NoError(t, err)

	// Row deleted — transaction is complete.
	rows := queryCompletionRows(t, tc)
	assert.Empty(t, rows)
}

func TestUpdateStateCompletion_StateArrives_TxStillWaiting(t *testing.T) {
	tc, done := newCompletionTestContext(t)
	defer done()

	txID := uuid.New()
	missingID := pldtypes.HexBytes(pldtypes.RandBytes(32))
	nextMissingID := pldtypes.HexBytes(pldtypes.RandBytes(32))
	insertCompletionRow(t, tc, tc.contractAddr.String(), txID, 10, missingID)

	txStates := &pldapi.TransactionStates{}
	tc.mockSS.On("GetTransactionStates", mock.Anything, mock.Anything, txID).Return(txStates, nil)
	// Domain reports a different missing state.
	nextIDStr := nextMissingID.String()
	tc.td.tp.Functions.CheckStateCompletion = func(_ context.Context, req *prototk.CheckStateCompletionRequest) (*prototk.CheckStateCompletionResponse, error) {
		return &prototk.CheckStateCompletionResponse{NextMissingStateId: &nextIDStr}, nil
	}

	err := tc.td.dm.persistence.Transaction(tc.ctx, func(ctx context.Context, dbTX persistence.DBTX) error {
		return tc.td.dm.UpdateStateCompletion(ctx, dbTX, []pldtypes.HexBytes{missingID})
	})
	require.NoError(t, err)

	// Row updated with new next_missing_state.
	rows := queryCompletionRows(t, tc)
	require.Len(t, rows, 1)
	assert.Equal(t, nextMissingID.String(), rows[0].NextMissingState)
}

func TestUpdateStateCompletion_MultipleTxsUnblocked(t *testing.T) {
	tc, done := newCompletionTestContext(t)
	defer done()

	txID1 := uuid.New()
	txID2 := uuid.New()
	missingID1 := pldtypes.HexBytes(pldtypes.RandBytes(32))
	missingID2 := pldtypes.HexBytes(pldtypes.RandBytes(32))

	insertCompletionRow(t, tc, tc.contractAddr.String(), txID1, 10, missingID1)
	insertCompletionRow(t, tc, tc.contractAddr.String(), txID2, 11, missingID2)

	txStates := &pldapi.TransactionStates{}
	tc.mockSS.On("GetTransactionStates", mock.Anything, mock.Anything, txID1).Return(txStates, nil)
	tc.mockSS.On("GetTransactionStates", mock.Anything, mock.Anything, txID2).Return(txStates, nil)
	// Both complete after the state arrives.
	tc.td.tp.Functions.CheckStateCompletion = func(_ context.Context, req *prototk.CheckStateCompletionRequest) (*prototk.CheckStateCompletionResponse, error) {
		return &prototk.CheckStateCompletionResponse{}, nil
	}

	err := tc.td.dm.persistence.Transaction(tc.ctx, func(ctx context.Context, dbTX persistence.DBTX) error {
		return tc.td.dm.UpdateStateCompletion(ctx, dbTX, []pldtypes.HexBytes{missingID1, missingID2})
	})
	require.NoError(t, err)

	rows := queryCompletionRows(t, tc)
	assert.Empty(t, rows)
}

// ─── CheckStateCompletionForContract ─────────────────────────────────────────────

func TestCheckStateCompletionForContract_NoRows_Complete(t *testing.T) {
	tc, done := newCompletionTestContext(t)
	defer done()

	complete, err := tc.td.dm.CheckStateCompletionForContract(tc.ctx, tc.td.dm.persistence.NOTX(), tc.contractAddr.String(), 1000)
	require.NoError(t, err)
	assert.True(t, complete)
}

func TestCheckStateCompletionForContract_RowAtOrBelowBlock_Incomplete(t *testing.T) {
	tc, done := newCompletionTestContext(t)
	defer done()

	txID := uuid.New()
	insertCompletionRow(t, tc, tc.contractAddr.String(), txID, 50, pldtypes.HexBytes(pldtypes.RandBytes(32)))

	// blockHeight=50: the row at block 50 is included.
	complete, err := tc.td.dm.CheckStateCompletionForContract(tc.ctx, tc.td.dm.persistence.NOTX(), tc.contractAddr.String(), 50)
	require.NoError(t, err)
	assert.False(t, complete)
}

func TestCheckStateCompletionForContract_RowAboveMaxBlock_Complete(t *testing.T) {
	// A row at block 100 does not count when blockHeight=50.
	tc, done := newCompletionTestContext(t)
	defer done()

	txID := uuid.New()
	insertCompletionRow(t, tc, tc.contractAddr.String(), txID, 100, pldtypes.HexBytes(pldtypes.RandBytes(32)))

	complete, err := tc.td.dm.CheckStateCompletionForContract(tc.ctx, tc.td.dm.persistence.NOTX(), tc.contractAddr.String(), 50)
	require.NoError(t, err)
	assert.True(t, complete)
}

func TestCheckStateCompletionForContract_DifferentContract_DoesNotInterfere(t *testing.T) {
	// Rows for a different contract do not affect the result for our contract.
	tc, done := newCompletionTestContext(t)
	defer done()

	otherContract := pldtypes.RandAddress().String()
	txID := uuid.New()
	insertCompletionRow(t, tc, otherContract, txID, 10, pldtypes.HexBytes(pldtypes.RandBytes(32)))

	complete, err := tc.td.dm.CheckStateCompletionForContract(tc.ctx, tc.td.dm.persistence.NOTX(), tc.contractAddr.String(), 100)
	require.NoError(t, err)
	assert.True(t, complete)
}
