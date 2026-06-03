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

package statemgr

import (
	"context"
	"fmt"
	"testing"

	"github.com/LFDT-Paladin/paladin/core/internal/components"
	"github.com/LFDT-Paladin/paladin/core/pkg/persistence"
	"github.com/LFDT-Paladin/paladin/sdk/go/pkg/pldtypes"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const testDomain = "domain1"

// queryAllCompletionRows fetches every row from private_state_completion.
func queryAllCompletionRows(t *testing.T, ss *stateManager) []privateStateCompletion {
	t.Helper()
	var rows []privateStateCompletion
	err := ss.p.DB().Find(&rows).Error
	require.NoError(t, err)
	return rows
}

// seedCompletionRow inserts a completion row directly, bypassing business logic.
func seedCompletionRow(t *testing.T, ss *stateManager, contract string, missingStateID pldtypes.HexBytes, blockNumber int64) {
	t.Helper()
	err := ss.p.DB().Create(&privateStateCompletion{
		MissingStateID: missingStateID.String(),
		Contract:       contract,
		BlockNumber:    blockNumber,
	}).Error
	require.NoError(t, err)
}

// makeCompletionEntry builds a StateCompletionEntry using the given contract address.
func makeCompletionEntry(stateID pldtypes.HexBytes, contract pldtypes.EthAddress, blockNumber int64) components.StateCompletionEntry {
	return components.StateCompletionEntry{
		StateID:     stateID,
		Contract:    contract,
		BlockNumber: blockNumber,
	}
}

// ─── WriteStateCompletionsForBatch ────────────────────────────────────────────

func TestWriteStateCompletionsForBatch_AllStatesPresent(t *testing.T) {
	ctx, ss, _, done := newDBTestStateManager(t)
	defer done()

	contractAddr := *pldtypes.RandAddress()
	id1 := pldtypes.HexBytes(pldtypes.RandBytes(32))
	id2 := pldtypes.HexBytes(pldtypes.RandBytes(32))

	// Pre-insert both states so getStateIDsMissingPrivateData returns empty.
	insertTestState(t, ss, testDomain, id1)
	insertTestState(t, ss, testDomain, id2)

	entries := []components.StateCompletionEntry{
		makeCompletionEntry(id1, contractAddr, 100),
		makeCompletionEntry(id2, contractAddr, 100),
	}

	err := ss.p.Transaction(ctx, func(ctx context.Context, dbTX persistence.DBTX) error {
		return ss.WriteStateCompletionsForBatch(ctx, dbTX, testDomain, entries)
	})
	require.NoError(t, err)

	assert.Empty(t, queryAllCompletionRows(t, ss))
}

func TestWriteStateCompletionsForBatch_OneMissingState(t *testing.T) {
	ctx, ss, _, done := newDBTestStateManager(t)
	defer done()

	contractAddr := *pldtypes.RandAddress()
	presentID := pldtypes.HexBytes(pldtypes.RandBytes(32))
	missingID := pldtypes.HexBytes(pldtypes.RandBytes(32))

	insertTestState(t, ss, testDomain, presentID) // present; missingID is not inserted

	entries := []components.StateCompletionEntry{
		makeCompletionEntry(presentID, contractAddr, 200),
		makeCompletionEntry(missingID, contractAddr, 200),
	}

	err := ss.p.Transaction(ctx, func(ctx context.Context, dbTX persistence.DBTX) error {
		return ss.WriteStateCompletionsForBatch(ctx, dbTX, testDomain, entries)
	})
	require.NoError(t, err)

	rows := queryAllCompletionRows(t, ss)
	require.Len(t, rows, 1)
	assert.Equal(t, contractAddr.String(), rows[0].Contract)
	assert.Equal(t, missingID.String(), rows[0].MissingStateID)
	assert.Equal(t, int64(200), rows[0].BlockNumber)
}

func TestWriteStateCompletionsForBatch_MultipleMissingStates(t *testing.T) {
	ctx, ss, _, done := newDBTestStateManager(t)
	defer done()

	contractAddr := *pldtypes.RandAddress()
	id1 := pldtypes.HexBytes(pldtypes.RandBytes(32))
	id2 := pldtypes.HexBytes(pldtypes.RandBytes(32))
	id3 := pldtypes.HexBytes(pldtypes.RandBytes(32))

	entries := []components.StateCompletionEntry{
		makeCompletionEntry(id1, contractAddr, 300),
		makeCompletionEntry(id2, contractAddr, 300),
		makeCompletionEntry(id3, contractAddr, 300),
	}

	err := ss.p.Transaction(ctx, func(ctx context.Context, dbTX persistence.DBTX) error {
		return ss.WriteStateCompletionsForBatch(ctx, dbTX, testDomain, entries)
	})
	require.NoError(t, err)

	rows := queryAllCompletionRows(t, ss)
	require.Len(t, rows, 3)
	writtenIDs := make(map[string]bool)
	for _, r := range rows {
		writtenIDs[r.MissingStateID] = true
		assert.Equal(t, contractAddr.String(), r.Contract)
		assert.Equal(t, int64(300), r.BlockNumber)
	}
	assert.True(t, writtenIDs[id1.String()])
	assert.True(t, writtenIDs[id2.String()])
	assert.True(t, writtenIDs[id3.String()])
}

func TestWriteStateCompletionsForBatch_Idempotent(t *testing.T) {
	ctx, ss, _, done := newDBTestStateManager(t)
	defer done()

	contractAddr := *pldtypes.RandAddress()
	missingID := pldtypes.HexBytes(pldtypes.RandBytes(32))
	entries := []components.StateCompletionEntry{makeCompletionEntry(missingID, contractAddr, 10)}

	err := ss.p.Transaction(ctx, func(ctx context.Context, dbTX persistence.DBTX) error {
		if err := ss.WriteStateCompletionsForBatch(ctx, dbTX, testDomain, entries); err != nil {
			return err
		}
		return ss.WriteStateCompletionsForBatch(ctx, dbTX, testDomain, entries)
	})
	require.NoError(t, err)

	rows := queryAllCompletionRows(t, ss)
	require.Len(t, rows, 1)
	assert.Equal(t, missingID.String(), rows[0].MissingStateID)
}

func TestWriteStateCompletionsForBatch_EmptyEntries(t *testing.T) {
	ctx, ss, _, done := newDBTestStateManager(t)
	defer done()

	err := ss.p.Transaction(ctx, func(ctx context.Context, dbTX persistence.DBTX) error {
		return ss.WriteStateCompletionsForBatch(ctx, dbTX, testDomain, nil)
	})
	require.NoError(t, err)
	assert.Empty(t, queryAllCompletionRows(t, ss))
}

func TestWriteStateCompletionsForBatch_DBError(t *testing.T) {
	ctx, ss, db, _, done := newDBMockStateManager(t)
	defer done()

	db.ExpectQuery("SELECT.*id.*states").WillReturnError(fmt.Errorf("db lookup error"))

	contractAddr := *pldtypes.RandAddress()
	stateID := pldtypes.HexBytes(pldtypes.RandBytes(32))
	entries := []components.StateCompletionEntry{makeCompletionEntry(stateID, contractAddr, 10)}

	err := ss.WriteStateCompletionsForBatch(ctx, ss.p.NOTX(), testDomain, entries)
	require.ErrorContains(t, err, "db lookup error")
}

func TestWriteStateCompletionsForBatch_MultipleContracts(t *testing.T) {
	ctx, ss, _, done := newDBTestStateManager(t)
	defer done()

	contract1 := *pldtypes.RandAddress()
	contract2 := *pldtypes.RandAddress()
	id1 := pldtypes.HexBytes(pldtypes.RandBytes(32))
	id2 := pldtypes.HexBytes(pldtypes.RandBytes(32))

	entries := []components.StateCompletionEntry{
		{StateID: id1, Contract: contract1, BlockNumber: 50},
		{StateID: id2, Contract: contract2, BlockNumber: 51},
	}

	err := ss.p.Transaction(ctx, func(ctx context.Context, dbTX persistence.DBTX) error {
		return ss.WriteStateCompletionsForBatch(ctx, dbTX, testDomain, entries)
	})
	require.NoError(t, err)

	rows := queryAllCompletionRows(t, ss)
	require.Len(t, rows, 2)
	rowByID := make(map[string]privateStateCompletion)
	for _, r := range rows {
		rowByID[r.MissingStateID] = r
	}
	assert.Equal(t, contract1.String(), rowByID[id1.String()].Contract)
	assert.Equal(t, int64(50), rowByID[id1.String()].BlockNumber)
	assert.Equal(t, contract2.String(), rowByID[id2.String()].Contract)
	assert.Equal(t, int64(51), rowByID[id2.String()].BlockNumber)
}

// ─── updateStateCompletion ─────────────────────────────────────────────────────

func TestUpdateStateCompletion_EmptyList(t *testing.T) {
	ctx, ss, _, done := newDBTestStateManager(t)
	defer done()

	contractAddr := *pldtypes.RandAddress()
	missingID := pldtypes.HexBytes(pldtypes.RandBytes(32))
	seedCompletionRow(t, ss, contractAddr.String(), missingID, 10)

	err := ss.p.Transaction(ctx, func(ctx context.Context, dbTX persistence.DBTX) error {
		return ss.updateStateCompletion(ctx, dbTX, nil)
	})
	require.NoError(t, err)

	rows := queryAllCompletionRows(t, ss)
	require.Len(t, rows, 1)
}

func TestUpdateStateCompletion_NoMatchingRows(t *testing.T) {
	ctx, ss, _, done := newDBTestStateManager(t)
	defer done()

	contractAddr := *pldtypes.RandAddress()
	trackedID := pldtypes.HexBytes(pldtypes.RandBytes(32))
	seedCompletionRow(t, ss, contractAddr.String(), trackedID, 10)

	arrivedID := pldtypes.HexBytes(pldtypes.RandBytes(32))
	err := ss.p.Transaction(ctx, func(ctx context.Context, dbTX persistence.DBTX) error {
		return ss.updateStateCompletion(ctx, dbTX, []pldtypes.HexBytes{arrivedID})
	})
	require.NoError(t, err)

	rows := queryAllCompletionRows(t, ss)
	require.Len(t, rows, 1)
	assert.Equal(t, trackedID.String(), rows[0].MissingStateID)
}

func TestUpdateStateCompletion_SingleStateArrives(t *testing.T) {
	ctx, ss, _, done := newDBTestStateManager(t)
	defer done()

	contractAddr := *pldtypes.RandAddress()
	missingID := pldtypes.HexBytes(pldtypes.RandBytes(32))
	seedCompletionRow(t, ss, contractAddr.String(), missingID, 10)

	err := ss.p.Transaction(ctx, func(ctx context.Context, dbTX persistence.DBTX) error {
		return ss.updateStateCompletion(ctx, dbTX, []pldtypes.HexBytes{missingID})
	})
	require.NoError(t, err)

	assert.Empty(t, queryAllCompletionRows(t, ss))
}

func TestUpdateStateCompletion_MultipleStatesArrive(t *testing.T) {
	ctx, ss, _, done := newDBTestStateManager(t)
	defer done()

	contractAddr := *pldtypes.RandAddress()
	id1 := pldtypes.HexBytes(pldtypes.RandBytes(32))
	id2 := pldtypes.HexBytes(pldtypes.RandBytes(32))
	untrackedID := pldtypes.HexBytes(pldtypes.RandBytes(32))
	seedCompletionRow(t, ss, contractAddr.String(), id1, 10)
	seedCompletionRow(t, ss, contractAddr.String(), id2, 11)

	err := ss.p.Transaction(ctx, func(ctx context.Context, dbTX persistence.DBTX) error {
		return ss.updateStateCompletion(ctx, dbTX, []pldtypes.HexBytes{id1, id2, untrackedID})
	})
	require.NoError(t, err)

	assert.Empty(t, queryAllCompletionRows(t, ss))
}

func TestUpdateStateCompletion_PartialArrivals(t *testing.T) {
	ctx, ss, _, done := newDBTestStateManager(t)
	defer done()

	contractAddr := *pldtypes.RandAddress()
	id1 := pldtypes.HexBytes(pldtypes.RandBytes(32))
	id2 := pldtypes.HexBytes(pldtypes.RandBytes(32))
	seedCompletionRow(t, ss, contractAddr.String(), id1, 10)
	seedCompletionRow(t, ss, contractAddr.String(), id2, 10)

	err := ss.p.Transaction(ctx, func(ctx context.Context, dbTX persistence.DBTX) error {
		return ss.updateStateCompletion(ctx, dbTX, []pldtypes.HexBytes{id1})
	})
	require.NoError(t, err)

	rows := queryAllCompletionRows(t, ss)
	require.Len(t, rows, 1)
	assert.Equal(t, id2.String(), rows[0].MissingStateID)
}

// ─── CheckStateCompletionForContract ──────────────────────────────────────────

func TestCheckStateCompletionForContract_NoRows_Complete(t *testing.T) {
	ctx, ss, _, done := newDBTestStateManager(t)
	defer done()

	contractAddr := *pldtypes.RandAddress()
	complete, err := ss.CheckStateCompletionForContract(ctx, ss.p.NOTX(), contractAddr.String(), 1000)
	require.NoError(t, err)
	assert.True(t, complete)
}

func TestCheckStateCompletionForContract_RowAtOrBelowBlock_Incomplete(t *testing.T) {
	ctx, ss, _, done := newDBTestStateManager(t)
	defer done()

	contractAddr := *pldtypes.RandAddress()
	seedCompletionRow(t, ss, contractAddr.String(), pldtypes.RandBytes(32), 50)

	complete, err := ss.CheckStateCompletionForContract(ctx, ss.p.NOTX(), contractAddr.String(), 50)
	require.NoError(t, err)
	assert.False(t, complete)
}

func TestCheckStateCompletionForContract_RowAboveMaxBlock_Complete(t *testing.T) {
	ctx, ss, _, done := newDBTestStateManager(t)
	defer done()

	contractAddr := *pldtypes.RandAddress()
	seedCompletionRow(t, ss, contractAddr.String(), pldtypes.RandBytes(32), 100)

	complete, err := ss.CheckStateCompletionForContract(ctx, ss.p.NOTX(), contractAddr.String(), 50)
	require.NoError(t, err)
	assert.True(t, complete)
}

func TestCheckStateCompletionForContract_DifferentContract_DoesNotInterfere(t *testing.T) {
	ctx, ss, _, done := newDBTestStateManager(t)
	defer done()

	contractAddr := *pldtypes.RandAddress()
	otherContract := pldtypes.RandAddress().String()
	seedCompletionRow(t, ss, otherContract, pldtypes.RandBytes(32), 10)

	complete, err := ss.CheckStateCompletionForContract(ctx, ss.p.NOTX(), contractAddr.String(), 100)
	require.NoError(t, err)
	assert.True(t, complete)
}

func TestCheckStateCompletionForContract_MultipleRows_Incomplete(t *testing.T) {
	ctx, ss, _, done := newDBTestStateManager(t)
	defer done()

	contractAddr := *pldtypes.RandAddress()
	seedCompletionRow(t, ss, contractAddr.String(), pldtypes.RandBytes(32), 10)
	seedCompletionRow(t, ss, contractAddr.String(), pldtypes.RandBytes(32), 20)

	complete, err := ss.CheckStateCompletionForContract(ctx, ss.p.NOTX(), contractAddr.String(), 100)
	require.NoError(t, err)
	assert.False(t, complete)
}
