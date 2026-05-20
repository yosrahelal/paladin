/*
 * Copyright © 2026 Kaleido, Inc.
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

package grapher

import (
	"strings"
	"testing"

	"github.com/LFDT-Paladin/paladin/core/internal/components"
	"github.com/LFDT-Paladin/paladin/core/internal/msgs"
	"github.com/LFDT-Paladin/paladin/core/internal/sequencer/coordinator/dependencytracker"
	"github.com/LFDT-Paladin/paladin/sdk/go/pkg/pldapi"
	"github.com/LFDT-Paladin/paladin/sdk/go/pkg/pldtypes"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const testBlockHeightTolerance uint64 = 5

func testGrapher(t *testing.T) Grapher {
	t.Helper()
	return NewGrapher(dependencytracker.NewDependencyTracker(), testBlockHeightTolerance)
}

func testGrapherUnlocked(t *testing.T) *grapher {
	t.Helper()
	return NewGrapher(dependencytracker.NewDependencyTracker(), testBlockHeightTolerance).(*grapher)
}

func TestGrapher_NewGrapher(t *testing.T) {
	g := testGrapher(t)
	assert.NotNil(t, g)
}

func TestAddMinter_Success(t *testing.T) {
	ctx := t.Context()
	g := testGrapherUnlocked(t)
	minterID := uuid.New()
	stateID := pldtypes.MustParseHexBytes("0x" + strings.Repeat("aa", 32))
	allowedNodes := map[string][]string{stateID.String(): {"node1", "node2"}}

	err := g.AddMinter(ctx, []*components.FullState{
		{ID: stateID, Schema: pldtypes.MustParseBytes32("0x" + strings.Repeat("bb", 32)), Data: pldtypes.RawJSON(`{}`)},
	}, minterID, allowedNodes)
	require.NoError(t, err)

	assert.Equal(t, minterID, g.transactionByOutputState[stateID.String()].ID)
	require.Contains(t, g.outputStatesByMinter, minterID)
	require.Len(t, g.outputStatesByMinter[minterID], 1)
	assert.True(t, g.outputStatesByMinter[minterID][0].ID.Equals(stateID))
	assert.Equal(t, []string{"node1", "node2"}, g.outputStatesByMinter[minterID][0].AllowedNodes)
}

func TestAddMinter_MultipleStates_AppendsToOutputStatesByMinter(t *testing.T) {
	ctx := t.Context()
	g := testGrapherUnlocked(t)
	minterID := uuid.New()
	s1 := pldtypes.MustParseHexBytes("0x" + strings.Repeat("01", 32))
	s2 := pldtypes.MustParseHexBytes("0x" + strings.Repeat("02", 32))
	states := []*components.FullState{
		{ID: s1, Schema: pldtypes.MustParseBytes32("0x" + strings.Repeat("03", 32)), Data: pldtypes.RawJSON(`{}`)},
		{ID: s2, Schema: pldtypes.MustParseBytes32("0x" + strings.Repeat("04", 32)), Data: pldtypes.RawJSON(`{}`)},
	}
	require.NoError(t, g.AddMinter(ctx, states, minterID, nil))
	require.Len(t, g.outputStatesByMinter[minterID], 2)
	assert.True(t, g.outputStatesByMinter[minterID][0].ID.Equals(s1))
	assert.True(t, g.outputStatesByMinter[minterID][1].ID.Equals(s2))
}

func TestAddMinter_RegistersSameGrapherTXInTransactionByIDAndTransactionByOutputState(t *testing.T) {
	ctx := t.Context()
	g := testGrapherUnlocked(t)
	minterID := uuid.New()
	stateID := pldtypes.MustParseHexBytes("0x" + strings.Repeat("c0", 32))
	states := []*components.FullState{
		{ID: stateID, Schema: pldtypes.MustParseBytes32("0x" + strings.Repeat("c1", 32)), Data: pldtypes.RawJSON(`{}`)},
	}

	require.NoError(t, g.AddMinter(ctx, states, minterID, nil))

	txByID, ok := g.transactionByID[minterID]
	require.True(t, ok, "AddMinter should register the minter in transactionByID")
	assert.Equal(t, minterID, txByID.ID)

	txByOutput, ok := g.transactionByOutputState[stateID.String()]
	require.True(t, ok, "AddMinter should register each minted state in transactionByOutputState")
	assert.Same(t, txByID, txByOutput, "both indexes should reference the same grapherTX")
}

func TestAddMinter_AlreadyExists(t *testing.T) {
	ctx := t.Context()
	g := testGrapherUnlocked(t)
	firstMinter := uuid.New()
	secondMinter := uuid.New()
	stateID := pldtypes.MustParseHexBytes("0x" + strings.Repeat("cc", 32))
	state := &components.FullState{ID: stateID, Schema: pldtypes.MustParseBytes32("0x" + strings.Repeat("dd", 32)), Data: pldtypes.RawJSON(`{}`)}

	require.NoError(t, g.AddMinter(ctx, []*components.FullState{state}, firstMinter, nil))
	err := g.AddMinter(ctx, []*components.FullState{state}, secondMinter, nil)
	require.Error(t, err)
	assert.ErrorContains(t, err, string(msgs.MsgSequencerGrapherAddMinterAlreadyExistsError))
}

func TestAddConsumer_Idempotent(t *testing.T) {
	g := testGrapherUnlocked(t)
	txID := uuid.New()
	g.mu.Lock()
	g.addConsumer(txID)
	g.addConsumer(txID)
	g.mu.Unlock()
	require.Contains(t, g.transactionByID, txID)
}

func TestLockMintsOnSpend_DependsOnMinter(t *testing.T) {
	ctx := t.Context()
	g := testGrapher(t)
	minterID := uuid.New()
	consumerID := uuid.New()
	stateID := pldtypes.MustParseHexBytes("0x" + strings.Repeat("ee", 32))
	state := &components.FullState{ID: stateID, Schema: pldtypes.MustParseBytes32("0x" + strings.Repeat("ff", 32)), Data: pldtypes.RawJSON(`{}`)}

	require.NoError(t, g.AddMinter(ctx, []*components.FullState{state}, minterID, nil))
	g.LockMintsOnReadAndSpend(ctx, []*components.FullState{}, []*components.FullState{state}, consumerID)

	assert.Equal(t, []uuid.UUID{minterID}, g.GetDependencies(ctx, consumerID))
}

func TestLockMintsOnRead_DependsOnMinter(t *testing.T) {
	ctx := t.Context()
	g := testGrapher(t)
	minterID := uuid.New()
	readerID := uuid.New()
	stateID := pldtypes.MustParseHexBytes("0x" + strings.Repeat("11", 32))
	state := &components.FullState{ID: stateID, Schema: pldtypes.MustParseBytes32("0x" + strings.Repeat("22", 32)), Data: pldtypes.RawJSON(`{}`)}

	require.NoError(t, g.AddMinter(ctx, []*components.FullState{state}, minterID, nil))
	g.LockMintsOnReadAndSpend(ctx, []*components.FullState{state}, []*components.FullState{}, readerID)

	assert.Equal(t, []uuid.UUID{minterID}, g.GetDependencies(ctx, readerID))
}

func TestGetDependencies_UnknownTransaction_ReturnsNil(t *testing.T) {
	ctx := t.Context()
	g := testGrapher(t)
	assert.Nil(t, g.GetDependencies(ctx, uuid.New()))
}

func TestGetDependents_UnknownTransaction_ReturnsNil(t *testing.T) {
	ctx := t.Context()
	g := testGrapher(t)
	assert.Nil(t, g.GetDependents(ctx, uuid.New()))
}

func TestGetDependents_ConsumerWithNoReadPrereqs_ReturnsEmptySlice(t *testing.T) {
	ctx := t.Context()
	g := testGrapher(t)
	consumerID := uuid.New()
	unknown := pldtypes.MustParseHexBytes("0x" + strings.Repeat("b1", 32))
	g.LockMintsOnReadAndSpend(ctx, []*components.FullState{{ID: unknown}}, []*components.FullState{}, consumerID)

	assert.Empty(t, g.GetDependents(ctx, consumerID))
}

func TestGetDependents_ConsumerWithNoSpendPrereqs_ReturnsEmptySlice(t *testing.T) {
	ctx := t.Context()
	g := testGrapher(t)
	consumerID := uuid.New()
	unknown := pldtypes.MustParseHexBytes("0x" + strings.Repeat("b1", 32))
	g.LockMintsOnReadAndSpend(ctx, []*components.FullState{}, []*components.FullState{{ID: unknown}}, consumerID)

	assert.Empty(t, g.GetDependents(ctx, consumerID))
}

func TestGetDependents_ReturnsDependentsViaPrerequisiteEdges(t *testing.T) {
	ctx := t.Context()
	g := testGrapherUnlocked(t)
	prereqID := uuid.New()
	dependentA := uuid.New()
	dependentB := uuid.New()

	g.mu.Lock()
	g.addConsumer(prereqID)
	g.addConsumer(dependentA)
	g.addConsumer(dependentB)
	g.dependencyChain.AddPrerequisites(ctx, dependentA, prereqID)
	g.dependencyChain.AddPrerequisites(ctx, dependentB, prereqID)
	g.mu.Unlock()

	assert.ElementsMatch(t, []uuid.UUID{dependentA, dependentB}, g.GetDependents(ctx, prereqID))
}

func TestLockMintsOnSpend_UnknownReadState_NoDependency(t *testing.T) {
	ctx := t.Context()
	g := testGrapher(t)
	consumerID := uuid.New()
	unknown := pldtypes.MustParseHexBytes("0x" + strings.Repeat("33", 32))
	state := &components.FullState{ID: unknown}

	g.LockMintsOnReadAndSpend(ctx, []*components.FullState{state}, []*components.FullState{}, consumerID)
	assert.Empty(t, g.GetDependencies(ctx, consumerID))
}

func TestLockMintsOnSpend_UnknownSpendState_NoDependency(t *testing.T) {
	ctx := t.Context()
	g := testGrapher(t)
	consumerID := uuid.New()
	unknown := pldtypes.MustParseHexBytes("0x" + strings.Repeat("33", 32))
	state := &components.FullState{ID: unknown}

	g.LockMintsOnReadAndSpend(ctx, []*components.FullState{}, []*components.FullState{state}, consumerID)
	assert.Empty(t, g.GetDependencies(ctx, consumerID))
}

func TestLockMintsOnSpend_MultipleStates_AppendsSpendLocks(t *testing.T) {
	ctx := t.Context()
	g := testGrapherUnlocked(t)
	txID := uuid.New()
	s1 := pldtypes.MustParseHexBytes("0x" + strings.Repeat("de", 32))
	s2 := pldtypes.MustParseHexBytes("0x" + strings.Repeat("ef", 32))

	g.LockMintsOnReadAndSpend(ctx, []*components.FullState{}, []*components.FullState{{ID: s1}, {ID: s2}}, txID)

	locks := g.locksByTransaction[txID]
	require.Len(t, locks, 2)
	assert.True(t, locks[0].State.Equals(s1))
	assert.True(t, locks[1].State.Equals(s2))
	assert.Equal(t, pldapi.StateLockTypeSpend.Enum(), locks[0].Type)
}

func TestLockMintsOnCreate_LocksPotentialStates(t *testing.T) {
	ctx := t.Context()
	g := testGrapher(t)
	txID := uuid.New()
	createdBy := uuid.New()
	stateID := pldtypes.MustParseHexBytes("0x" + strings.Repeat("44", 32))
	upserts := []*components.StateUpsert{
		{ID: stateID, CreatedBy: &createdBy},
	}
	states := []*components.FullState{{ID: stateID}}

	g.LockMintsOnCreate(ctx, upserts, states, txID)

	data, err := g.ExportStatesAndLocks(ctx, "test-node")
	require.NoError(t, err)
	require.Len(t, data.LockedState, 1)
	assert.True(t, data.LockedState[0].State.Equals(stateID))
	require.NotNil(t, data.LockedState[0].Transaction)
	assert.Equal(t, txID, *data.LockedState[0].Transaction)
	assert.Equal(t, pldapi.StateLockTypeCreate.Enum(), data.LockedState[0].Type)
}

func TestLockMintsOnCreate_NoCreatedBy_NoLocks(t *testing.T) {
	ctx := t.Context()
	g := testGrapher(t)
	txID := uuid.New()
	stateID := pldtypes.MustParseHexBytes("0x" + strings.Repeat("90", 32))
	upserts := []*components.StateUpsert{{ID: stateID, CreatedBy: nil}}
	states := []*components.FullState{{ID: stateID}}

	g.LockMintsOnCreate(ctx, upserts, states, txID)

	data, err := g.ExportStatesAndLocks(ctx, "test-node")
	require.NoError(t, err)
	assert.Empty(t, data.LockedState)
}

func TestLockMintsOnCreate_MixedCreatedBy_AppendsOnlyPotential(t *testing.T) {
	ctx := t.Context()
	g := testGrapher(t)
	txID := uuid.New()
	createdBy := uuid.New()
	s1 := pldtypes.MustParseHexBytes("0x" + strings.Repeat("91", 32))
	s2 := pldtypes.MustParseHexBytes("0x" + strings.Repeat("92", 32))
	upserts := []*components.StateUpsert{
		{ID: s1, CreatedBy: nil},
		{ID: s2, CreatedBy: &createdBy},
	}
	states := []*components.FullState{{ID: s1}, {ID: s2}}

	g.LockMintsOnCreate(ctx, upserts, states, txID)

	data, err := g.ExportStatesAndLocks(ctx, "test-node")
	require.NoError(t, err)
	require.Len(t, data.LockedState, 1)
	assert.True(t, data.LockedState[0].State.Equals(s2))
}

func TestExportStatesAndLocks_OutputAndLocks(t *testing.T) {
	ctx := t.Context()
	g := testGrapher(t)
	minterID := uuid.New()
	consumerID := uuid.New()
	stateID := pldtypes.MustParseHexBytes("0x" + strings.Repeat("55", 32))
	state := &components.FullState{ID: stateID, Schema: pldtypes.MustParseBytes32("0x" + strings.Repeat("66", 32)), Data: pldtypes.RawJSON(`{"x":1}`)}

	require.NoError(t, g.AddMinter(ctx, []*components.FullState{state}, minterID, map[string][]string{stateID.String(): {"test-node"}}))
	g.LockMintsOnReadAndSpend(ctx, []*components.FullState{state}, []*components.FullState{}, consumerID)

	data, err := g.ExportStatesAndLocks(ctx, "test-node")
	require.NoError(t, err)
	require.Len(t, data.OutputState, 1)
	assert.True(t, data.OutputState[0].ID.Equals(stateID))
	require.Len(t, data.LockedState, 1)
	assert.True(t, data.LockedState[0].State.Equals(stateID))
}

func TestExportStatesAndLocks_EmptyGrapher(t *testing.T) {
	ctx := t.Context()
	g := testGrapher(t)
	data, err := g.ExportStatesAndLocks(ctx, "test-node")
	require.NoError(t, err)
	assert.Empty(t, data.OutputState)
	assert.Empty(t, data.LockedState)
}

func TestForgetTransactionAndLocks_UnknownTransaction_NoOp(t *testing.T) {
	ctx := t.Context()
	g := testGrapher(t)
	unknown := uuid.New()
	g.ForgetTransactionAndLocks(ctx, unknown)
	assert.Nil(t, g.GetDependencies(ctx, unknown))
}

func TestForgetTransactionAndLocks_RemoveAllDependencyLinks_SkipsMissingDependent(t *testing.T) {
	ctx := t.Context()
	g := testGrapherUnlocked(t)
	ghostDependent := uuid.New()
	realDependent := uuid.New()
	minterID := uuid.New()
	stateID := pldtypes.MustParseHexBytes("0x" + strings.Repeat("a0", 32))
	state := &components.FullState{ID: stateID, Schema: pldtypes.MustParseBytes32("0x" + strings.Repeat("a1", 32)), Data: pldtypes.RawJSON(`{}`)}

	require.NoError(t, g.AddMinter(ctx, []*components.FullState{state}, minterID, nil))
	g.LockMintsOnReadAndSpend(ctx, []*components.FullState{}, []*components.FullState{state}, realDependent)

	g.mu.Lock()
	g.addConsumer(ghostDependent)
	g.dependencyChain.AddPrerequisites(ctx, ghostDependent, minterID)
	g.mu.Unlock()

	g.ForgetTransactionAndLocks(ctx, minterID)

	assert.Empty(t, g.GetDependencies(ctx, realDependent))
}

func TestForgetTransactionAndLocks_RemoveAllDependencyLinks_SkipsMissingPrerequisite(t *testing.T) {
	ctx := t.Context()
	g := testGrapherUnlocked(t)
	txID := uuid.New()
	ghostPrereq := uuid.New()
	minterID := uuid.New()
	stateID := pldtypes.MustParseHexBytes("0x" + strings.Repeat("b0", 32))
	state := &components.FullState{ID: stateID, Schema: pldtypes.MustParseBytes32("0x" + strings.Repeat("b1", 32)), Data: pldtypes.RawJSON(`{}`)}

	require.NoError(t, g.AddMinter(ctx, []*components.FullState{state}, minterID, nil))

	g.mu.Lock()
	g.addConsumer(ghostPrereq)
	g.addConsumer(txID)
	g.dependencyChain.AddPrerequisites(ctx, txID, minterID, ghostPrereq)
	g.mu.Unlock()

	g.ForgetTransactionAndLocks(ctx, txID)

	assert.NotContains(t, g.GetDependents(ctx, minterID), txID)
}

func TestForgetTransactionAndLocks_ClearsPrereqOnMinterWhenConsumerForgotten(t *testing.T) {
	ctx := t.Context()
	g := testGrapherUnlocked(t)
	minterID := uuid.New()
	consumerID := uuid.New()
	stateID := pldtypes.MustParseHexBytes("0x" + strings.Repeat("f0", 32))
	state := &components.FullState{ID: stateID, Schema: pldtypes.MustParseBytes32("0x" + strings.Repeat("f1", 32)), Data: pldtypes.RawJSON(`{}`)}

	require.NoError(t, g.AddMinter(ctx, []*components.FullState{state}, minterID, nil))
	g.LockMintsOnReadAndSpend(ctx, []*components.FullState{}, []*components.FullState{state}, consumerID)

	require.Contains(t, g.GetDependents(ctx, minterID), consumerID)

	g.ForgetTransactionAndLocks(ctx, consumerID)

	assert.NotContains(t, g.GetDependents(ctx, minterID), consumerID)
}

func TestForgetTransactionAndLocks_ClearsMinterConsumerAndLocks(t *testing.T) {
	ctx := t.Context()
	g := testGrapherUnlocked(t)
	minterID := uuid.New()
	consumerID := uuid.New()
	createdBy := uuid.New()
	stateID := pldtypes.MustParseHexBytes("0x" + strings.Repeat("77", 32))
	state := &components.FullState{ID: stateID, Schema: pldtypes.MustParseBytes32("0x" + strings.Repeat("88", 32)), Data: pldtypes.RawJSON(`{}`)}

	require.NoError(t, g.AddMinter(ctx, []*components.FullState{state}, minterID, nil))
	g.LockMintsOnCreate(ctx, []*components.StateUpsert{{ID: stateID, CreatedBy: &createdBy}}, []*components.FullState{{ID: stateID}}, minterID)
	g.LockMintsOnReadAndSpend(ctx, []*components.FullState{}, []*components.FullState{state}, consumerID)
	g.ForgetTransactionAndLocks(ctx, minterID)

	// Transaction-indexed maps cleared
	_, ok := g.transactionByOutputState[stateID.String()]
	assert.False(t, ok)
	_, ok = g.outputStatesByMinter[minterID]
	assert.False(t, ok)
	// outputStatesByStateID cleared via cascade from the create lock deletion
	_, ok = g.outputStatesByStateID[stateID.String()]
	assert.False(t, ok)
}

func TestForgetTransactionAndLocks_ClearsLocksForTransaction(t *testing.T) {
	ctx := t.Context()
	g := testGrapherUnlocked(t)
	txID := uuid.New()
	s := pldtypes.MustParseHexBytes("0x" + strings.Repeat("ab", 32))
	// Read lock → lands in readLocksByStateID
	g.LockMintsOnReadAndSpend(ctx, []*components.FullState{{ID: s}}, []*components.FullState{}, txID)
	require.Contains(t, g.locksByTransaction, txID)
	require.Contains(t, g.readLocksByStateID, s.String())
	g.ForgetTransactionAndLocks(ctx, txID)
	_, ok := g.locksByTransaction[txID]
	assert.False(t, ok)
	_, ok = g.readLocksByStateID[s.String()]
	assert.False(t, ok)
}

func TestForgetTransactionAndLocks_AlreadyConfirmedTransaction_NoOp(t *testing.T) {
	ctx := t.Context()
	g := testGrapher(t)
	txID := uuid.New()
	s := pldtypes.MustParseHexBytes("0x" + strings.Repeat("cd", 32))
	g.LockMintsOnReadAndSpend(ctx, []*components.FullState{{ID: s}}, []*components.FullState{}, txID)
	g.ForgetTransaction(ctx, txID, 100)
	// Second call (from cleanUpTransaction) must be a no-op
	g.ForgetTransactionAndLocks(ctx, txID)
	// The confirmed lock (no transaction) should still be present — ForgetTransactionAndLocks is a no-op once confirmed
	data, err := g.ExportStatesAndLocks(ctx, "test-node")
	require.NoError(t, err)
	assert.Len(t, data.LockedState, 1)
}

func TestForgetTransaction_OutputStateRemainsForHeartbeatsUntilLockExpires(t *testing.T) {
	ctx := t.Context()
	g := testGrapher(t)
	txID := uuid.New()
	createdBy := uuid.New()
	s := pldtypes.MustParseHexBytes("0x" + strings.Repeat("e1", 32))
	state := &components.FullState{ID: s, Schema: pldtypes.MustParseBytes32("0x" + strings.Repeat("e2", 32)), Data: pldtypes.RawJSON(`{}`)}

	require.NoError(t, g.AddMinter(ctx, []*components.FullState{state}, txID, map[string][]string{s.String(): {"test-node"}}))
	g.LockMintsOnCreate(ctx, []*components.StateUpsert{{ID: s, CreatedBy: &createdBy}}, []*components.FullState{{ID: s}}, txID)
	g.ForgetTransaction(ctx, txID, 100)

	// OutputState should still be exported for heartbeats after confirmation
	data, err := g.ExportStatesAndLocks(ctx, "test-node")
	require.NoError(t, err)
	require.Len(t, data.OutputState, 1, "OutputState must remain after confirmation for handover heartbeats")
	assert.True(t, data.OutputState[0].ID.Equals(s))

	// Once the lock expires, both the lock and the OutputState are removed
	g.ForgetLocks(ctx, 100+testBlockHeightTolerance)
	data, err = g.ExportStatesAndLocks(ctx, "test-node")
	require.NoError(t, err)
	assert.Empty(t, data.LockedState)
	assert.Empty(t, data.OutputState, "OutputState must be removed when the lock expires")
}

func TestForgetTransaction_StampsConfirmedAtBlockAndClearsTransaction(t *testing.T) {
	ctx := t.Context()
	g := testGrapherUnlocked(t)
	txID := uuid.New()
	createdBy := uuid.New()
	s := pldtypes.MustParseHexBytes("0x" + strings.Repeat("12", 32))
	upserts := []*components.StateUpsert{{ID: s, CreatedBy: &createdBy}}
	states := []*components.FullState{{ID: s}}

	g.LockMintsOnCreate(ctx, upserts, states, txID)
	g.ForgetTransaction(ctx, txID, 100)

	// Transaction removed from grapher indexes
	assert.NotContains(t, g.transactionByID, txID)
	assert.NotContains(t, g.locksByTransaction, txID)

	// Create lock still present — transaction cleared, confirmedAtBlock set
	lock, ok := g.createLocksByStateID[s.String()]
	require.True(t, ok)
	assert.Nil(t, lock.Transaction)
	require.NotNil(t, lock.ConfirmedAtBlock)
	assert.Equal(t, uint64(100), *lock.ConfirmedAtBlock)
	assert.True(t, lock.State.Equals(s))
}

// TestForgetTransaction_CreateAndSpendLocksStampedIndependently verifies that when a minter
// transaction and a consumer transaction both confirm, each lock (create and spend) receives the
// confirmedAtBlock of its own transaction. This relies on the stateLock object being shared by
// pointer between locksByTransaction and the type-segregated maps: stamping via the transaction
// index propagates to the state-ID index automatically without direct map access.
func TestForgetTransaction_CreateAndSpendLocksStampedIndependently(t *testing.T) {
	ctx := t.Context()
	g := testGrapherUnlocked(t)

	minterTx := uuid.New()
	consumerTx := uuid.New()
	createdBy := uuid.New()
	stateID := pldtypes.MustParseHexBytes("0x" + strings.Repeat("5c", 32))
	state := &components.FullState{ID: stateID}

	// Minter assembles: create lock recorded in createLocksByStateID.
	g.LockMintsOnCreate(ctx,
		[]*components.StateUpsert{{ID: stateID, CreatedBy: &createdBy}},
		[]*components.FullState{{ID: stateID}},
		minterTx,
	)
	// Consumer assembles: spend lock recorded in spendLocksByStateID.
	g.LockMintsOnReadAndSpend(ctx, []*components.FullState{}, []*components.FullState{state}, consumerTx)

	// Minter confirms first at block 10.
	g.ForgetTransaction(ctx, minterTx, 10)

	// Create lock should carry block 10; spend lock still transaction-owned.
	createLock, ok := g.createLocksByStateID[stateID.String()]
	require.True(t, ok)
	assert.Nil(t, createLock.Transaction)
	require.NotNil(t, createLock.ConfirmedAtBlock)
	assert.Equal(t, uint64(10), *createLock.ConfirmedAtBlock)

	spendLock, ok := g.spendLocksByStateID[stateID.String()]
	require.True(t, ok)
	require.NotNil(t, spendLock.Transaction, "spend lock must still be transaction-owned")
	assert.Equal(t, consumerTx, *spendLock.Transaction)

	// Consumer confirms later at block 20.
	g.ForgetTransaction(ctx, consumerTx, 20)

	// Spend lock now carries block 20, independently of the create lock's block 10.
	spendLock, ok = g.spendLocksByStateID[stateID.String()]
	require.True(t, ok)
	assert.Nil(t, spendLock.Transaction)
	require.NotNil(t, spendLock.ConfirmedAtBlock)
	assert.Equal(t, uint64(20), *spendLock.ConfirmedAtBlock)

	// Create lock is unaffected by the consumer confirmation.
	createLock = g.createLocksByStateID[stateID.String()]
	require.NotNil(t, createLock.ConfirmedAtBlock)
	assert.Equal(t, uint64(10), *createLock.ConfirmedAtBlock, "create lock must retain its own confirmedAtBlock")
}

func TestForgetTransaction_ClearsInFlightIndexesButKeepsStateData(t *testing.T) {
	ctx := t.Context()
	g := testGrapherUnlocked(t)
	txID := uuid.New()
	stateID := pldtypes.MustParseHexBytes("0x" + strings.Repeat("34", 32))
	state := &components.FullState{ID: stateID, Schema: pldtypes.MustParseBytes32("0x" + strings.Repeat("35", 32)), Data: pldtypes.RawJSON(`{}`)}

	require.NoError(t, g.AddMinter(ctx, []*components.FullState{state}, txID, map[string][]string{stateID.String(): {"node1"}}))
	createdBy := uuid.New()
	g.LockMintsOnCreate(ctx, []*components.StateUpsert{{ID: stateID, CreatedBy: &createdBy}}, []*components.FullState{{ID: stateID}}, txID)
	g.ForgetTransaction(ctx, txID, 50)

	// All transaction tracking removed — txID is no longer known to the grapher
	assert.NotContains(t, g.transactionByID, txID)
	assert.NotContains(t, g.locksByTransaction, txID)
	assert.NotContains(t, g.outputStatesByMinter, txID)
	assert.NotContains(t, g.transactionByOutputState, stateID.String())

	// Private state data kept in outputStatesByStateID until the lock expires
	assert.Contains(t, g.outputStatesByStateID, stateID.String())

	// Once the lock expires, OutputState is also cleaned up
	g.ForgetLocks(ctx, 50+testBlockHeightTolerance)
	assert.NotContains(t, g.outputStatesByStateID, stateID.String())
}

func TestForgetTransaction_UnknownTransaction_NoOp(t *testing.T) {
	ctx := t.Context()
	g := testGrapher(t)
	// Should be a no-op with no panic
	g.ForgetTransaction(ctx, uuid.New(), 100)
	data, err := g.ExportStatesAndLocks(ctx, "test-node")
	require.NoError(t, err)
	assert.Empty(t, data.LockedState)
}

func TestForgetLocks_RemovesExpiredLocks(t *testing.T) {
	ctx := t.Context()
	g := testGrapher(t)
	txID := uuid.New()
	s := pldtypes.MustParseHexBytes("0x" + strings.Repeat("56", 32))
	g.LockMintsOnReadAndSpend(ctx, []*components.FullState{{ID: s}}, []*components.FullState{}, txID)
	g.ForgetTransaction(ctx, txID, 100)

	// tolerance = 5, confirmedAt = 100, expires at >= 105
	g.ForgetLocks(ctx, 104) // not yet expired
	data, err := g.ExportStatesAndLocks(ctx, "test-node")
	require.NoError(t, err)
	assert.Len(t, data.LockedState, 1)

	g.ForgetLocks(ctx, 105) // exactly at expiry
	data, err = g.ExportStatesAndLocks(ctx, "test-node")
	require.NoError(t, err)
	assert.Empty(t, data.LockedState)
}

func TestForgetLocks_DoesNotRemoveTransactionOwnedLocks(t *testing.T) {
	ctx := t.Context()
	g := testGrapher(t)
	txID := uuid.New()
	s := pldtypes.MustParseHexBytes("0x" + strings.Repeat("78", 32))
	g.LockMintsOnReadAndSpend(ctx, []*components.FullState{{ID: s}}, []*components.FullState{}, txID)

	// Should not touch transaction-owned locks
	g.ForgetLocks(ctx, 99999)
	data, err := g.ExportStatesAndLocks(ctx, "test-node")
	require.NoError(t, err)
	assert.Len(t, data.LockedState, 1)
}

func TestImportStatesAndLocks_AddsTxFreeLocks(t *testing.T) {
	ctx := t.Context()
	g := testGrapher(t)
	s := pldtypes.MustParseHexBytes("0x" + strings.Repeat("9a", 32))
	confirmedAt := uint64(200)
	locks := []*StateLock{
		{State: s, Type: pldapi.StateLockTypeSpend.Enum(), ConfirmedAtBlock: &confirmedAt},
	}

	g.ImportStatesAndLocks(ctx, nil, locks)

	data, err := g.ExportStatesAndLocks(ctx, "test-node")
	require.NoError(t, err)
	require.Len(t, data.LockedState, 1)
	assert.True(t, data.LockedState[0].State.Equals(s))
	assert.Nil(t, data.LockedState[0].Transaction)
	require.NotNil(t, data.LockedState[0].ConfirmedAtBlock)
	assert.Equal(t, uint64(200), *data.LockedState[0].ConfirmedAtBlock)
}

func TestImportStatesAndLocks_SkipsLockWithNoTransactionAndNoConfirmedAtBlock(t *testing.T) {
	ctx := t.Context()
	g := testGrapher(t)
	s := pldtypes.MustParseHexBytes("0x" + strings.Repeat("bc", 32))
	locks := []*StateLock{
		{State: s, Type: pldapi.StateLockTypeCreate.Enum(), ConfirmedAtBlock: nil},
	}

	g.ImportStatesAndLocks(ctx, nil, locks)

	data, err := g.ExportStatesAndLocks(ctx, "test-node")
	require.NoError(t, err)
	assert.Empty(t, data.LockedState)
}

func TestImportStatesAndLocks_DoesNotOverwriteExistingLock(t *testing.T) {
	ctx := t.Context()
	g := testGrapher(t)
	s := pldtypes.MustParseHexBytes("0x" + strings.Repeat("de", 32))
	first := uint64(20)
	second := uint64(10)

	g.ImportStatesAndLocks(ctx, nil, []*StateLock{{State: s, Type: pldapi.StateLockTypeCreate.Enum(), ConfirmedAtBlock: &first}})
	// A second import for the same state must not overwrite the first.
	g.ImportStatesAndLocks(ctx, nil, []*StateLock{{State: s, Type: pldapi.StateLockTypeCreate.Enum(), ConfirmedAtBlock: &second}})

	data, err := g.ExportStatesAndLocks(ctx, "test-node")
	require.NoError(t, err)
	require.Len(t, data.LockedState, 1)
	assert.Equal(t, uint64(20), *data.LockedState[0].ConfirmedAtBlock)
}

func TestImportStatesAndLocks_ExpiredAfterImport(t *testing.T) {
	ctx := t.Context()
	g := testGrapher(t) // tolerance = 5
	s := pldtypes.MustParseHexBytes("0x" + strings.Repeat("ef", 32))
	confirmedAt := uint64(10)
	g.ImportStatesAndLocks(ctx, nil, []*StateLock{{State: s, Type: pldapi.StateLockTypeRead.Enum(), ConfirmedAtBlock: &confirmedAt}})

	g.ForgetLocks(ctx, 15) // 10 + 5 = 15, should expire
	data, err := g.ExportStatesAndLocks(ctx, "test-node")
	require.NoError(t, err)
	assert.Empty(t, data.LockedState)
}

func TestImportStatesAndLocks_SkipsInFlightLocks(t *testing.T) {
	ctx := t.Context()
	g := testGrapherUnlocked(t)
	txID := uuid.New()
	s := pldtypes.MustParseHexBytes("0x" + strings.Repeat("a5", 32))
	schema := pldtypes.MustParseBytes32("0x" + strings.Repeat("b5", 32))

	locks := []*StateLock{
		{State: s, Type: pldapi.StateLockTypeCreate.Enum(), Transaction: &txID},
	}
	outputStates := []*OutputState{
		{
			StateUpsert:  components.StateUpsert{ID: s, Schema: schema, Data: pldtypes.RawJSON(`{"v":1}`)},
			AllowedNodes: []string{"node1"},
		},
	}

	g.ImportStatesAndLocks(ctx, outputStates, locks)

	// In-flight lock must not be imported — the new coordinator has no state machine for it
	assert.Empty(t, g.createLocksByStateID)
	assert.Empty(t, g.spendLocksByStateID)
	assert.Empty(t, g.readLocksByStateID)

	// Output state must also be skipped — no confirmed lock to anchor it
	assert.Empty(t, g.outputStatesByStateID)

	// Transaction-indexed maps must be untouched
	assert.Empty(t, g.transactionByID)
	assert.Empty(t, g.outputStatesByMinter)
	assert.Empty(t, g.transactionByOutputState)
}

func TestImportStatesAndLocks_ImportsConfirmedOutputStates(t *testing.T) {
	ctx := t.Context()
	g := testGrapherUnlocked(t)
	s := pldtypes.MustParseHexBytes("0x" + strings.Repeat("a6", 32))
	confirmedAt := uint64(50)

	// Confirmed lock — no transaction
	locks := []*StateLock{
		{State: s, Type: pldapi.StateLockTypeCreate.Enum(), ConfirmedAtBlock: &confirmedAt},
	}
	outputStates := []*OutputState{
		{
			StateUpsert:  components.StateUpsert{ID: s},
			AllowedNodes: []string{"node1"},
		},
	}

	g.ImportStatesAndLocks(ctx, outputStates, locks)

	// Private state data in outputStatesByStateID
	assert.Contains(t, g.outputStatesByStateID, s.String())

	// In-flight indexes NOT populated (no txID known)
	assert.Empty(t, g.outputStatesByMinter)
	assert.Empty(t, g.transactionByOutputState)
}

func TestImportStatesAndLocks_SkipsOutputStateWithNoMatchingLock(t *testing.T) {
	ctx := t.Context()
	g := testGrapherUnlocked(t)
	s := pldtypes.MustParseHexBytes("0x" + strings.Repeat("c5", 32))

	outputStates := []*OutputState{
		{StateUpsert: components.StateUpsert{ID: s}},
	}
	// No lock provided for this state
	g.ImportStatesAndLocks(ctx, outputStates, nil)

	assert.Empty(t, g.outputStatesByStateID)
	assert.Empty(t, g.outputStatesByMinter)
	assert.Empty(t, g.transactionByOutputState)
}

func TestExportStatesAndLocks_OutputStateFiltering(t *testing.T) {
	ctx := t.Context()
	g := testGrapher(t)
	minterID := uuid.New()
	s1 := pldtypes.MustParseHexBytes("0x" + strings.Repeat("a1", 32))
	s2 := pldtypes.MustParseHexBytes("0x" + strings.Repeat("a2", 32))
	s3 := pldtypes.MustParseHexBytes("0x" + strings.Repeat("a3", 32))

	// s1: AllowedNodes=["node1"] — only node1 should see this OutputState
	require.NoError(t, g.AddMinter(ctx, []*components.FullState{
		{ID: s1, Schema: pldtypes.MustParseBytes32("0x" + strings.Repeat("b1", 32)), Data: pldtypes.RawJSON(`{}`)},
	}, minterID, map[string][]string{s1.String(): {"node1"}}))

	// s2: AllowedNodes=["node2"] — only node2 should see this OutputState
	minterID2 := uuid.New()
	require.NoError(t, g.AddMinter(ctx, []*components.FullState{
		{ID: s2, Schema: pldtypes.MustParseBytes32("0x" + strings.Repeat("b2", 32)), Data: pldtypes.RawJSON(`{}`)},
	}, minterID2, map[string][]string{s2.String(): {"node2"}}))

	// s3: nil AllowedNodes — excluded from all exports (distribution unknown)
	minterID3 := uuid.New()
	require.NoError(t, g.AddMinter(ctx, []*components.FullState{
		{ID: s3, Schema: pldtypes.MustParseBytes32("0x" + strings.Repeat("b3", 32)), Data: pldtypes.RawJSON(`{}`)},
	}, minterID3, nil))

	// node1: sees only s1 (AllowedNodes=["node1"]); s2 excluded (wrong node), s3 excluded (nil AllowedNodes)
	forNode1, err := g.ExportStatesAndLocks(ctx, "node1")
	require.NoError(t, err)
	node1StateIDs := make(map[string]bool)
	for _, s := range forNode1.OutputState {
		node1StateIDs[s.ID.String()] = true
	}
	assert.True(t, node1StateIDs[s1.String()], "node1 should see s1")
	assert.False(t, node1StateIDs[s2.String()], "node1 should not see s2 (different AllowedNodes)")
	assert.False(t, node1StateIDs[s3.String()], "node1 should not see s3 (nil AllowedNodes = excluded)")

	// node2: sees only s2 (AllowedNodes=["node2"]); s1 excluded (wrong node), s3 excluded (nil AllowedNodes)
	forNode2, err := g.ExportStatesAndLocks(ctx, "node2")
	require.NoError(t, err)
	node2StateIDs := make(map[string]bool)
	for _, s := range forNode2.OutputState {
		node2StateIDs[s.ID.String()] = true
	}
	assert.False(t, node2StateIDs[s1.String()], "node2 should not see s1")
	assert.True(t, node2StateIDs[s2.String()], "node2 should see s2")
	assert.False(t, node2StateIDs[s3.String()], "node2 should not see s3 (nil AllowedNodes = excluded)")

	// All locks are returned unfiltered for both nodes
	assert.Empty(t, forNode1.LockedState, "no locks created in this test")
	assert.Empty(t, forNode2.LockedState, "no locks created in this test")
}

func TestExportStatesAndLocks_LocksReturnedUnfiltered(t *testing.T) {
	ctx := t.Context()
	g := testGrapher(t)
	txID1 := uuid.New()
	txID2 := uuid.New()
	s1 := pldtypes.MustParseHexBytes("0x" + strings.Repeat("d1", 32))
	s2 := pldtypes.MustParseHexBytes("0x" + strings.Repeat("d2", 32))

	// Two transactions create locks on different states
	g.LockMintsOnReadAndSpend(ctx, []*components.FullState{{ID: s1}}, []*components.FullState{}, txID1)
	g.LockMintsOnReadAndSpend(ctx, []*components.FullState{}, []*components.FullState{{ID: s2}}, txID2)

	// Both nodes should see all locks regardless of any AllowedNodes on states
	forNode1, err := g.ExportStatesAndLocks(ctx, "node1")
	require.NoError(t, err)
	assert.Len(t, forNode1.LockedState, 2, "all locks returned to node1")

	forNode2, err := g.ExportStatesAndLocks(ctx, "node2")
	require.NoError(t, err)
	assert.Len(t, forNode2.LockedState, 2, "all locks returned to node2")
}

func TestImportStatesAndLocks_ExistingOutputStatePreserved(t *testing.T) {
	ctx := t.Context()
	txID := uuid.New()
	stateID := pldtypes.MustParseHexBytes("0x" + strings.Repeat("ae", 32))

	g := testGrapherUnlocked(t)

	// Seed an existing output state via AddMinter so it is already in outputStatesByStateID.
	err := g.AddMinter(ctx, []*components.FullState{{ID: stateID}}, txID, map[string][]string{stateID.String(): {"node1"}})
	require.NoError(t, err)

	originalState := g.outputStatesByStateID[stateID.String()]
	require.NotNil(t, originalState)

	// Build an import with a confirmed lock for the same state ID but different AllowedNodes.
	blockNum := uint64(10)
	importState := &OutputState{
		StateUpsert:  components.StateUpsert{ID: stateID},
		AllowedNodes: []string{"node2"},
	}
	lock := &StateLock{
		State:            stateID,
		Type:             pldapi.StateLockTypeSpend.Enum(),
		ConfirmedAtBlock: &blockNum,
	}

	// ImportStatesAndLocks should skip the state because an existing entry already exists.
	g.ImportStatesAndLocks(ctx, []*OutputState{importState}, []*StateLock{lock})

	// The original output state must not have been overwritten.
	after := g.outputStatesByStateID[stateID.String()]
	assert.Equal(t, originalState, after, "existing output state should take precedence over imported one")
	assert.Equal(t, []string{"node1"}, after.AllowedNodes, "AllowedNodes should remain from original entry")
}

func TestAddMinter_DuplicateStateIDWithinOneCall_ReturnsError(t *testing.T) {
	ctx := t.Context()
	txID := uuid.New()
	stateID := pldtypes.MustParseHexBytes("0x" + strings.Repeat("bf", 32))

	g := testGrapher(t)

	// Pass the same state ID twice in a single AddMinter call. The first iteration registers the
	// state under transactionByOutputState; the second finds it already present and returns an error.
	err := g.AddMinter(ctx, []*components.FullState{
		{ID: stateID},
		{ID: stateID},
	}, txID, map[string][]string{})

	require.Error(t, err)
	assert.ErrorContains(t, err, string(msgs.MsgSequencerGrapherAddMinterAlreadyExistsError))
}

// TestCreateLockSurvivesSpendLockRevert verifies that an optimistic spend of a create-locked state
// followed by rollback of the spend does not affect the create lock. A minter holds a create lock
// on a state; a consumer optimistically spends it, adding a spend lock; if the consumer reverts
// only the spend lock is removed — the minter's create lock must remain intact and exported.
func TestCreateLockSurvivesSpendLockRevert(t *testing.T) {
	ctx := t.Context()
	g := testGrapherUnlocked(t)

	minterTx := uuid.New()
	consumerTx := uuid.New()
	createdBy := uuid.New()
	stateID := pldtypes.MustParseHexBytes("0x" + strings.Repeat("ca", 32))
	state := &components.FullState{ID: stateID, Schema: pldtypes.MustParseBytes32("0x" + strings.Repeat("cb", 32)), Data: pldtypes.RawJSON(`{}`)}

	// Step 1: minterTx assembles and produces stateID with a create lock.
	require.NoError(t, g.AddMinter(ctx, []*components.FullState{state}, minterTx, nil))
	g.LockMintsOnCreate(ctx,
		[]*components.StateUpsert{{ID: stateID, CreatedBy: &createdBy}},
		[]*components.FullState{{ID: stateID}},
		minterTx,
	)

	require.Contains(t, g.createLocksByStateID, stateID.String(), "create lock must be recorded for minterTx")
	assert.Empty(t, g.spendLocksByStateID, "no spend lock yet")

	// Step 2: consumerTx optimistically spends stateID — this must NOT displace the create lock.
	g.LockMintsOnReadAndSpend(ctx, []*components.FullState{}, []*components.FullState{state}, consumerTx)

	require.Contains(t, g.createLocksByStateID, stateID.String(), "create lock must still exist after spend lock added")
	require.Contains(t, g.spendLocksByStateID, stateID.String(), "spend lock must be recorded for consumerTx")

	// Step 3: consumerTx reverts — its spend lock is deleted.
	g.ForgetTransactionAndLocks(ctx, consumerTx)

	assert.NotContains(t, g.spendLocksByStateID, stateID.String(), "spend lock must be removed after revert")

	// Step 4: the create lock from minterTx must survive.
	require.Contains(t, g.createLocksByStateID, stateID.String(), "create lock must survive the consumer revert")
	createLock := g.createLocksByStateID[stateID.String()]
	require.NotNil(t, createLock.Transaction)
	assert.Equal(t, minterTx, *createLock.Transaction)
	assert.Equal(t, pldapi.StateLockTypeCreate.Enum(), createLock.Type)

	// Step 5: ExportStatesAndLocks must still include the create lock so that a reassembled
	// transaction on the assembler node can find stateID via ImportSnapshot → creatingStates.
	data, err := g.ExportStatesAndLocks(ctx, "test-node")
	require.NoError(t, err)
	require.Len(t, data.LockedState, 1, "exactly the create lock must be exported")
	assert.Equal(t, pldapi.StateLockTypeCreate.Enum(), data.LockedState[0].Type)
	require.NotNil(t, data.LockedState[0].Transaction)
	assert.Equal(t, minterTx, *data.LockedState[0].Transaction)
}

// TestReadLockSurvivesSpendLockRevert verifies that an optimistic spend of a read-locked state
// followed by rollback of the spend does not affect the read lock. A reader holds a read lock on
// a state; an independent spender optimistically spends it, adding a spend lock; if the spender
// reverts only the spend lock is removed — the reader's read lock must remain intact and exported.
func TestReadLockSurvivesSpendLockRevert(t *testing.T) {
	ctx := t.Context()
	g := testGrapherUnlocked(t)

	readerTx := uuid.New()
	spenderTx := uuid.New()
	stateID := pldtypes.MustParseHexBytes("0x" + strings.Repeat("cc", 32))
	state := &components.FullState{ID: stateID}

	// txB reads stateID → read lock in readLocksByStateID.
	g.LockMintsOnReadAndSpend(ctx, []*components.FullState{state}, []*components.FullState{}, readerTx)
	require.Contains(t, g.readLocksByStateID, stateID.String(), "read lock must be recorded for readerTx")
	assert.Empty(t, g.spendLocksByStateID, "no spend lock yet")

	// txC spends stateID → spend lock in spendLocksByStateID, must NOT displace the read lock.
	g.LockMintsOnReadAndSpend(ctx, []*components.FullState{}, []*components.FullState{state}, spenderTx)
	require.Contains(t, g.readLocksByStateID, stateID.String(), "read lock must still exist after spend lock added")
	require.Contains(t, g.spendLocksByStateID, stateID.String(), "spend lock must be recorded for spenderTx")

	// txC reverts — only the spend lock is deleted.
	g.ForgetTransactionAndLocks(ctx, spenderTx)
	assert.NotContains(t, g.spendLocksByStateID, stateID.String(), "spend lock must be removed after revert")

	// txB's read lock must survive.
	require.Contains(t, g.readLocksByStateID, stateID.String(), "read lock must survive the spender revert")
	readLock := g.readLocksByStateID[stateID.String()]
	require.NotNil(t, readLock.Transaction)
	assert.Equal(t, readerTx, *readLock.Transaction)
	assert.Equal(t, pldapi.StateLockTypeRead.Enum(), readLock.Type)

	// Export must include the read lock so the assembler knows stateID is still in use.
	data, err := g.ExportStatesAndLocks(ctx, "test-node")
	require.NoError(t, err)
	require.Len(t, data.LockedState, 1, "exactly the read lock must be exported")
	assert.Equal(t, pldapi.StateLockTypeRead.Enum(), data.LockedState[0].Type)
	require.NotNil(t, data.LockedState[0].Transaction)
	assert.Equal(t, readerTx, *data.LockedState[0].Transaction)
}
