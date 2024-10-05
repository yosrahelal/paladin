// Copyright © 2024 Kaleido, Inc.
//
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package statemgr

import (
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/hyperledger/firefly-signer/pkg/abi"
	"github.com/hyperledger/firefly-signer/pkg/ethtypes"
	"github.com/kaleido-io/paladin/core/internal/components"
	"github.com/kaleido-io/paladin/toolkit/pkg/tktypes"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const fakeCoinABI = `{
	"type": "tuple",
	"internalType": "struct FakeCoin",
	"components": [
		{
			"name": "salt",
			"type": "bytes32"
		},
		{
			"name": "owner",
			"type": "address",
			"indexed": true
		},
		{
			"name": "amount",
			"type": "uint256",
			"indexed": true
		}
	]
}`

const fakeCoinABI2 = `{
	"type": "tuple",
	"internalType": "struct FakeCoin2",
	"components": [
		{
			"name": "salt",
			"type": "bytes32"
		},
		{
			"name": "owner",
			"type": "address",
			"indexed": true
		},
		{
			"name": "tokenUri",
			"type": "bytes32",
			"indexed": true
		}
	]
}`

type FakeCoin struct {
	Amount ethtypes.HexInteger       `json:"amount"`
	Salt   ethtypes.HexBytes0xPrefix `json:"salt"`
}

func parseFakeCoin(t *testing.T, s *components.State) *FakeCoin {
	var c FakeCoin
	err := json.Unmarshal(s.Data, &c)
	require.NoError(t, err)
	return &c
}

func TestStateFlushAsyncNoWork(t *testing.T) {

	ctx, ss, _, done := newDBMockStateManager(t)
	defer done()

	contractAddress := tktypes.RandAddress()
	flushed := make(chan error)

	dc := ss.NewDomainContext(ctx, "domain1", *contractAddress)
	defer dc.Close(ctx)

	err := dc.InitiateFlush(ctx, func(err error) { flushed <- err })
	require.NoError(t, err)

	require.Eventually(t, func() bool {
		select {
		case err := <-flushed:
			require.NoError(t, err)
			return true
		default:
			return false
		}
	}, 1*time.Second, 10*time.Millisecond)

}

func TestUpsertSchemaEmptyList(t *testing.T) {

	ctx, ss, _, done := newDBMockStateManager(t)
	defer done()

	schemas, err := ss.EnsureABISchemas(ctx, ss.p.DB(), "domain1", []*abi.Parameter{})
	require.NoError(t, err)
	require.Len(t, schemas, 0)

}

func TestUpsertSchemaAndStates(t *testing.T) {

	ctx, ss, done := newDBTestStateManager(t)
	defer done()

	schemas, err := ss.EnsureABISchemas(ctx, ss.p.DB(), "domain1", []*abi.Parameter{testABIParam(t, fakeCoinABI)})
	require.NoError(t, err)
	require.Len(t, schemas, 1)
	schemaID := schemas[0].ID()
	fakeHash := tktypes.HexBytes(tktypes.RandBytes(32))

	contractAddress := tktypes.RandAddress()
	dc := ss.NewDomainContext(ctx, "domain1", *contractAddress)
	defer dc.Close(ctx)

	states, err := dc.UpsertStates(ctx,
		&components.StateUpsert{
			SchemaID: schemaID,
			Data:     tktypes.RawJSON(fmt.Sprintf(`{"amount": 100, "owner": "0x1eDfD974fE6828dE81a1a762df680111870B7cDD", "salt": "%s"}`, tktypes.RandHex(32))),
		},
		&components.StateUpsert{
			ID:       fakeHash,
			SchemaID: schemaID,
			Data:     tktypes.RawJSON(fmt.Sprintf(`{"amount": 100, "owner": "0x1eDfD974fE6828dE81a1a762df680111870B7cDD", "salt": "%s"}`, tktypes.RandHex(32))),
		},
	)
	require.NoError(t, err)
	require.Len(t, states, 2)
	assert.NotEmpty(t, states[0].ID)
	assert.Equal(t, fakeHash, states[1].ID)

}

func TestStateContextMintSpendMint(t *testing.T) {

	ctx, ss, done := newDBTestStateManager(t)
	defer done()

	transactionID := uuid.New()
	var schemaID tktypes.Bytes32

	// Pop in our widget ABI
	schemas, err := ss.EnsureABISchemas(ctx, ss.p.DB(), "domain1", []*abi.Parameter{testABIParam(t, fakeCoinABI)})
	require.NoError(t, err)
	assert.Len(t, schemas, 1)
	schemaID = schemas[0].ID()

	contractAddress := tktypes.RandAddress()
	dc := ss.NewDomainContext(ctx, "domain1", *contractAddress)
	defer dc.Close(ctx)

	// Store some states
	tx1states, err := dc.UpsertStates(ctx,
		&components.StateUpsert{SchemaID: schemaID, Data: tktypes.RawJSON(fmt.Sprintf(`{"amount": 100, "owner": "0xf7b1c69F5690993F2C8ecE56cc89D42b1e737180", "salt": "%s"}`, tktypes.RandHex(32))), CreatedBy: &transactionID},
		&components.StateUpsert{SchemaID: schemaID, Data: tktypes.RawJSON(fmt.Sprintf(`{"amount": 10,  "owner": "0xf7b1c69F5690993F2C8ecE56cc89D42b1e737180", "salt": "%s"}`, tktypes.RandHex(32))), CreatedBy: &transactionID},
		&components.StateUpsert{SchemaID: schemaID, Data: tktypes.RawJSON(fmt.Sprintf(`{"amount": 75,  "owner": "0xf7b1c69F5690993F2C8ecE56cc89D42b1e737180", "salt": "%s"}`, tktypes.RandHex(32))), CreatedBy: &transactionID},
	)
	require.NoError(t, err)
	assert.Len(t, tx1states, 3)

	// Mark an in-memory read - doesn't affect it's availability
	transactionID2 := uuid.New()
	err = dc.AddStateLocks(ctx,
		&components.StateLock{Type: components.StateLockTypeRead.Enum(), State: tx1states[1].ID, Transaction: transactionID2},
	)
	require.NoError(t, err)

	// Query the states, and notice we find the ones that are still in the process of creating
	// even though they've not yet been written to the DB
	_, states, err := dc.FindAvailableStates(ctx, schemaID, toQuery(t, `{
			"sort": [ "amount" ]
		}`))
	require.NoError(t, err)
	assert.Len(t, states, 3)

	// The values should be sorted according to the requested order
	assert.Equal(t, int64(10), parseFakeCoin(t, states[0]).Amount.Int64())
	assert.Equal(t, int64(75), parseFakeCoin(t, states[1]).Amount.Int64())
	assert.Equal(t, int64(100), parseFakeCoin(t, states[2]).Amount.Int64())
	require.Len(t, states[0].Locks, 2)
	assert.Equal(t, components.StateLockTypeCreate, states[0].Locks[0].Type.V()) // should be marked creating
	assert.Equal(t, transactionID, states[0].Locks[0].Transaction)               // for the transaction we specified
	assert.Equal(t, components.StateLockTypeRead, states[0].Locks[1].Type.V())   // should be marked read
	assert.Equal(t, transactionID2, states[0].Locks[1].Transaction)              // for the transaction we specified

	// // Simulate a transaction where we spend two states, and create 2 new ones
	// err = dc.MarkStatesSpending(transactionID, []string{
	// 	states[0].ID.String(), // 10 +
	// 	states[1].ID.String(), // 75
	// })
	// require.NoError(t, err)

	// // Do a quick check on upsert semantics with un-flushed updates, to make sure the unflushed list doesn't dup
	// tx2Salts := []string{tktypes.RandHex(32), tktypes.RandHex(32)}
	// for dup := 0; dup < 2; dup++ {
	// 	tx2states, err := dc.UpsertStates(ctx,
	// 		&components.StateUpsert{SchemaID: schemaID, Data: tktypes.RawJSON(fmt.Sprintf(`{"amount": 35, "owner": "0xf7b1c69F5690993F2C8ecE56cc89D42b1e737180", "salt": "%s"}`, tx2Salts[0])), CreatedBy: &transactionID},
	// 		&components.StateUpsert{SchemaID: schemaID, Data: tktypes.RawJSON(fmt.Sprintf(`{"amount": 50, "owner": "0x615dD09124271D8008225054d85Ffe720E7a447A", "salt": "%s"}`, tx2Salts[1])), CreatedBy: &transactionID},
	// 	)
	// 	require.NoError(t, err)
	// 	assert.Len(t, tx2states, 2)
	// 	assert.Equal(t, len(dc.(*domainContext).unFlushed.states), 5)
	// 	assert.Equal(t, len(dc.(*domainContext).txLocks), 5)
	// }

	// // Query the states on the first address
	// states, err = dc.FindAvailableStates(schemaID, toQuery(t, `{
	// 		"sort": [ "-amount" ],
	// 		"eq": [{"field": "owner", "value": "0xf7b1c69F5690993F2C8ecE56cc89D42b1e737180"}]
	// 	}`))
	// require.NoError(t, err)
	// assert.Len(t, states, 2)
	// assert.Equal(t, int64(100), parseFakeCoin(t, states[0]).Amount.Int64())
	// assert.Equal(t, int64(35), parseFakeCoin(t, states[1]).Amount.Int64())

	// // Query the states on the other address
	// states, err = dc.FindAvailableStates(schemaID, toQuery(t, `{
	// 				"sort": [ "-amount" ],
	// 				"eq": [{"field": "owner", "value": "0x615dD09124271D8008225054d85Ffe720E7a447A"}]
	// 			}`))
	// require.NoError(t, err)
	// assert.Len(t, states, 1)
	// assert.Equal(t, int64(50), parseFakeCoin(t, states[0]).Amount.Int64())

	// // Flush the states to the database
	// syncFlushContext(t, ctx, dc)

	// // Check the DB persisted state is what we expect
	// states, err = dc.FindAvailableStates(schemaID, toQuery(t, `{
	// 	"sort": [ "owner", "amount" ]
	// }`))
	// require.NoError(t, err)
	// assert.Len(t, states, 3)
	// assert.Equal(t, int64(50), parseFakeCoin(t, states[0]).Amount.Int64())
	// assert.Equal(t, int64(35), parseFakeCoin(t, states[1]).Amount.Int64())
	// assert.Equal(t, int64(100), parseFakeCoin(t, states[2]).Amount.Int64())
	// log.L(ctx).Infof("STATE(35): %s", states[1].ID)

	// // Mark a persisted one read - doesn't affect it's availability, but will be locked to that transaction
	// err = dc.MarkStatesRead(transactionID, []string{
	// 	states[1].ID.String(),
	// })
	// require.NoError(t, err)

	// // Write another transaction that splits a coin to two
	// err = dc.MarkStatesSpending(transactionID, []string{
	// 	states[0].ID.String(), // 50
	// })
	// require.NoError(t, err)
	// tx3states, err := dc.UpsertStates(&transactionID, []*components.StateUpsert{
	// 	{SchemaID: schemaID, Data: tktypes.RawJSON(fmt.Sprintf(`{"amount": 20, "owner": "0x615dD09124271D8008225054d85Ffe720E7a447A", "salt": "%s"}`, tktypes.RandHex(32))), Creating: true},
	// 	{SchemaID: schemaID, Data: tktypes.RawJSON(fmt.Sprintf(`{"amount": 30, "owner": "0x615dD09124271D8008225054d85Ffe720E7a447A", "salt": "%s"}`, tktypes.RandHex(32))), Creating: true},
	// })
	// require.NoError(t, err)
	// assert.Len(t, tx3states, 2)

	// // Now check that we merge the DB and in-memory state
	// states, err = dc.FindAvailableStates(schemaID, toQuery(t, `{
	// 	"sort": [ "owner", "amount" ]
	// }`))
	// require.NoError(t, err)
	// assert.Len(t, states, 4)
	// assert.Equal(t, int64(20), parseFakeCoin(t, states[0]).Amount.Int64())
	// assert.Equal(t, int64(30), parseFakeCoin(t, states[1]).Amount.Int64())
	// assert.Equal(t, int64(35), parseFakeCoin(t, states[2]).Amount.Int64())
	// assert.Equal(t, int64(100), parseFakeCoin(t, states[3]).Amount.Int64())

	// // Check the limit works too across this
	// states, err = dc.FindAvailableStates(schemaID, toQuery(t, `{
	// 	"limit": 1,
	// 	"sort": [ "owner", "amount" ]
	// }`))
	// require.NoError(t, err)
	// assert.Len(t, states, 1)
	// assert.Equal(t, int64(20), parseFakeCoin(t, states[0]).Amount.Int64())

	// stateToConfirmAndThenSpend = states[0]

	// syncFlushContext(t, ctx, dc)

	// // Mark a state confirmed, and the same state state spent - all in one DB TX
	// err = ss.WriteStateFinalizations(ss.bgCtx, ss.p.DB(),
	// 	[]*components.StateSpend{
	// 		{DomainName: "domain1", State: stateToConfirmAndThenSpend.ID, Transaction: transactionID},
	// 	}, []*components.StateConfirm{
	// 		{DomainName: "domain1", State: stateToConfirmAndThenSpend.ID, Transaction: transactionID},
	// 	})
	// require.NoError(t, err)

	// // Check the remaining states
	// states, err = dc.FindAvailableStates(schemaID, toQuery(t, `{
	// 	"sort": [ "owner", "amount" ]
	// }`))
	// require.NoError(t, err)
	// assert.Len(t, states, 3)
	// assert.Equal(t, int64(30), parseFakeCoin(t, states[0]).Amount.Int64())
	// assert.Equal(t, int64(35), parseFakeCoin(t, states[1]).Amount.Int64())
	// assert.Equal(t, int64(100), parseFakeCoin(t, states[2]).Amount.Int64())

	// // Reset the transaction - this will clear the in-memory state,
	// // and remove the locks from the DB. It will not remove the states
	// // themselves
	// err = dc.ResetTransaction(transactionID)
	// require.NoError(t, err)

	// // None of the states will be returned to available after the flush
	// // - but before then the DB ones will be
	// syncFlushContext(t, ctx, dc)

	// // Confirm
	// states, err = dc.FindAvailableStates(schemaID, toQuery(t, `{}`))
	// require.NoError(t, err)
	// assert.Empty(t, states)

	// syncFlushContext(t, ctx, dc)

}

// func TestStateContextMintSpendWithNullifier(t *testing.T) {

// 	_, ss, done := newDBTestStateManager(t)
// 	defer done()

// 	transactionID := uuid.New()

// 	schemas, err := ss.EnsureABISchemas(ctx, "domain1", []*abi.Parameter{testABIParam(t, fakeCoinABI)})
// 	require.NoError(t, err)
// 	assert.Len(t, schemas, 1)
// 	schemaID := schemas[0].ID)
// 	stateID1 := tktypes.HexBytes(tktypes.RandBytes(32))
// 	stateID2 := tktypes.HexBytes(tktypes.RandBytes(32))
// 	nullifier1 := tktypes.HexBytes(tktypes.RandBytes(32))
// 	nullifier2 := tktypes.HexBytes(tktypes.RandBytes(32))
// 	data1 := tktypes.RawJSON(fmt.Sprintf(`{"amount": 100, "owner": "0xf7b1c69F5690993F2C8ecE56cc89D42b1e737180", "salt": "%s"}`, tktypes.RandHex(32)))
// 	data2 := tktypes.RawJSON(fmt.Sprintf(`{"amount": 10,  "owner": "0xf7b1c69F5690993F2C8ecE56cc89D42b1e737180", "salt": "%s"}`, tktypes.RandHex(32)))

// 	contractAddress := tktypes.RandAddress()
// 	err = ss.RunInDomainContextFlush("domain1", *contractAddress, func(ctx context.Context, dsi components.DomainContext) error {

// 		// Start with 2 states
// 		tx1states, err := dc.UpsertStates(&transactionID, []*components.StateUpsert{
// 			{ID: stateID1, SchemaID: schemaID, Data: data1, Creating: true},
// 			{ID: stateID2, SchemaID: schemaID, Data: data2, Creating: true},
// 		})
// 		require.NoError(t, err)
// 		assert.Len(t, tx1states, 2)

// 		states, err := dc.FindAvailableStates(schemaID, toQuery(t, `{}`))
// 		require.NoError(t, err)
// 		assert.Len(t, states, 2)
// 		states, err = dc.FindAvailableNullifiers(schemaID, toQuery(t, `{}`))
// 		require.NoError(t, err)
// 		assert.Len(t, states, 0)

// 		// Attach a nullifier to the first state
// 		err = dc.UpsertNullifiers([]*components.StateNullifier{
// 			{State: stateID1, Nullifier: nullifier1},
// 		})
// 		require.NoError(t, err)

// 		states, err = dc.FindAvailableNullifiers(schemaID, toQuery(t, `{}`))
// 		require.NoError(t, err)
// 		require.Len(t, states, 1)
// 		require.NotNil(t, states[0].Nullifier)
// 		assert.Equal(t, nullifier1, states[0].Nullifier.Nullifier)

// 		// Flush the states to the database
// 		return nil
// 	})
// 	require.NoError(t, err)

// 	err = ss.RunInDomainContextFlush("domain1", *contractAddress, func(ctx context.Context, dsi components.DomainContext) error {

// 		// Confirm still 2 states and 1 nullifier
// 		states, err := dc.FindAvailableStates(schemaID, toQuery(t, `{}`))
// 		require.NoError(t, err)
// 		assert.Len(t, states, 2)
// 		states, err = dc.FindAvailableNullifiers(schemaID, toQuery(t, `{}`))
// 		require.NoError(t, err)
// 		assert.Len(t, states, 1)
// 		require.NotNil(t, states[0].Nullifier)
// 		assert.Equal(t, nullifier1, states[0].Nullifier.Nullifier)
// 		return nil
// 	})
// 	require.NoError(t, err)

// 	// Mark both states confirmed
// 	err = ss.WriteStateFinalizations(ss.bgCtx, ss.p.DB(), []*components.StateSpend{},
// 		[]*components.StateConfirm{
// 			{DomainName: "domain1", State: stateID1, Transaction: transactionID},
// 			{DomainName: "domain1", State: stateID2, Transaction: transactionID},
// 		})

// 	err = ss.RunInDomainContextFlush("domain1", *contractAddress, func(ctx context.Context, dsi components.DomainStateInterface) error {
// 		// Mark the first state as "spending"
// 		_, err = dc.UpsertStates(&transactionID, []*components.StateUpsert{
// 			{ID: stateID1, SchemaID: schemaID, Data: data1, Spending: true},
// 		})
// 		assert.NoError(t, err)

// 		// Confirm no more nullifiers available
// 		states, err := dc.FindAvailableNullifiers(schemaID, toQuery(t, `{}`))
// 		require.NoError(t, err)
// 		assert.Len(t, states, 0)

// 		// Reset transaction to unlock
// 		err = dc.ResetTransaction(transactionID)
// 		assert.NoError(t, err)
// 		states, err = dc.FindAvailableNullifiers(schemaID, toQuery(t, `{}`))
// 		require.NoError(t, err)
// 		assert.Len(t, states, 1)

// 		return nil
// 	})

// 	// Spend the nullifier
// 	err = ss.WriteStateFinalizations(ss.bgCtx, ss.p.DB(),
// 		[]*components.StateSpend{
// 			{DomainName: "domain1", State: nullifier1, Transaction: transactionID},
// 		}, []*components.StateConfirm{})
// 	require.NoError(t, err)

// 	err = ss.RunInDomainContextFlush("domain1", *contractAddress, func(ctx context.Context, dsi components.DomainStateInterface) error {
// 		// Confirm no more nullifiers available
// 		states, err := dc.FindAvailableNullifiers(schemaID, toQuery(t, `{}`))
// 		require.NoError(t, err)
// 		assert.Len(t, states, 0)

// 		// Flush the states to the database
// 		return nil
// 	})
// 	require.NoError(t, err)

// 	err = ss.RunInDomainContextFlush("domain1", *contractAddress, func(ctx context.Context, dsi components.DomainContext) error {

// 		states, err := dc.FindAvailableNullifiers(schemaID, toQuery(t, `{}`))
// 		require.NoError(t, err)
// 		assert.Len(t, states, 0)

// 		// Attach a nullifier to the second state
// 		err = dc.UpsertNullifiers([]*components.StateNullifier{
// 			{State: stateID2, Nullifier: nullifier2},
// 		})
// 		require.NoError(t, err)

// 		states, err = dc.FindAvailableNullifiers(schemaID, toQuery(t, `{}`))
// 		require.NoError(t, err)
// 		require.Len(t, states, 1)
// 		require.NotNil(t, states[0].Nullifier)
// 		assert.Equal(t, nullifier2, states[0].Nullifier.Nullifier)

// 		return nil
// 	})
// 	require.NoError(t, err)

// }

// func TestDSILatch(t *testing.T) {

// 	_, ss, done := newDBTestStateManager(t)

// 	contractAddress := tktypes.RandAddress()
// 	dsi := ss.getDomainContext("domain1", *contractAddress)
// 	err := dc.takeLatch()
// 	require.NoError(t, err)

// 	done()
// 	err = dc.run(func(ctx context.Context, dsi components.DomainContext) error { return nil })
// 	assert.Regexp(t, "PD010301", err)

// }

// func TestDSIBadSchema(t *testing.T) {

// 	_, ss, _, done := newDBMockStateManager(t)
// 	defer done()

// 	_, err := ss.EnsureABISchemas(ctx, "domain1", []*abi.Parameter{{}})
// 	assert.Regexp(t, "PD010114", err)

// }

// func TestDSIFlushErrorCapture(t *testing.T) {

// 	_, ss, done := newDBTestStateManager(t)
// 	defer done()

// 	fakeFlushError := func(dc *domainContext) {
// 		dc.flushing = &writeOperation{}
// 		dc.flushResult = make(chan error, 1)
// 		dc.flushResult <- fmt.Errorf("pop")
// 	}

// 	schemas, err := ss.EnsureABISchemas(ctx, "domain1", []*abi.Parameter{testABIParam(t, fakeCoinABI)})
// 	require.NoError(t, err)

// 	contractAddress := tktypes.RandAddress()
// 	err = ss.RunInDomainContextFlush("domain1", *contractAddress, func(ctx context.Context, dsi components.DomainContext) error {

// 		dc := dc.(*domainContext)

// 		fakeFlushError(dc)
// 		_, err = dc.FindAvailableStates("", nil)
// 		assert.Regexp(t, "pop", err)

// 		fakeFlushError(dc)
// 		_, err = dc.FindAvailableNullifiers("", nil)
// 		assert.Regexp(t, "pop", err)

// 		fakeFlushError(dc)
// 		schema, err := ss.getSchemaByID(ctx, "domain1", tktypes.MustParseBytes32(schemas[0].ID()), true)
// 		require.NoError(t, err)
// 		_, err = dc.mergedUnFlushed(schema, nil, nil, false)
// 		assert.Regexp(t, "pop", err)

// 		fakeFlushError(dc)
// 		_, err = dc.UpsertStates(nil, nil)
// 		assert.Regexp(t, "pop", err)

// 		fakeFlushError(dc)
// 		err = dc.UpsertNullifiers(nil)
// 		assert.Regexp(t, "pop", err)

// 		fakeFlushError(dc)
// 		err = dc.MarkStatesRead(uuid.New(), nil)
// 		assert.Regexp(t, "pop", err)

// 		fakeFlushError(dc)
// 		err = dc.MarkStatesSpending(uuid.New(), nil)
// 		assert.Regexp(t, "pop", err)

// 		fakeFlushError(dc)
// 		err = dc.ResetTransaction(uuid.New())
// 		assert.Regexp(t, "pop", err)

// 		fakeFlushError(dc)
// 		err = dc.Flush()
// 		assert.Regexp(t, "pop", err)

// 		return nil

// 	})
// 	require.NoError(t, err)

// }

// func TestDSIMergedUnFlushedWhileFlushing(t *testing.T) {

// 	ctx, ss, _, done := newDBMockStateManager(t)
// 	defer done()

// 	schema, err := newABISchema(ctx, "domain1", testABIParam(t, fakeCoinABI))
// 	require.NoError(t, err)

// 	contractAddress := tktypes.RandAddress()
// 	dc := ss.getDomainContext("domain1", *contractAddress)

// 	s1, err := schema.ProcessState(ctx, *contractAddress, tktypes.RawJSON(fmt.Sprintf(
// 		`{"amount": 20, "owner": "0x615dD09124271D8008225054d85Ffe720E7a447A", "salt": "%s"}`,
// 		tktypes.RandHex(32))), nil)
// 	require.NoError(t, err)
// 	s1.Locked = &components.StateLock{State: s1.ID, Transaction: uuid.New(), Creating: true}

// 	dc.flushing = &writeOperation{
// 		states: []*components.StateWithLabels{s1},
// 		stateLocks: []*components.StateLock{
// 			s1.Locked,
// 			{State: []byte("another"), Spending: true},
// 		},
// 	}

// 	spending, _, _, err := dc.getUnFlushedStates()
// 	require.NoError(t, err)
// 	assert.Len(t, spending, 1)

// 	states, err := dc.mergedUnFlushed(schema, []*components.State{}, &query.QueryJSON{
// 		Sort: []string{".created"},
// 	}, false)
// 	require.NoError(t, err)
// 	assert.Len(t, states, 1)

// }

// func TestDSIMergedUnFlushedSpend(t *testing.T) {

// 	ctx, ss, _, done := newDBMockStateManager(t)
// 	defer done()

// 	schema1, err := newABISchema(ctx, "domain1", testABIParam(t, fakeCoinABI))
// 	require.NoError(t, err)

// 	schema2, err := newABISchema(ctx, "domain1", testABIParam(t, fakeCoinABI2))
// 	require.NoError(t, err)

// 	contractAddress := tktypes.RandAddress()
// 	dc := ss.getDomainContext("domain1", *contractAddress)

// 	s1, err := schema1.ProcessState(ctx, *contractAddress, tktypes.RawJSON(fmt.Sprintf(
// 		`{"amount": 20, "owner": "0x615dD09124271D8008225054d85Ffe720E7a447A", "salt": "%s"}`,
// 		tktypes.RandHex(32))), nil)
// 	require.NoError(t, err)
// 	s1.Locked = &components.StateLock{State: s1.ID, Transaction: uuid.New(), Creating: true}

// 	s2, err := schema2.ProcessState(ctx, *contractAddress, tktypes.RawJSON(fmt.Sprintf(
// 		`{"tokenUri": "%s", "owner": "0x615dD09124271D8008225054d85Ffe720E7a447A", "salt": "%s"}`,
// 		tktypes.RandHex(32), tktypes.RandHex(32))), nil)
// 	require.NoError(t, err)
// 	s2.Locked = &components.StateLock{State: s2.ID, Transaction: uuid.New(), Creating: true}

// 	states, err := dc.mergedUnFlushed(schema1, []*components.State{}, &query.QueryJSON{}, false)
// 	require.NoError(t, err)
// 	assert.Len(t, states, 0)

// }

// func TestDSIMergedUnFlushedWhileFlushingDedup(t *testing.T) {

// 	ctx, ss, _, done := newDBMockStateManager(t)
// 	defer done()

// 	schema, err := newABISchema(ctx, "domain1", testABIParam(t, fakeCoinABI))
// 	require.NoError(t, err)

// 	contractAddress := tktypes.RandAddress()
// 	dc := ss.getDomainContext("domain1", *contractAddress)

// 	s1, err := schema.ProcessState(ctx, *contractAddress, tktypes.RawJSON(fmt.Sprintf(
// 		`{"amount": 20, "owner": "0x615dD09124271D8008225054d85Ffe720E7a447A", "salt": "%s"}`,
// 		tktypes.RandHex(32))), nil)
// 	require.NoError(t, err)
// 	s1.Locked = &components.StateLock{State: s1.ID, Transaction: uuid.New(), Creating: true}

// 	dc.flushing = &writeOperation{
// 		states: []*components.StateWithLabels{s1},
// 		stateLocks: []*components.StateLock{
// 			s1.Locked,
// 			{State: []byte("another"), Spending: true},
// 		},
// 	}

// 	spending, _, _, err := dc.getUnFlushedStates()
// 	require.NoError(t, err)
// 	assert.Len(t, spending, 1)

// 	dc.stateLock.Lock()
// 	inTheFlush := dc.flushing.states[0]
// 	dc.stateLock.Unlock()

// 	states, err := dc.mergedUnFlushed(schema, []*components.State{
// 		inTheFlush.State,
// 	}, &query.QueryJSON{
// 		Sort: []string{".created"},
// 	}, false)
// 	require.NoError(t, err)
// 	assert.Len(t, states, 1)

// }

// func TestDSIMergedUnFlushedEvalError(t *testing.T) {

// 	ctx, ss, _, done := newDBMockStateManager(t)
// 	defer done()

// 	schema, err := newABISchema(ctx, "domain1", testABIParam(t, fakeCoinABI))
// 	require.NoError(t, err)

// 	contractAddress := tktypes.RandAddress()
// 	dc := ss.getDomainContext("domain1", *contractAddress)

// 	s1, err := schema.ProcessState(ctx, *contractAddress, tktypes.RawJSON(fmt.Sprintf(
// 		`{"amount": 20, "owner": "0x615dD09124271D8008225054d85Ffe720E7a447A", "salt": "%s"}`,
// 		tktypes.RandHex(32))), nil)
// 	require.NoError(t, err)

// 	dc.flushing = &writeOperation{
// 		states: []*components.StateWithLabels{s1},
// 	}

// 	_, err = dc.mergedUnFlushed(schema, []*components.State{}, toQuery(t,
// 		`{"eq": [{ "field": "wrong", "value": "any" }]}`,
// 	), false)
// 	assert.Regexp(t, "PD010700", err)

// }

// func TestDSIMergedInMemoryMatchesRecoverLabelsFail(t *testing.T) {

// 	ctx, ss, _, done := newDBMockStateManager(t)
// 	defer done()

// 	schema, err := newABISchema(ctx, "domain1", testABIParam(t, fakeCoinABI))
// 	require.NoError(t, err)

// 	contractAddress := tktypes.RandAddress()
// 	dc := ss.getDomainContext("domain1", *contractAddress)

// 	s1, err := schema.ProcessState(ctx, *contractAddress, tktypes.RawJSON(fmt.Sprintf(
// 		`{"amount": 20, "owner": "0x615dD09124271D8008225054d85Ffe720E7a447A", "salt": "%s"}`,
// 		tktypes.RandHex(32))), nil)
// 	require.NoError(t, err)
// 	s1.Data = tktypes.RawJSON(`! wrong `)

// 	dc.flushing = &writeOperation{
// 		states: []*components.StateWithLabels{s1},
// 	}

// 	_, err = dc.mergeInMemoryMatches(schema, []*components.State{
// 		s1.State,
// 	}, []*components.StateWithLabels{}, nil)
// 	assert.Regexp(t, "PD010116", err)

// }

// func TestDSIMergedInMemoryMatchesSortFail(t *testing.T) {

// 	ctx, ss, _, done := newDBMockStateManager(t)
// 	defer done()

// 	schema, err := newABISchema(ctx, "domain1", testABIParam(t, fakeCoinABI))
// 	require.NoError(t, err)

// 	contractAddress := tktypes.RandAddress()
// 	dc := ss.getDomainContext("domain1", *contractAddress)

// 	s1, err := schema.ProcessState(ctx, *contractAddress, tktypes.RawJSON(fmt.Sprintf(
// 		`{"amount": 20, "owner": "0x615dD09124271D8008225054d85Ffe720E7a447A", "salt": "%s"}`,
// 		tktypes.RandHex(32))), nil)
// 	require.NoError(t, err)

// 	dc.flushing = &writeOperation{
// 		states: []*components.StateWithLabels{s1},
// 	}

// 	_, err = dc.mergeInMemoryMatches(schema, []*components.State{
// 		s1.State,
// 	}, []*components.StateWithLabels{}, toQuery(t,
// 		`{"sort": ["wrong"]}`,
// 	))
// 	assert.Regexp(t, "PD010700", err)
// }

// func TestDSIFindBadQueryAndInsert(t *testing.T) {

// 	_, ss, done := newDBTestStateManager(t)
// 	defer done()

// 	schemas, err := ss.EnsureABISchemas(ctx, "domain1", []*abi.Parameter{testABIParam(t, fakeCoinABI)})
// 	require.NoError(t, err)
// 	schemaID := schemas[0].ID()
// 	assert.Equal(t, "type=FakeCoin(bytes32 salt,address owner,uint256 amount),labels=[owner,amount]", schemas[0].Signature())

// 	contractAddress := tktypes.RandAddress()
// 	err = ss.RunInDomainContextFlush("domain1", *contractAddress, func(ctx context.Context, dsi components.DomainContext) error {
// 		_, err = dc.FindAvailableStates(schemaID, toQuery(t,
// 			`{"sort":["wrong"]}`))
// 		assert.Regexp(t, "PD010700", err)

// 		_, err = dc.FindAvailableNullifiers(schemaID, toQuery(t,
// 			`{"sort":["wrong"]}`))
// 		assert.Regexp(t, "PD010700", err)

// 		_, err = dc.UpsertStates(nil, []*components.StateUpsert{
// 			{SchemaID: schemaID, Data: tktypes.RawJSON(`"wrong"`)},
// 		})
// 		assert.Regexp(t, "FF22038", err)

// 		return nil
// 	})
// 	require.NoError(t, err)

// }

// func TestDSIBadIDs(t *testing.T) {

// 	_, ss, _, done := newDBMockStateManager(t)
// 	defer done()

// 	contractAddress := tktypes.RandAddress()
// 	_ = ss.RunInDomainContext("domain1", *contractAddress, func(ctx context.Context, dsi components.DomainContext) error {

// 		_, err := dc.UpsertStates(nil, []*components.StateUpsert{
// 			{SchemaID: "wrong"},
// 		})
// 		assert.Regexp(t, "PD020007", err)

// 		err = dc.MarkStatesRead(uuid.New(), []string{"wrong"})
// 		assert.Regexp(t, "PD020007", err)

// 		err = dc.MarkStatesSpending(uuid.New(), []string{"wrong"})
// 		assert.Regexp(t, "PD020007", err)

// 		return nil
// 	})

// }

// func TestDSIResetWithMixed(t *testing.T) {

// 	_, ss, _, done := newDBMockStateManager(t)
// 	defer done()

// 	contractAddress := tktypes.RandAddress()
// 	dc := ss.getDomainContext("domain1", *contractAddress)

// 	state1 := tktypes.HexBytes("state1")
// 	transactionID1 := uuid.New()
// 	err := dc.MarkStatesRead(transactionID1, []string{state1.String()})
// 	require.NoError(t, err)

// 	state2 := tktypes.HexBytes("state2")
// 	transactionID2 := uuid.New()
// 	err = dc.MarkStatesSpending(transactionID2, []string{state2.String()})
// 	require.NoError(t, err)

// 	err = dc.ResetTransaction(transactionID1)
// 	require.NoError(t, err)

// 	assert.Len(t, dc.unFlushed.stateLocks, 1)
// 	assert.Equal(t, dc.unFlushed.stateLocks[0].State, state2)

// }

// func TestCheckEvalGTTimestamp(t *testing.T) {
// 	ctx, ss, _, done := newDBMockStateManager(t)
// 	defer done()

// 	contractAddress := tktypes.RandAddress()
// 	dc := ss.getDomainContext("domain1", *contractAddress)

// 	filterJSON :=
// 		`{"gt":[{"field":".created","value":1726545933211347000}],"limit":10,"sort":[".created"]}`
// 	var jq query.QueryJSON
// 	err := json.Unmarshal([]byte(filterJSON), &jq)
// 	assert.NoError(t, err)

// 	schema, err := newABISchema(ctx, "domain1", testABIParam(t, fakeCoinABI))
// 	require.NoError(t, err)
// 	labelSet := dc.ss.labelSetFor(schema)

// 	s := &components.State{
// 		ID:      tktypes.MustParseHexBytes("2eaf4727b7c7e9b3728b1344ac38ea6d8698603dc3b41d9458d7c011c20ce672"),
// 		Created: tktypes.TimestampFromUnix(1726545933211347000),
// 	}
// 	ls := filters.PassthroughValueSet{}
// 	addStateBaseLabels(ls, s.ID, s.Created)
// 	labelSet.labels[".created"] = nil

// 	match, err := filters.EvalQuery(dc.ctx, &jq, labelSet, ls)
// 	assert.NoError(t, err)
// 	assert.False(t, match)

// }
