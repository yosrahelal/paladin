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

package coordinator

import (
	"context"
	"testing"

	"github.com/LFDT-Paladin/paladin/core/internal/sequencer/coordinator/transaction"
	"github.com/LFDT-Paladin/paladin/core/mocks/coordinatortransactionmocks"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
)

func TestGuard_FlushComplete_NoTransactions(t *testing.T) {
	ctx := context.Background()
	c, _ := NewCoordinatorBuilderForTesting(t, State_Idle).Build()
	result := guard_FlushComplete(ctx, c)
	assert.True(t, result, "no transactions should return true")
}

func TestGuard_FlushComplete_TransactionsInOtherStates(t *testing.T) {
	ctx := context.Background()
	tx1 := coordinatortransactionmocks.NewCoordinatorTransaction(t)
	tx1.EXPECT().GetID().Return(uuid.New())
	tx1.EXPECT().GetCurrentState().Return(transaction.State_Pooled)

	tx2 := coordinatortransactionmocks.NewCoordinatorTransaction(t)
	tx2.EXPECT().GetID().Return(uuid.New())
	tx2.EXPECT().GetCurrentState().Return(transaction.State_Assembling)

	tx3 := coordinatortransactionmocks.NewCoordinatorTransaction(t)
	tx3.EXPECT().GetID().Return(uuid.New())
	tx3.EXPECT().GetCurrentState().Return(transaction.State_Confirmed)

	c, _ := NewCoordinatorBuilderForTesting(t, State_Idle).Transactions(tx1, tx2, tx3).Build()
	result := guard_FlushComplete(ctx, c)
	assert.True(t, result, "transactions in other states should return true")
}

func TestGuard_FlushComplete_TransactionInReadyForDispatchState(t *testing.T) {
	ctx := context.Background()
	tx := coordinatortransactionmocks.NewCoordinatorTransaction(t)
	tx.EXPECT().GetID().Return(uuid.New())
	tx.EXPECT().GetCurrentState().Return(transaction.State_Ready_For_Dispatch)

	c, _ := NewCoordinatorBuilderForTesting(t, State_Idle).Transactions(tx).Build()
	result := guard_FlushComplete(ctx, c)
	assert.False(t, result, "transaction in Ready_For_Dispatch should return false")
}

func TestGuard_FlushComplete_TransactionInDispatchedState(t *testing.T) {
	ctx := context.Background()
	tx := coordinatortransactionmocks.NewCoordinatorTransaction(t)
	tx.EXPECT().GetID().Return(uuid.New())
	tx.EXPECT().GetCurrentState().Return(transaction.State_Dispatched)

	c, _ := NewCoordinatorBuilderForTesting(t, State_Idle).Transactions(tx).Build()
	result := guard_FlushComplete(ctx, c)
	assert.False(t, result, "transaction in Dispatched should return false")
}

func TestGuard_FlushComplete_TransactionInSubmittedState(t *testing.T) {
	ctx := context.Background()
	tx := coordinatortransactionmocks.NewCoordinatorTransaction(t)
	tx.EXPECT().GetID().Return(uuid.New())
	tx.EXPECT().GetCurrentState().Return(transaction.State_Dispatched)

	c, _ := NewCoordinatorBuilderForTesting(t, State_Idle).Transactions(tx).Build()
	result := guard_FlushComplete(ctx, c)
	assert.False(t, result, "transaction in Submitted should return false")
}

func TestGuard_FlushComplete_MultipleTransactionsInFlushStates(t *testing.T) {
	ctx := context.Background()
	tx1 := coordinatortransactionmocks.NewCoordinatorTransaction(t)
	tx1.EXPECT().GetID().Return(uuid.New())
	tx1.EXPECT().GetCurrentState().Return(transaction.State_Ready_For_Dispatch)

	tx2 := coordinatortransactionmocks.NewCoordinatorTransaction(t)
	tx2.EXPECT().GetID().Return(uuid.New())
	tx2.EXPECT().GetCurrentState().Return(transaction.State_Dispatched)

	tx3 := coordinatortransactionmocks.NewCoordinatorTransaction(t)
	tx3.EXPECT().GetID().Return(uuid.New())
	tx3.EXPECT().GetCurrentState().Return(transaction.State_Dispatched)

	c, _ := NewCoordinatorBuilderForTesting(t, State_Idle).Transactions(tx1, tx2, tx3).Build()
	result := guard_FlushComplete(ctx, c)
	assert.False(t, result, "transactions in flush states should return false")
}

func TestGuard_FlushComplete_MixOfFlushAndNonFlushStates(t *testing.T) {
	ctx := context.Background()
	tx1 := coordinatortransactionmocks.NewCoordinatorTransaction(t)
	tx1.EXPECT().GetID().Return(uuid.New())
	tx1.EXPECT().GetCurrentState().Return(transaction.State_Ready_For_Dispatch)

	tx2 := coordinatortransactionmocks.NewCoordinatorTransaction(t)
	tx2.EXPECT().GetID().Return(uuid.New())
	tx2.EXPECT().GetCurrentState().Return(transaction.State_Confirmed)

	c, _ := NewCoordinatorBuilderForTesting(t, State_Idle).Transactions(tx1, tx2).Build()
	result := guard_FlushComplete(ctx, c)
	assert.False(t, result, "mix with flush state should return false")
}

func TestGuard_HasTransactionsInflight_NoTransactions(t *testing.T) {
	ctx := context.Background()
	c, _ := NewCoordinatorBuilderForTesting(t, State_Idle).Build()
	result := guard_HasTransactionsInflight(ctx, c)
	assert.False(t, result, "no transactions should return false")
}

func TestGuard_HasTransactionsInflight_OnlyConfirmedTransactions(t *testing.T) {
	ctx := context.Background()
	tx1 := coordinatortransactionmocks.NewCoordinatorTransaction(t)
	tx1.EXPECT().GetID().Return(uuid.New())

	tx2 := coordinatortransactionmocks.NewCoordinatorTransaction(t)
	tx2.EXPECT().GetID().Return(uuid.New())

	c, _ := NewCoordinatorBuilderForTesting(t, State_Idle).Transactions(tx1, tx2).Build()
	result := guard_HasTransactionsInflight(ctx, c)
	assert.True(t, result, "only confirmed should return true")
}

func TestGuard_HasTransactionsInflight_TransactionInPooledState(t *testing.T) {
	ctx := context.Background()
	tx := coordinatortransactionmocks.NewCoordinatorTransaction(t)
	tx.EXPECT().GetID().Return(uuid.New())

	c, _ := NewCoordinatorBuilderForTesting(t, State_Idle).Transactions(tx).Build()
	result := guard_HasTransactionsInflight(ctx, c)
	assert.True(t, result, "transaction in Pooled should return true")
}

func TestGuard_HasTransactionsInflight_TransactionInAssemblingState(t *testing.T) {
	ctx := context.Background()
	tx := coordinatortransactionmocks.NewCoordinatorTransaction(t)
	tx.EXPECT().GetID().Return(uuid.New())

	c, _ := NewCoordinatorBuilderForTesting(t, State_Idle).Transactions(tx).Build()
	result := guard_HasTransactionsInflight(ctx, c)
	assert.True(t, result, "transaction in Assembling should return true")
}

func TestGuard_HasTransactionsInflight_TransactionInReadyForDispatchState(t *testing.T) {
	ctx := context.Background()
	tx := coordinatortransactionmocks.NewCoordinatorTransaction(t)
	tx.EXPECT().GetID().Return(uuid.New())

	c, _ := NewCoordinatorBuilderForTesting(t, State_Idle).Transactions(tx).Build()
	result := guard_HasTransactionsInflight(ctx, c)
	assert.True(t, result, "transaction in Ready_For_Dispatch should return true")
}

func TestGuard_HasTransactionsInflight_TransactionInDispatchedState(t *testing.T) {
	ctx := context.Background()
	tx := coordinatortransactionmocks.NewCoordinatorTransaction(t)
	tx.EXPECT().GetID().Return(uuid.New())

	c, _ := NewCoordinatorBuilderForTesting(t, State_Idle).Transactions(tx).Build()
	result := guard_HasTransactionsInflight(ctx, c)
	assert.True(t, result, "transaction in Dispatched should return true")
}

func TestGuard_HasTransactionsInflight_TransactionInSubmittedState(t *testing.T) {
	ctx := context.Background()
	tx := coordinatortransactionmocks.NewCoordinatorTransaction(t)
	tx.EXPECT().GetID().Return(uuid.New())

	c, _ := NewCoordinatorBuilderForTesting(t, State_Idle).Transactions(tx).Build()
	result := guard_HasTransactionsInflight(ctx, c)
	assert.True(t, result, "transaction in Submitted should return true")
}

func TestGuard_HasTransactionsInflight_MixOfConfirmedAndInflight(t *testing.T) {
	ctx := context.Background()
	tx1 := coordinatortransactionmocks.NewCoordinatorTransaction(t)
	tx1.EXPECT().GetID().Return(uuid.New())

	tx2 := coordinatortransactionmocks.NewCoordinatorTransaction(t)
	tx2.EXPECT().GetID().Return(uuid.New())

	c, _ := NewCoordinatorBuilderForTesting(t, State_Idle).Transactions(tx1, tx2).Build()
	result := guard_HasTransactionsInflight(ctx, c)
	assert.True(t, result, "mix with inflight should return true")
}

func TestGuard_HasTransactionAssembling_NoTransactions(t *testing.T) {
	ctx := context.Background()
	c, _ := NewCoordinatorBuilderForTesting(t, State_Idle).Build()
	result := guard_HasTransactionAssembling(ctx, c)
	assert.False(t, result, "no transactions should return false")
}

func TestGuard_HasTransactionAssembling_TransactionInAssemblingState(t *testing.T) {
	ctx := context.Background()
	tx := coordinatortransactionmocks.NewCoordinatorTransaction(t)
	tx.EXPECT().GetID().Return(uuid.New())
	tx.EXPECT().GetCurrentState().Return(transaction.State_Assembling)

	c, _ := NewCoordinatorBuilderForTesting(t, State_Idle).Transactions(tx).Build()
	result := guard_HasTransactionAssembling(ctx, c)
	assert.True(t, result, "transaction in Assembling should return true")
}

func TestGuard_HasTransactionAssembling_MultipleTransactionsInAssemblingState(t *testing.T) {
	ctx := context.Background()
	tx1 := coordinatortransactionmocks.NewCoordinatorTransaction(t)
	tx1.EXPECT().GetID().Return(uuid.New())
	tx1.EXPECT().GetCurrentState().Return(transaction.State_Assembling)

	tx2 := coordinatortransactionmocks.NewCoordinatorTransaction(t)
	tx2.EXPECT().GetID().Return(uuid.New())
	tx2.EXPECT().GetCurrentState().Return(transaction.State_Assembling)

	c, _ := NewCoordinatorBuilderForTesting(t, State_Idle).Transactions(tx1, tx2).Build()
	result := guard_HasTransactionAssembling(ctx, c)
	assert.True(t, result, "multiple transactions in Assembling should return true")
}

func TestGuard_HasTransactionAssembling_TransactionInOtherStates(t *testing.T) {
	ctx := context.Background()
	tx1 := coordinatortransactionmocks.NewCoordinatorTransaction(t)
	tx1.EXPECT().GetID().Return(uuid.New())
	tx1.EXPECT().GetCurrentState().Return(transaction.State_Pooled)

	tx2 := coordinatortransactionmocks.NewCoordinatorTransaction(t)
	tx2.EXPECT().GetID().Return(uuid.New())
	tx2.EXPECT().GetCurrentState().Return(transaction.State_Ready_For_Dispatch)

	tx3 := coordinatortransactionmocks.NewCoordinatorTransaction(t)
	tx3.EXPECT().GetID().Return(uuid.New())
	tx3.EXPECT().GetCurrentState().Return(transaction.State_Confirmed)

	c, _ := NewCoordinatorBuilderForTesting(t, State_Idle).Transactions(tx1, tx2, tx3).Build()
	result := guard_HasTransactionAssembling(ctx, c)
	assert.False(t, result, "transactions in other states should return false")
}

func TestGuard_ActiveCoordinatorFlushComplete_WhenFlush_ReturnsFalse(t *testing.T) {
	ctx := context.Background()
	c, _ := NewCoordinatorBuilderForTesting(t, State_Idle).ActiveCoordinatorState(State_Flush).Build()
	result := guard_ActiveCoordinatorFlushComplete(ctx, c)
	assert.False(t, result, "active coordinator in Flush state should return false")
}

func TestGuard_ActiveCoordinatorFlushComplete_WhenNotFlush_ReturnsTrue(t *testing.T) {
	ctx := context.Background()
	c, _ := NewCoordinatorBuilderForTesting(t, State_Idle).ActiveCoordinatorState(State_Closing).Build()
	result := guard_ActiveCoordinatorFlushComplete(ctx, c)
	assert.True(t, result, "active coordinator not in Flush state should return true")
}

func TestGuard_HasTransactionAssembling_MixOfAssemblingAndOtherStates(t *testing.T) {
	ctx := context.Background()
	tx1 := coordinatortransactionmocks.NewCoordinatorTransaction(t)
	tx1.EXPECT().GetID().Return(uuid.New())
	tx1.EXPECT().GetCurrentState().Return(transaction.State_Assembling)

	tx2 := coordinatortransactionmocks.NewCoordinatorTransaction(t)
	tx2.EXPECT().GetID().Return(uuid.New())
	tx2.EXPECT().GetCurrentState().Return(transaction.State_Pooled)

	c, _ := NewCoordinatorBuilderForTesting(t, State_Idle).Transactions(tx1, tx2).Build()
	result := guard_HasTransactionAssembling(ctx, c)
	assert.True(t, result, "mix with Assembling should return true")
}

func Test_guard_IsPreferredActiveCoordinator_MatchesPreferredField(t *testing.T) {
	ctx := context.Background()
	c, _ := NewCoordinatorBuilderForTesting(t, State_Idle).
		NodeName("self").
		PreferredActiveCoordinator("self").
		CurrentActiveCoordinator("other").
		Build()
	assert.True(t, guard_IsPreferredActiveCoordinator(ctx, c))
	assert.False(t, guard_IsCurrentActiveCoordinator(ctx, c))
}

func Test_guard_IsCurrentActiveCoordinator_MatchesCurrentField(t *testing.T) {
	ctx := context.Background()
	c, _ := NewCoordinatorBuilderForTesting(t, State_Idle).
		NodeName("self").
		PreferredActiveCoordinator("other").
		CurrentActiveCoordinator("self").
		Build()
	assert.False(t, guard_IsPreferredActiveCoordinator(ctx, c))
	assert.True(t, guard_IsCurrentActiveCoordinator(ctx, c))
}
