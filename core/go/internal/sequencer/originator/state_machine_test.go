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
package originator
import (
	"context"
	"testing"
	"github.com/LFDT-Paladin/paladin/core/internal/sequencer/originator/transaction"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)
func Test_GetTxStatus_KnownTransactionReturnsStatus(t *testing.T) {
	ctx := context.Background()
	txBuilder := transaction.NewTransactionBuilderForTesting(t, transaction.State_Pending)
	builder := NewOriginatorBuilderForTesting(State_Observing).TransactionBuilders(txBuilder)
	o, _ := builder.Build()
	txn := txBuilder.GetBuiltTransaction()
	require.NotNil(t, txn)
	status, err := o.GetTxStatus(ctx, txn.GetID())
	require.NoError(t, err)
	assert.Equal(t, txn.GetID().String(), status.TxID)
	assert.NotEmpty(t, status.Status)
}
func Test_GetTxStatus_UnknownTransactionReturnsUnknown(t *testing.T) {
	ctx := context.Background()
	builder := NewOriginatorBuilderForTesting(State_Observing)
	o, _ := builder.Build()
	unknownID := uuid.New()
	status, err := o.GetTxStatus(ctx, unknownID)
	require.NoError(t, err)
	assert.Equal(t, unknownID.String(), status.TxID)
	assert.Equal(t, "unknown", status.Status)
}