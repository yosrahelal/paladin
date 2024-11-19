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

package ptmgrtypes

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"

	"github.com/google/uuid"
)

func TestDispatchableTransactionsIDs(t *testing.T) {
	ctx := context.Background()
	id1 := uuid.New()
	id2 := uuid.New()
	id3 := uuid.New()
	id4 := uuid.New()
	mockTransactionFlow1 := NewMockTransactionFlow(t)
	mockTransactionFlow1.On("ID", mock.Anything).Return(id1)

	mockTransactionFlow2 := NewMockTransactionFlow(t)
	mockTransactionFlow2.On("ID", mock.Anything).Return(id2)
	mockTransactionFlow3 := NewMockTransactionFlow(t)
	mockTransactionFlow3.On("ID", mock.Anything).Return(id3)
	mockTransactionFlow4 := NewMockTransactionFlow(t)
	mockTransactionFlow4.On("ID", mock.Anything).Return(id4)

	dispatchableTransactions := DispatchableTransactions{
		"A": {
			mockTransactionFlow1,
			mockTransactionFlow2,
		},
		"B": {
			mockTransactionFlow3,
			mockTransactionFlow4,
		},
	}

	ids := dispatchableTransactions.IDs(ctx)
	assert.Len(t, ids, 4)
	assert.Contains(t, ids, id1.String())
	assert.Contains(t, ids, id2.String())
	assert.Contains(t, ids, id3.String())
	assert.Contains(t, ids, id4.String())

}
