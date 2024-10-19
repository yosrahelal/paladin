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

package pldclient

import (
	"context"

	"github.com/google/uuid"
	"github.com/kaleido-io/paladin/toolkit/pkg/pldapi"
	"github.com/kaleido-io/paladin/toolkit/pkg/query"
)

// Any function that is added do the PR should be added to the docs as well
// This will generate the documentation for interface
var _ PTXTransaction = &PTXTransactionDoc{}

type PTXTransactionDoc struct{}

func (ptx *PTXTransactionDoc) GetTransaction(ctx context.Context, txID uuid.UUID) (*pldapi.Transaction, error) {
	return nil, nil
}

func (ptx *PTXTransactionDoc) GetTransactionFull(ctx context.Context, txID uuid.UUID) (*pldapi.TransactionFull, error) {
	return nil, nil
}

func (ptx *PTXTransactionDoc) QueryTransactions(ctx context.Context, jq *query.QueryJSON) ([]*pldapi.Transaction, error) {
	return nil, nil
}

func (ptx *PTXTransactionDoc) QueryTransactionsFull(ctx context.Context, jq *query.QueryJSON) ([]*pldapi.TransactionFull, error) {
	return nil, nil
}

func (ptx *PTXTransactionDoc) GetTransactionReceipt(ctx context.Context, txID uuid.UUID) (*pldapi.TransactionReceipt, error) {
	return nil, nil
}

func (ptx *PTXTransactionDoc) QueryTransactionReceipts(ctx context.Context, jq *query.QueryJSON) ([]*pldapi.TransactionReceipt, error) {
	return nil, nil
}
