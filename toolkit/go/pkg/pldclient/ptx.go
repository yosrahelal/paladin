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

type PTX interface {
	GetTransaction(ctx context.Context, txID uuid.UUID) (receipt *pldapi.Transaction, err error)
	GetTransactionFull(ctx context.Context, txID uuid.UUID) (receipt *pldapi.TransactionFull, err error)
	QueryTransactions(ctx context.Context, jq *query.QueryJSON) (txs []*pldapi.Transaction, err error)
	QueryTransactionsFull(ctx context.Context, jq *query.QueryJSON) (txs []*pldapi.TransactionFull, err error)

	GetTransactionReceipt(ctx context.Context, txID uuid.UUID) (receipt *pldapi.TransactionReceipt, err error)
	QueryTransactionReceipts(ctx context.Context, jq *query.QueryJSON) (receipts []*pldapi.TransactionReceipt, err error)

	ResoleVerifier(ctx context.Context, identifier string, algorithm string, verifierType string) (verifier string, err error)
}

var _ PTX = &ptx{}

type ptx struct{ c *paladinClient }

func (c *paladinClient) PTX() PTX {
	return &ptx{c: c}
}

func (p *ptx) SendTransaction(ctx context.Context, tx *pldapi.TransactionInput) (txID *uuid.UUID, err error) {
	err = p.c.CallRPC(ctx, &txID, "ptx_sendTransaction", tx)
	return txID, err
}

func (p *ptx) SendTransactions(ctx context.Context, txs []*pldapi.TransactionInput) (txIDs []uuid.UUID, err error) {
	err = p.c.CallRPC(ctx, &txIDs, "ptx_sendTransactions", txs)
	return txIDs, err
}

func (p *ptx) GetTransaction(ctx context.Context, txID uuid.UUID) (tx *pldapi.Transaction, err error) {
	err = p.c.CallRPC(ctx, &tx, "ptx_getTransaction", txID, false)
	return tx, err
}

func (p *ptx) GetTransactionFull(ctx context.Context, txID uuid.UUID) (tx *pldapi.TransactionFull, err error) {
	err = p.c.CallRPC(ctx, &tx, "ptx_getTransaction", txID, true)
	return tx, err
}

func (p *ptx) QueryTransactions(ctx context.Context, jq *query.QueryJSON) (txs []*pldapi.Transaction, err error) {
	err = p.c.CallRPC(ctx, &txs, "ptx_queryTransactions", jq, false)
	return txs, err
}

func (p *ptx) QueryTransactionsFull(ctx context.Context, jq *query.QueryJSON) (txs []*pldapi.TransactionFull, err error) {
	err = p.c.CallRPC(ctx, &txs, "ptx_queryTransactions", jq, true)
	return txs, err
}

func (p *ptx) GetTransactionReceipt(ctx context.Context, txID uuid.UUID) (receipt *pldapi.TransactionReceipt, err error) {
	err = p.c.CallRPC(ctx, &receipt, "ptx_getTransactionReceipt", txID)
	return receipt, err
}

func (p *ptx) QueryTransactionReceipts(ctx context.Context, jq *query.QueryJSON) (receipts []*pldapi.TransactionReceipt, err error) {
	err = p.c.CallRPC(ctx, &receipts, "ptx_queryTransactionReceipts", jq)
	return receipts, err
}

func (p *ptx) ResoleVerifier(ctx context.Context, identifier string, algorithm string, verifierType string) (verifier string, err error) {
	err = p.c.CallRPC(ctx, &verifier, "ptx_resolveVerifier", identifier, algorithm, verifierType)
	return verifier, err
}
