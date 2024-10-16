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
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/hyperledger/firefly-common/pkg/i18n"
	"github.com/kaleido-io/paladin/toolkit/pkg/ptxapi"
	"github.com/kaleido-io/paladin/toolkit/pkg/query"
	"github.com/kaleido-io/paladin/toolkit/pkg/tkmsgs"
)

type PTX interface {
	SendTransaction(ctx context.Context, tx *ptxapi.TransactionInput) (result SentTransaction, err error)
	SendTransactions(ctx context.Context, tx *ptxapi.TransactionInput) (results []SentTransaction, err error)

	WrapSentTransaction(id uuid.UUID) SentTransaction
	WrapSentTransactions(ids []uuid.UUID) []SentTransaction

	WrapTransactionResult(receipt *ptxapi.TransactionReceipt) TransactionResult

	GetTransaction(ctx context.Context, txID uuid.UUID) (receipt *ptxapi.Transaction, err error)
	GetTransactionFull(ctx context.Context, txID uuid.UUID) (receipt *ptxapi.TransactionFull, err error)
	QueryTransactions(ctx context.Context, jq *query.QueryJSON) (txs []*ptxapi.Transaction, err error)
	QueryTransactionsFull(ctx context.Context, jq *query.QueryJSON) (txs []*ptxapi.TransactionFull, err error)

	GetTransactionReceipt(ctx context.Context, txID uuid.UUID) (receipt *ptxapi.TransactionReceipt, err error)
	QueryTransactionReceipts(ctx context.Context, jq *query.QueryJSON) (receipts []*ptxapi.TransactionReceipt, err error)
}

type SentTransaction interface {
	ID() uuid.UUID
	Wait(ctx context.Context) (TransactionResult, error)
}

type TransactionResult interface {
	ID() uuid.UUID
	Error() error
	Success() bool
	Receipt() *ptxapi.TransactionReceipt
}

type ptx struct{ *paladinClient }

func (p *ptx) SendTransaction(ctx context.Context, tx *ptxapi.TransactionInput) (result SentTransaction, err error) {
	var txID *uuid.UUID
	err = p.rpc.CallRPC(ctx, &txID, "ptx_sendTransaction", tx)
	if err != nil {
		return nil, err
	}
	return p.WrapSentTransaction(*txID), err
}

func (p *ptx) SendTransactions(ctx context.Context, txs *ptxapi.TransactionInput) (results []SentTransaction, err error) {
	var txIDs []uuid.UUID
	err = p.rpc.CallRPC(ctx, &txIDs, "ptx_sendTransactions", txs)
	return p.WrapSentTransactions(txIDs), err
}

func (p *ptx) GetTransaction(ctx context.Context, txID uuid.UUID) (tx *ptxapi.Transaction, err error) {
	err = p.rpc.CallRPC(ctx, &tx, "ptx_getTransaction", txID, false)
	return tx, err
}

func (p *ptx) GetTransactionFull(ctx context.Context, txID uuid.UUID) (tx *ptxapi.TransactionFull, err error) {
	err = p.rpc.CallRPC(ctx, &tx, "ptx_getTransaction", txID, true)
	return tx, err
}

func (p *ptx) QueryTransactions(ctx context.Context, jq *query.QueryJSON) (txs []*ptxapi.Transaction, err error) {
	err = p.rpc.CallRPC(ctx, &txs, "ptx_queryTransactions", jq, false)
	return txs, err
}

func (p *ptx) QueryTransactionsFull(ctx context.Context, jq *query.QueryJSON) (txs []*ptxapi.TransactionFull, err error) {
	err = p.rpc.CallRPC(ctx, &txs, "ptx_queryTransactions", jq, true)
	return txs, err
}

func (p *ptx) GetTransactionReceipt(ctx context.Context, txID uuid.UUID) (receipt *ptxapi.TransactionReceipt, err error) {
	err = p.rpc.CallRPC(ctx, &receipt, "ptx_getTransactionReceipt", txID)
	return receipt, err
}

func (p *ptx) QueryTransactionReceipts(ctx context.Context, jq *query.QueryJSON) (receipts []*ptxapi.TransactionReceipt, err error) {
	err = p.rpc.CallRPC(ctx, &receipts, "ptx_queryTransactionReceipts", jq)
	return receipts, err
}

func (c *paladinClient) PTX() PTX {
	return &ptx{paladinClient: c}
}

func (p *ptx) WrapSentTransaction(id uuid.UUID) SentTransaction {
	return &sentTransaction{ptx: p, txID: id}
}

func (p *ptx) WrapSentTransactions(ids []uuid.UUID) []SentTransaction {
	results := make([]SentTransaction, len(ids))
	for i, id := range ids {
		results[i] = p.WrapSentTransaction(id)
	}
	return results
}

type sentTransaction struct {
	*ptx
	txID uuid.UUID
}

func (s *sentTransaction) ID() uuid.UUID {
	return s.txID
}

func (s *sentTransaction) GetTransaction(ctx context.Context) (*ptxapi.Transaction, error) {
	return s.PTX().GetTransaction(ctx, s.txID)
}

func (s *sentTransaction) GetTransactionFull(ctx context.Context) (*ptxapi.TransactionFull, error) {
	return s.PTX().GetTransactionFull(ctx, s.txID)
}

func (s *sentTransaction) Wait(ctx context.Context) (TransactionResult, error) {
	// TODO: Websocket optimization
	ptx := s.PTX()

	// With HTTP we poll
	ticker := time.NewTicker(s.receiptPollingInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
		case <-ctx.Done():
			return nil, i18n.NewError(ctx, tkmsgs.MsgContextCanceled)
		}
		receipt, err := ptx.GetTransactionReceipt(ctx, s.txID)
		if receipt != nil || err != nil {
			return ptx.WrapTransactionResult(receipt), err
		}
	}
}

func (p *ptx) WrapTransactionResult(r *ptxapi.TransactionReceipt) TransactionResult {
	return &completedTransaction{ptx: p, receipt: r}
}

type completedTransaction struct {
	*ptx
	receipt *ptxapi.TransactionReceipt
}

func (s *completedTransaction) ID() uuid.UUID {
	return s.receipt.ID
}

func (s *completedTransaction) Success() bool {
	return s.receipt != nil && s.receipt.Success
}

func (s *completedTransaction) Error() error {
	if s.Success() {
		return nil
	}
	if s.receipt == nil || s.receipt.FailureMessage != "" {
		return i18n.NewError(context.Background(), tkmsgs.MsgPaladinClientNoFailureMsg)
	}
	return errors.New(s.receipt.FailureMessage)
}

func (s *completedTransaction) Receipt() *ptxapi.TransactionReceipt {
	return s.receipt
}
