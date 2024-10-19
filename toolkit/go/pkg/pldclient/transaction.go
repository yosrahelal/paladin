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
	"github.com/hyperledger/firefly-signer/pkg/abi"
	"github.com/kaleido-io/paladin/toolkit/pkg/pldapi"
	"github.com/kaleido-io/paladin/toolkit/pkg/tkmsgs"
	"github.com/kaleido-io/paladin/toolkit/pkg/tktypes"
)

// High level helpers for transactions
type Transaction interface {

	// Building public & private transactions from ABI function interfaces

	ABI(ctx context.Context, a abi.ABI) (ABIClient, error)
	MustABI(a abi.ABI) ABIClient
	ABIJSON(ctx context.Context, abiJson []byte) (ABIClient, error)
	ABIFunction(ctx context.Context, functionABI *abi.Entry) (_ ABIFunctionClient, err error)
	ABIConstructor(ctx context.Context, constructorABI *abi.Entry, bytecode tktypes.HexBytes) (_ ABIFunctionClient, err error)
	MustABIJSON(abiJson []byte) ABIClient

	// Sending transactions
	Send(ctx context.Context, tx *pldapi.TransactionInput) (result SentTransaction, err error)
	SendMany(ctx context.Context, txs []*pldapi.TransactionInput) (results []SentTransaction, err error)

	// Direct access to helper wrapper
	WrapSent(id uuid.UUID) SentTransaction
	WrapSentMany(ids []uuid.UUID) []SentTransaction
	WrapResult(receipt *pldapi.TransactionReceipt) TransactionResult
}

type SentTransaction interface {
	ID() uuid.UUID
	Wait(ctx context.Context) (TransactionResult, error)
}

type TransactionResult interface {
	ID() uuid.UUID
	Error() error
	Success() bool
	Receipt() *pldapi.TransactionReceipt
}

func (c *paladinClient) Transaction() Transaction {
	return &transaction{ptx: c.PTX().(*ptx)}
}

type transaction struct {
	*ptx
}

func (p *transaction) Send(ctx context.Context, tx *pldapi.TransactionInput) (result SentTransaction, err error) {
	var txID *uuid.UUID
	err = p.c.CallRPC(ctx, &txID, "ptx_sendTransaction", tx)
	if err != nil {
		return nil, err
	}
	return p.WrapSent(*txID), err
}

func (p *transaction) SendMany(ctx context.Context, txs []*pldapi.TransactionInput) (results []SentTransaction, err error) {
	txIDs, err := p.SendTransactions(ctx, txs)
	return p.WrapSentMany(txIDs), err
}

func (p *transaction) WrapSent(id uuid.UUID) SentTransaction {
	return &sentTransaction{ptx: p.ptx, txID: id}
}

func (p *transaction) WrapSentMany(ids []uuid.UUID) []SentTransaction {
	results := make([]SentTransaction, len(ids))
	for i, id := range ids {
		results[i] = p.WrapSent(id)
	}
	return results
}

type sentTransaction struct {
	*transaction
	*ptx
	txID uuid.UUID
}

func (s *sentTransaction) ID() uuid.UUID {
	return s.txID
}

func (s *sentTransaction) GetTransaction(ctx context.Context) (*pldapi.Transaction, error) {
	return s.c.PTX().GetTransaction(ctx, s.txID)
}

func (s *sentTransaction) GetTransactionFull(ctx context.Context) (*pldapi.TransactionFull, error) {
	return s.c.PTX().GetTransactionFull(ctx, s.txID)
}

func (s *sentTransaction) Wait(ctx context.Context) (TransactionResult, error) {
	// TODO: Websocket optimization

	// With HTTP we poll
	ticker := time.NewTicker(s.c.receiptPollingInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
		case <-ctx.Done():
			return nil, i18n.NewError(ctx, tkmsgs.MsgContextCanceled)
		}
		receipt, err := s.GetTransactionReceipt(ctx, s.txID)
		if receipt != nil || err != nil {
			return s.WrapResult(receipt), err
		}
	}
}

func (t *transaction) WrapResult(r *pldapi.TransactionReceipt) TransactionResult {
	return &completedTransaction{ptx: t.ptx, receipt: r}
}

type completedTransaction struct {
	*ptx
	receipt *pldapi.TransactionReceipt
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

func (s *completedTransaction) Receipt() *pldapi.TransactionReceipt {
	return s.receipt
}
