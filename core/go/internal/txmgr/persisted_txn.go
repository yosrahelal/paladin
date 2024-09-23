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

package txmgr

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"

	"github.com/google/uuid"
	"github.com/hyperledger/firefly-common/pkg/i18n"
	"github.com/hyperledger/firefly-signer/pkg/abi"
	"github.com/kaleido-io/paladin/core/internal/components"
	"github.com/kaleido-io/paladin/core/internal/filters"
	"github.com/kaleido-io/paladin/core/internal/msgs"
	"github.com/kaleido-io/paladin/toolkit/pkg/log"
	"github.com/kaleido-io/paladin/toolkit/pkg/ptxapi"
	"github.com/kaleido-io/paladin/toolkit/pkg/query"
	"github.com/kaleido-io/paladin/toolkit/pkg/tktypes"
	"gorm.io/gorm"
)

// This contains the fields that go into the database.
// We keep this separate from the ptxapi.TransactionXYZ interfaces that clients and applications use to interact
// with this, so we have a separation of concerns on the GORM annotations and data serialization format
type persistedTransaction struct {
	ID                 uuid.UUID                            `gorm:"column:id;primaryKey"`
	IdempotencyKey     *string                              `gorm:"column:idempotency_key"`
	Type               tktypes.Enum[ptxapi.TransactionType] `gorm:"column:type"`
	Created            tktypes.Timestamp                    `gorm:"column:created;autoCreateTime:nano"`
	ABIReference       *tktypes.Bytes32                     `gorm:"column:abi_ref"`
	Function           *string                              `gorm:"column:function"`
	Domain             *string                              `gorm:"column:domain"`
	From               string                               `gorm:"column:from"`
	To                 *tktypes.EthAddress                  `gorm:"column:to"`
	Data               tktypes.RawJSON                      `gorm:"column:data"` // we always store in JSON object format
	TransactionDeps    []*transactionDep                    `gorm:"foreignKey:transaction;references:id"`
	TransactionReceipt *transactionReceipt                  `gorm:"foreignKey:transaction;references:id"`
}

type transactionDep struct {
	Transaction uuid.UUID `gorm:"column:transaction;primaryKey"`
	DependsOn   uuid.UUID `gorm:"column:depends_on"`
}

var transactionFilters = filters.FieldMap{
	"id":           filters.UUIDField("id"),
	"created":      filters.TimestampField("created"),
	"abiReference": filters.TimestampField("abi_ref"),
	"functionName": filters.StringField("fn_name"),
	"domain":       filters.StringField("domain"),
	"from":         filters.StringField("from"),
	"to":           filters.HexBytesField("to"),
}

func mapPersistedTXBase(pt *persistedTransaction) *ptxapi.Transaction {
	res := &ptxapi.Transaction{
		ID:             pt.ID,
		Created:        pt.Created,
		IdempotencyKey: stringOrEmpty(pt.IdempotencyKey),
		Type:           pt.Type,
		Domain:         stringOrEmpty(pt.Domain),
		Function:       stringOrEmpty(pt.Function),
		ABIReference:   pt.ABIReference,
		From:           pt.From,
		To:             pt.To,
		Data:           pt.Data,
	}
	return res
}

func (tm *txManager) mapPersistedTXFull(pt *persistedTransaction) *ptxapi.TransactionFull {
	res := &ptxapi.TransactionFull{
		Transaction: mapPersistedTXBase(pt),
	}
	receipt := pt.TransactionReceipt
	if receipt != nil {
		res.Receipt = mapPersistedReceipt(receipt)
	}
	for _, dep := range pt.TransactionDeps {
		res.DependsOn = append(res.DependsOn, dep.DependsOn)
	}
	res.Activity = tm.getActivityRecords(res.ID)
	return res
}

type resolvedFunction struct {
	abi          abi.ABI
	abiReference *tktypes.Bytes32
	definition   *abi.Entry
	signature    string
}

func (tm *txManager) resolveFunction(ctx context.Context, dbTX *gorm.DB, inputABI abi.ABI, inputABIRef *tktypes.Bytes32, requiredFunction string, to *tktypes.EthAddress) (_ *resolvedFunction, err error) {

	// Lookup the ABI we're working with.
	// Only needs to contain the function definition we're calling, but can be the whole ABI of the contract.
	// Beneficial if it includes the error definitions for this
	var pa *ptxapi.StoredABI
	if inputABIRef != nil {
		if inputABI != nil {
			return nil, i18n.NewError(ctx, msgs.MsgTxMgrABIAndDefinition)
		}
		pa, err = tm.getABIByHash(ctx, *inputABIRef)
	} else if len(inputABI) > 0 {
		pa, err = tm.upsertABI(ctx, dbTX, inputABI)
	} else {
		return nil, i18n.WrapError(ctx, err, msgs.MsgTxMgrNoABIOrReference)
	}
	if err != nil || pa == nil {
		return nil, i18n.WrapError(ctx, err, msgs.MsgTxMgrABIReferenceLookupFailed, inputABIRef)
	}

	// If a function is specified, we cannot be invoking the constructor
	if requiredFunction != "" && to == nil {
		return nil, i18n.NewError(ctx, msgs.MsgTxMgrFunctionWithoutTo)
	}

	// Find the function in the ABI that we're invoking
	var selectedFunction *abi.Entry
	var functionSignature string
	for _, e := range pa.ABI {
		var isMatch bool
		if e.Type == abi.Constructor && to == nil {
			isMatch = true
		} else if e.Type == abi.Function && to != nil {
			if strings.HasPrefix(requiredFunction, "0x") {
				selectorString := e.FunctionSelectorBytes().String()
				isMatch = strings.EqualFold(selectorString, requiredFunction)
			} else if strings.Contains(requiredFunction, "(") {
				selectorString, _ := e.Signature()
				isMatch = (selectorString == requiredFunction)
			} else if len(requiredFunction) > 0 {
				isMatch = (e.Name == requiredFunction)
			} else {
				// No selector - any function is a match
				isMatch = true
			}
		}
		if isMatch {
			oldSelector := functionSignature
			functionSignature, _ = e.Signature()
			if oldSelector != "" {
				return nil, i18n.NewError(ctx, msgs.MsgTxMgrFunctionMultiMatch, oldSelector, functionSignature)
			}
			selectedFunction = e
		}
	}
	if functionSignature == "" || selectedFunction == nil {
		return nil, i18n.NewError(ctx, msgs.MsgTxMgrFunctionNoMatch)
	}
	log.L(ctx).Debugf("Function selected: %s", selectedFunction.SolString())
	return &resolvedFunction{
		abi:          pa.ABI,
		abiReference: &pa.Hash,
		definition:   selectedFunction,
		signature:    functionSignature,
	}, nil
}

func (tm *txManager) parseDataBytes(ctx context.Context, e *abi.Entry, dataBytes []byte) (cv *abi.ComponentValue, err error) {
	// We might have the function selector
	selector := e.FunctionSelectorBytes()
	if len(dataBytes) >= len(selector) && len(dataBytes)%32 == 4 && bytes.Equal(selector, dataBytes[0:4]) {
		cv, err = e.Inputs.DecodeABIDataCtx(ctx, selector, 4) // we will run out of data if this is not right, so safe to do first
	}
	if cv == nil || err != nil {
		cv, err = e.Inputs.DecodeABIDataCtx(ctx, dataBytes, 0)
	}
	return cv, err
}

func (tm *txManager) parseInputs(
	ctx context.Context,
	e *abi.Entry,
	txType tktypes.Enum[ptxapi.TransactionType],
	data tktypes.RawJSON,
	bytecode tktypes.HexBytes,
) (jsonData tktypes.RawJSON, err error) {

	if _, err := txType.MapToString(); err != nil {
		return nil, i18n.WrapError(ctx, err, msgs.MsgTxMgrInvalidTXType)
	}
	if (e.Type != abi.Constructor || txType.V() != ptxapi.TransactionTypePublic) && len(bytecode) != 0 {
		return nil, i18n.NewError(ctx, msgs.MsgTxMgrBytecodeNonPublicConstructor, txType.V(), e.String())
	} else if e.Type == abi.Constructor && len(bytecode) == 0 && txType == ptxapi.TransactionTypePublic.Enum() {
		// We don't support supplying bytecode for public transactions precompiled ahead of the constructor
		// inputs, you must split the contract code out into bytecode
		return nil, i18n.NewError(ctx, msgs.MsgTxMgrBytecodeAndHexData, e.String())
	}

	// TODO: Resolve domain for private TX

	var iDecoded any
	d := json.NewDecoder(bytes.NewReader(data.BytesOrNull()))
	d.UseNumber()
	if err := d.Decode(&iDecoded); err != nil {
		return nil, i18n.WrapError(ctx, err, msgs.MsgTxMgrInvalidInputData, e.String())
	}
	var cv *abi.ComponentValue
	switch decoded := iDecoded.(type) {
	case nil:
		cv, err = tm.parseDataBytes(ctx, e, []byte{})
	case string:
		// Must be a byte array pre-encoded
		var dataBytes []byte
		dataBytes, err = tktypes.ParseHexBytes(ctx, decoded)
		if err == nil {
			cv, err = tm.parseDataBytes(ctx, e, dataBytes)
		}
	case map[string]interface{}, []interface{}:
		cv, err = e.Inputs.ParseExternalDataCtx(ctx, decoded)
	default:
		return nil, i18n.WrapError(ctx, err, msgs.MsgTxMgrInvalidInputDataType, iDecoded)
	}
	if err != nil {
		return nil, i18n.WrapError(ctx, err, msgs.MsgTxMgrInvalidInputData, e.String())
	}
	return tktypes.StandardABISerializer().SerializeJSONCtx(ctx, cv)
}

func (tm *txManager) sendTransaction(ctx context.Context, tx *ptxapi.TransactionInput) (*uuid.UUID, error) {
	// TODO: Add flush writer for parallel performance on this form of insertion
	txIDs, err := tm.sendTransactions(ctx, []*ptxapi.TransactionInput{tx})
	if err != nil {
		return nil, err
	}
	return &txIDs[0], nil
}

func (tm *txManager) sendTransactions(ctx context.Context, txs []*ptxapi.TransactionInput) ([]uuid.UUID, error) {
	var inserts []txInsertInfo
	err := tm.p.DB().Transaction(func(dbTX *gorm.DB) (err error) {
		inserts, err = tm.insertTransactions(ctx, dbTX, txs)
		return err
	})
	if err != nil {
		return nil, err
	}

	// TODO: Integrate with private TX manager persistence when available
	txIDs := make([]uuid.UUID, len(txs))
	for i, tx := range txs {
		txIDs[i] = inserts[i].id
		if tx.Type.V() == ptxapi.TransactionTypePrivate {
			if tx.To == nil {
				err = tm.privateTxMgr.HandleDeployTx(ctx, &components.PrivateContractDeploy{
					ID:     inserts[i].id,
					Domain: tx.Domain,
					Inputs: inserts[i].inputs,
				})
			} else {
				err = tm.privateTxMgr.HandleNewTx(ctx, &components.PrivateTransaction{
					ID: inserts[i].id,
					Inputs: &components.TransactionInputs{
						Domain:   tx.Domain,
						From:     tx.From,
						To:       *tx.To,
						Function: inserts[i].fn.definition,
						Inputs:   inserts[i].inputs,
					},
				})
			}
			if err != nil {
				return nil, err
			}
		}
	}
	return txIDs, err
}

type txInsertInfo struct {
	id     uuid.UUID
	fn     *resolvedFunction
	inputs tktypes.RawJSON
}

func (tm *txManager) insertTransactions(ctx context.Context, dbTX *gorm.DB, txs []*ptxapi.TransactionInput) ([]txInsertInfo, error) {
	info := make([]txInsertInfo, len(txs))
	ptxs := make([]*persistedTransaction, len(txs))
	var transactionDeps []*transactionDep
	for i := range txs {
		tx := txs[i]
		txID := uuid.New()
		info[i].id = txID

		fn, err := tm.resolveFunction(ctx, dbTX, tx.ABI, tx.ABIReference, tx.Function, tx.To)
		if err != nil {
			return nil, err
		}
		info[i].fn = fn

		normalizedJSON, err := tm.parseInputs(ctx, fn.definition, tx.Type, tx.Data, tx.Bytecode)
		if err != nil {
			return nil, err
		}
		info[i].inputs = normalizedJSON

		// TODO: Flush writer for singleton transactions vs batch
		ptxs[i] = &persistedTransaction{
			ID:             txID,
			IdempotencyKey: notEmptyOrNull(tx.IdempotencyKey),
			Type:           tx.Type,
			ABIReference:   fn.abiReference,
			Function:       notEmptyOrNull(fn.signature),
			Domain:         notEmptyOrNull(tx.Domain),
			From:           tx.From,
			To:             tx.To,
			Data:           normalizedJSON,
		}
		for _, d := range tx.DependsOn {
			transactionDeps = append(transactionDeps, &transactionDep{
				Transaction: txID,
				DependsOn:   d,
			})
		}
	}

	err := dbTX.
		Table("transactions").
		Create(ptxs).
		Omit("TransactionDeps").
		Error
	if err == nil && len(transactionDeps) > 0 {
		err = dbTX.
			Table("transaction_deps").
			Create(transactionDeps).
			Error
	}
	if err != nil {
		return nil, err
	}
	return info, nil
}

func (tm *txManager) queryTransactions(ctx context.Context, jq *query.QueryJSON, pending bool) ([]*ptxapi.Transaction, error) {
	qw := &queryWrapper[persistedTransaction, ptxapi.Transaction]{
		p:           tm.p,
		table:       "transactions",
		defaultSort: "-created",
		filters:     transactionFilters,
		query:       jq,
		finalize: func(q *gorm.DB) *gorm.DB {
			// TODO: Join public and private transaction strings
			if pending {
				q = q.Joins("TransactionReceipt").
					Where(`"TransactionReceipt"."transaction" IS NULL`)
			}
			return q
		},
		mapResult: func(pt *persistedTransaction) (*ptxapi.Transaction, error) {
			return mapPersistedTXBase(pt), nil
		},
	}
	return qw.run(ctx, nil)
}

func (tm *txManager) queryTransactionsFull(ctx context.Context, jq *query.QueryJSON, pending bool) ([]*ptxapi.TransactionFull, error) {
	qw := &queryWrapper[persistedTransaction, ptxapi.TransactionFull]{
		p:           tm.p,
		table:       "transactions",
		defaultSort: "-created",
		filters:     transactionFilters,
		query:       jq,
		finalize: func(q *gorm.DB) *gorm.DB {
			// TODO: Join public and private transaction info
			q = q.
				Preload("TransactionDeps").
				Joins("TransactionReceipt")
			if pending {
				q = q.Where(`"TransactionReceipt"."transaction" IS NULL`)
			}
			return q
		},
		mapResult: func(pt *persistedTransaction) (*ptxapi.TransactionFull, error) {
			return tm.mapPersistedTXFull(pt), nil
		},
	}
	return qw.run(ctx, nil)
}

func (tm *txManager) getTransactionByIDFull(ctx context.Context, id uuid.UUID) (*ptxapi.TransactionFull, error) {
	ptxs, err := tm.queryTransactionsFull(ctx, query.NewQueryBuilder().Limit(1).Equal("id", id).Query(), false)
	if len(ptxs) == 0 || err != nil {
		return nil, err
	}
	return ptxs[0], nil
}

func (tm *txManager) getTransactionByID(ctx context.Context, id uuid.UUID) (*ptxapi.Transaction, error) {
	ptxs, err := tm.queryTransactions(ctx, query.NewQueryBuilder().Limit(1).Equal("id", id).Query(), false)
	if len(ptxs) == 0 || err != nil {
		return nil, err
	}
	return ptxs[0], nil
}

func (tm *txManager) getTransactionDependencies(ctx context.Context, id uuid.UUID) (*ptxapi.TransactionDependencies, error) {
	var persistedDeps []*transactionDep
	err := tm.p.DB().
		WithContext(ctx).
		Table(`transaction_deps`).
		Where(`"transaction" = ?`, id).
		Or("depends_on = ?", id).
		Find(&persistedDeps).
		Error
	if err != nil {
		return nil, err
	}
	res := &ptxapi.TransactionDependencies{
		DependsOn: make([]uuid.UUID, 0, len(persistedDeps)),
		PrereqOf:  make([]uuid.UUID, 0, len(persistedDeps)),
	}
	for _, td := range persistedDeps {
		if td.Transaction == id {
			res.DependsOn = append(res.DependsOn, td.DependsOn)
		} else {
			res.PrereqOf = append(res.PrereqOf, td.Transaction)
		}
	}
	return res, nil
}
