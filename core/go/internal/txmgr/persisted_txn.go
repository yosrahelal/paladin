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

type transactionReceipt struct {
	Transaction uuid.UUID        `gorm:"column:transaction;primaryKey"`
	Success     bool             `gorm:"column:success"`
	TXHash      *tktypes.Bytes32 `gorm:"column:tx_hash"`
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
	for _, dep := range pt.TransactionDeps {
		res.DependsOn = append(res.DependsOn, dep.DependsOn)
	}
	return res
}

func (tm *txManager) mapPersistedTXFull(pt *persistedTransaction) *ptxapi.TransactionFull {
	res := &ptxapi.TransactionFull{
		Transaction: mapPersistedTXBase(pt),
	}
	receipt := pt.TransactionReceipt
	if receipt != nil {
		res.Receipt = &ptxapi.TransactionReceiptData{
			Success:         receipt.Success,
			TransactionHash: receipt.TXHash,
		}
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

func (tm *txManager) resolveFunction(ctx context.Context, inputABI abi.ABI, inputABIRef *tktypes.Bytes32, requiredFunction string, to *tktypes.EthAddress) (_ *resolvedFunction, err error) {

	// Lookup the ABI we're working with.
	// Only needs to contain the function definition we're calling, but can be the whole ABI of the contract.
	// Beneficial if it includes the error definitions for this
	var pa *ptxapi.StoredABI
	if inputABIRef != nil {
		if inputABI != nil {
			return nil, i18n.NewError(ctx, msgs.MsgTxMgrABIAndDefinition)
		}
		pa, err = tm.getABIByHash(ctx, *inputABIRef)
	} else {
		pa, err = tm.upsertABI(ctx, inputABI)
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
				i18n.NewError(ctx, msgs.MsgTxMgrFunctionMultiMatch, oldSelector, functionSignature)
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
	if e.Type != abi.Constructor && len(bytecode) != 0 {
		return nil, i18n.NewError(ctx, msgs.MsgTxMgrBytecodeNonConstructor, e.String())
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
	case string:
		// Must be a byte array pre-encoded
		dataBytes, err := tktypes.ParseHexBytes(ctx, decoded)
		if err != nil {
			return nil, i18n.WrapError(ctx, err, msgs.MsgTxMgrInvalidInputDataBytes, e.String())
		}
		if e.Type != abi.Constructor && len(bytecode) == 0 {
			// We don't support u
			return nil, i18n.NewError(ctx, msgs.MsgTxMgrBytecodeAndHexData, e.String())
		}
		// We might have the function selector
		cv, err = e.Inputs.DecodeABIDataCtx(ctx, dataBytes, 0)
		if err != nil && e.Type == abi.Function {
			selector := e.FunctionSelectorBytes()
			if len(dataBytes) >= len(selector) && bytes.Equal(selector, dataBytes[0:4]) {
				cv, err = e.Inputs.DecodeABIDataCtx(ctx, selector, 4)
			}
		}
		if err != nil {
			return nil, i18n.WrapError(ctx, err, msgs.MsgTxMgrInvalidInputDataBytes, e.String())
		}
	case map[string]interface{}, []interface{}:
		cv, err = e.Inputs.ParseExternalDataCtx(ctx, decoded)
		if err != nil {
			return nil, i18n.WrapError(ctx, err, msgs.MsgTxMgrInvalidInputData, e.String())
		}
	default:
		return nil, i18n.WrapError(ctx, err, msgs.MsgTxMgrInvalidInputDataType, iDecoded)
	}

	return tktypes.StandardABISerializer().SerializeJSONCtx(ctx, cv)
}

func (tm *txManager) sendTransaction(ctx context.Context, tx *ptxapi.TransactionInput) (*uuid.UUID, error) {

	fn, err := tm.resolveFunction(ctx, tx.ABI, tx.ABIReference, tx.Function, tx.To)
	if err != nil {
		return nil, err
	}

	normalizedJSON, err := tm.parseInputs(ctx, fn.definition, tx.Type, tx.Data, tx.Bytecode)
	if err != nil {
		return nil, err
	}

	// TODO: Flush writer for singleton transactions vs batch
	ptx := &persistedTransaction{
		ID:             uuid.New(),
		IdempotencyKey: notEmptyOrNull(tx.IdempotencyKey),
		Type:           tx.Type,
		ABIReference:   fn.abiReference,
		Function:       notEmptyOrNull(fn.signature),
		Domain:         notEmptyOrNull(tx.Domain),
		From:           tx.From,
		To:             tx.To,
		Data:           normalizedJSON,
	}
	err = tm.p.DB().
		Table("transactions").
		Create(ptx).
		Error
	if err != nil {
		return nil, err
	}
	return &ptx.ID, nil
}

func (tm *txManager) queryTransactions(ctx context.Context, jq *query.QueryJSON) ([]*ptxapi.Transaction, error) {
	qw := &queryWrapper[persistedTransaction, ptxapi.Transaction]{
		p:       tm.p,
		table:   "transactions",
		filters: transactionFilters,
		query:   jq,
		finalize: func(q *gorm.DB) *gorm.DB {
			// TODO: Join public and private transaction strings
			return q.Joins("TransactionDeps")
		},
		mapResult: func(pt *persistedTransaction) (*ptxapi.Transaction, error) {
			return mapPersistedTXBase(pt), nil
		},
	}
	return qw.run(ctx)
}

func (tm *txManager) queryTransactionsFull(ctx context.Context, jq *query.QueryJSON) ([]*ptxapi.TransactionFull, error) {
	qw := &queryWrapper[persistedTransaction, ptxapi.TransactionFull]{
		p:       tm.p,
		table:   "transactions",
		filters: transactionFilters,
		query:   jq,
		finalize: func(q *gorm.DB) *gorm.DB {
			// TODO: Join public and private transaction info
			return q.Joins("TransactionDeps").Joins("TransactionReceipt")
		},
		mapResult: func(pt *persistedTransaction) (*ptxapi.TransactionFull, error) {
			return tm.mapPersistedTXFull(pt), nil
		},
	}
	return qw.run(ctx)
}

func (tm *txManager) getPersistedTransactionByID(ctx context.Context, id uuid.UUID) (*persistedTransaction, error) {
	var pTxns []*persistedTransaction
	err := tm.p.DB().
		WithContext(ctx).
		Table("transactions").
		Where("id = ?", id).
		Find(&pTxns).
		Error
	if err != nil || len(pTxns) == 0 {
		return nil, err
	}
	return pTxns[0], nil
}

func (tm *txManager) getTransactionByIDFull(ctx context.Context, id uuid.UUID) (*ptxapi.TransactionFull, error) {
	ptx, err := tm.getPersistedTransactionByID(ctx, id)
	if ptx == nil || err != nil {
		return nil, err
	}
	return tm.mapPersistedTXFull(ptx), nil
}

func (tm *txManager) getTransactionByID(ctx context.Context, id uuid.UUID) (*ptxapi.Transaction, error) {
	ptx, err := tm.getPersistedTransactionByID(ctx, id)
	if ptx == nil || err != nil {
		return nil, err
	}
	return mapPersistedTXBase(ptx), nil
}
