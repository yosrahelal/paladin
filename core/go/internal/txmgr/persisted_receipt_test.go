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
	"fmt"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/google/uuid"
	"github.com/kaleido-io/paladin/core/internal/components"
	"github.com/kaleido-io/paladin/core/pkg/config"
	"github.com/stretchr/testify/assert"
	"gorm.io/gorm"
)

func TestFinalizeTransactionsNoOp(t *testing.T) {

	ctx, txm, done := newTestTransactionManager(t, false)
	defer done()

	err := txm.FinalizeTransactions(ctx, txm.p.DB(), nil, false)
	assert.NoError(t, err)

}

func TestFinalizeTransactionsLookupFail(t *testing.T) {

	ctx, txm, done := newTestTransactionManager(t, false, func(conf *config.TxManagerConfig, mc *mockComponents) {
		mc.db.ExpectQuery("SELECT.*transactions").WillReturnError(fmt.Errorf("pop"))
	})
	defer done()

	txID := uuid.New()
	err := txm.FinalizeTransactions(ctx, txm.p.DB(), []*components.ReceiptInput{
		{TransactionID: txID, ReceiptType: components.RT_Success},
	}, false)
	assert.Regexp(t, "pop", err)

}

func TestFinalizeTransactionsSuccessWithFailure(t *testing.T) {

	txID := uuid.New()
	ctx, txm, done := newTestTransactionManager(t, false, func(conf *config.TxManagerConfig, mc *mockComponents) {
		mc.db.ExpectQuery("SELECT.*transactions").WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(txID))
	})
	defer done()

	err := txm.FinalizeTransactions(ctx, txm.p.DB(), []*components.ReceiptInput{
		{TransactionID: txID, ReceiptType: components.RT_Success,
			FailureMessage: "not empty"},
	}, false)
	assert.Regexp(t, "PD012213", err)
}

func TestFinalizeTransactionsBadType(t *testing.T) {

	txID := uuid.New()
	ctx, txm, done := newTestTransactionManager(t, false, func(conf *config.TxManagerConfig, mc *mockComponents) {
		mc.db.ExpectQuery("SELECT.*transactions").WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(txID))
	})
	defer done()

	err := txm.FinalizeTransactions(ctx, txm.p.DB(), []*components.ReceiptInput{
		{TransactionID: txID, ReceiptType: components.ReceiptType(42)},
	}, false)
	assert.Regexp(t, "PD012213", err)

}

func TestFinalizeTransactionsFailedWithMessageNoMessage(t *testing.T) {

	txID := uuid.New()
	ctx, txm, done := newTestTransactionManager(t, false, func(conf *config.TxManagerConfig, mc *mockComponents) {
		mc.db.ExpectQuery("SELECT.*transactions").WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(txID))
	})
	defer done()

	err := txm.FinalizeTransactions(ctx, txm.p.DB(), []*components.ReceiptInput{
		{TransactionID: txID, ReceiptType: components.RT_FailedWithMessage},
	}, false)
	assert.Regexp(t, "PD012213", err)

}

func TestFinalizeTransactionsFailedWithRevertDataWithMessage(t *testing.T) {

	txID := uuid.New()
	ctx, txm, done := newTestTransactionManager(t, false, func(conf *config.TxManagerConfig, mc *mockComponents) {
		mc.db.ExpectQuery("SELECT.*transactions").WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(txID))
	})
	defer done()

	err := txm.FinalizeTransactions(ctx, txm.p.DB(), []*components.ReceiptInput{
		{TransactionID: txID, ReceiptType: components.RT_FailedOnChainWithRevertData,
			FailureMessage: "not empty"},
	}, false)
	assert.Regexp(t, "PD012213", err)

}

func TestFinalizeTransactionsInsertFail(t *testing.T) {

	txID := uuid.New()
	ctx, txm, done := newTestTransactionManager(t, false, func(conf *config.TxManagerConfig, mc *mockComponents) {
		mc.db.ExpectBegin()
		mc.db.ExpectQuery("SELECT.*transactions").WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(txID))
		mc.db.ExpectExec("INSERT.*transaction_receipts").WillReturnError(fmt.Errorf("pop"))
	})
	defer done()

	err := txm.p.DB().Transaction(func(tx *gorm.DB) error {
		return txm.FinalizeTransactions(ctx, tx, []*components.ReceiptInput{
			{TransactionID: txID, ReceiptType: components.RT_FailedWithMessage,
				FailureMessage: "something went wrong"},
		}, false)
	})
	assert.Regexp(t, "pop", err)

}

func TestFinalizeTransactionsIgnoreUnknown(t *testing.T) {

	ctx, txm, done := newTestTransactionManager(t, false, func(conf *config.TxManagerConfig, mc *mockComponents) {
		mc.db.ExpectQuery("SELECT.*transactions").WillReturnRows(sqlmock.NewRows([]string{"id"}))
	})
	defer done()

	err := txm.FinalizeTransactions(ctx, txm.p.DB(), []*components.ReceiptInput{
		{TransactionID: uuid.New(), ReceiptType: components.RT_FailedOnChainWithRevertData,
			FailureMessage: "will be ignored"},
	}, false)
	assert.NoError(t, err)

}

func TestCalculateRevertErrorNoData(t *testing.T) {

	ctx, txm, done := newTestTransactionManager(t, false)
	defer done()

	err := txm.CalculateRevertError(ctx, nil, nil)
	assert.Regexp(t, "PD012214", err)

}

func TestCalculateRevertErrorQueryFail(t *testing.T) {

	ctx, txm, done := newTestTransactionManager(t, false, func(conf *config.TxManagerConfig, mc *mockComponents) {
		mc.db.ExpectQuery("SELECT.*abi_errors").WillReturnError(fmt.Errorf("pop"))
	})
	defer done()

	err := txm.CalculateRevertError(ctx, txm.p.DB(), []byte("any data"))
	assert.Regexp(t, "PD012215.*pop", err)

}

func TestCalculateRevertErrorDecodeFail(t *testing.T) {

	ctx, txm, done := newTestTransactionManager(t, false, func(conf *config.TxManagerConfig, mc *mockComponents) {
		mc.db.ExpectQuery("SELECT.*abi_errors").WillReturnRows(sqlmock.NewRows([]string{"definition"}).AddRow(`{}`))
	})
	defer done()

	err := txm.CalculateRevertError(ctx, txm.p.DB(), []byte("any data"))
	assert.Regexp(t, "PD012215", err)

}

func TestGetTransactionReceiptNoResult(t *testing.T) {

	ctx, txm, done := newTestTransactionManager(t, false, func(conf *config.TxManagerConfig, mc *mockComponents) {
		mc.db.ExpectQuery("SELECT.*transaction_receipts").WillReturnRows(sqlmock.NewRows([]string{}))
	})
	defer done()

	res, err := txm.getTransactionReceiptByID(ctx, uuid.New())
	assert.NoError(t, err)
	assert.Nil(t, res)

}
