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

package persistence

import (
	"context"
	"database/sql/driver"
	"fmt"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	gormPostgres "gorm.io/driver/postgres"
	"gorm.io/gorm"
)

func TestTransactionOk(t *testing.T) {
	ctx := context.Background()

	db, mdb, _ := sqlmock.New()

	preCommitCalled := false
	finalizerCalled := false
	postCommitCalled := false

	mdb.ExpectBegin()
	mdb.ExpectExec("INSERT.*a_table").WillReturnResult(driver.ResultNoRows)
	mdb.ExpectExec("INSERT.*b_table").WillReturnResult(driver.ResultNoRows)
	mdb.ExpectCommit()

	gdb, err := gorm.Open(gormPostgres.New(gormPostgres.Config{Conn: db}), &gorm.Config{})
	require.NoError(t, err)
	err = Transaction(ctx, gdb, func(tx DBTX) error {
		err := tx.DB().Exec("INSERT INPUT a_table (col1) VALUES ('abc');").Error
		require.NoError(t, err)
		tx.AddPreCommit(func(preCommitTX DBTX) error {
			preCommitCalled = true
			err := preCommitTX.DB().Exec("INSERT INPUT b_table (col1) VALUES ('def');").Error
			require.Same(t, tx, preCommitTX)
			require.NoError(t, err)
			return nil
		})
		tx.AddFinalizer(func(err error) {
			require.Nil(t, err)
			finalizerCalled = true
		})
		tx.AddPostCommit(func() {
			postCommitCalled = true
		})
		return nil
	})
	require.NoError(t, err)

	require.True(t, preCommitCalled)
	require.True(t, finalizerCalled)
	require.True(t, postCommitCalled)

	require.NoError(t, mdb.ExpectationsWereMet())
}

func TestTransactionPreCommitErr(t *testing.T) {
	ctx := context.Background()

	db, mdb, _ := sqlmock.New()

	preCommitCalled := false
	finalizerCalled := false
	postCommitCalled := false

	mdb.ExpectBegin()
	mdb.ExpectExec("INSERT.*a_table").WillReturnResult(driver.ResultNoRows)
	mdb.ExpectRollback()

	gdb, err := gorm.Open(gormPostgres.New(gormPostgres.Config{Conn: db}), &gorm.Config{})
	require.NoError(t, err)
	err = Transaction(ctx, gdb, func(tx DBTX) error {
		err := tx.DB().Exec("INSERT INPUT a_table (col1) VALUES ('abc');").Error
		require.NoError(t, err)
		tx.AddPreCommit(func(preCommitTX DBTX) error {
			preCommitCalled = true
			return fmt.Errorf("pop")
		})
		tx.AddFinalizer(func(err error) {
			require.Regexp(t, "pop", err)
			finalizerCalled = true
		})
		tx.AddPostCommit(func() {
			postCommitCalled = true
		})
		return nil
	})
	require.Regexp(t, "pop", err)

	require.True(t, preCommitCalled)
	require.True(t, finalizerCalled)
	require.False(t, postCommitCalled) // post-commit should not be called

	require.NoError(t, mdb.ExpectationsWereMet())
}

func TestTransactionPanic(t *testing.T) {
	ctx := context.Background()

	db, mdb, _ := sqlmock.New()

	preCommitCalled := false
	finalizerCalled := false
	postCommitCalled := false

	mdb.ExpectBegin()
	mdb.ExpectRollback()

	assert.Panics(t, func() {
		gdb, err := gorm.Open(gormPostgres.New(gormPostgres.Config{Conn: db}), &gorm.Config{})
		require.NoError(t, err)
		err = Transaction(ctx, gdb, func(tx DBTX) error {
			tx.AddPreCommit(func(preCommitTX DBTX) error {
				preCommitCalled = true
				return nil
			})
			tx.AddFinalizer(func(err error) {
				require.Regexp(t, "pop", err)
				finalizerCalled = true
			})
			tx.AddPostCommit(func() {
				postCommitCalled = true
			})
			panic("pop")
		})
		require.Regexp(t, "pop", err)
	})

	require.True(t, finalizerCalled)
	require.False(t, preCommitCalled)
	require.False(t, postCommitCalled) // post-commit should not be called

	require.NoError(t, mdb.ExpectationsWereMet())
}
