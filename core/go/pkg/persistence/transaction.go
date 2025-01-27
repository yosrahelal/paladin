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
	"runtime/debug"

	"github.com/hyperledger/firefly-common/pkg/i18n"
	"github.com/kaleido-io/paladin/core/internal/msgs"
	"github.com/kaleido-io/paladin/toolkit/pkg/log"
	"gorm.io/gorm"
)

type DBTX interface {
	// Access the Gorm DB object for the transaction
	DB() *gorm.DB
	// Functions to be run at the end of the transaction, before it has committed. An error from these will cause a rollback of the transaction itself
	AddPreCommit(func(tx DBTX) error)
	// Only called after a transaction is successfully committed - useful for triggering other actions that are conditional on new data
	AddPostCommit(func())
	// Called in all cases (including panic cases) AFTER the transaction commits, to release resources. An error indicates the transaction rolled back. Can be used as a post-commit too by checking err==nil.
	AddFinalizer(func(error))
}

type transaction struct {
	db          *gorm.DB
	preCommits  []func(tx DBTX) error
	postCommits []func()
	finalizers  []func(error)
}

func (t *transaction) DB() *gorm.DB {
	return t.db
}

func (t *transaction) AddPreCommit(fn func(tx DBTX) error) {
	t.preCommits = append(t.preCommits, fn)
}

func (t *transaction) AddPostCommit(fn func()) {
	t.postCommits = append(t.postCommits, fn)
}

func (t *transaction) AddFinalizer(fn func(error)) {
	t.finalizers = append(t.finalizers, fn)
}

// Run a transaction with preCommit, postCommit and finalizer support to propagate between components in a simple and consistent way.
func Transaction(ctx context.Context, db *gorm.DB, fn func(tx DBTX) error) (err error) {

	completed := false
	tx := &transaction{}
	defer func() {
		if !completed {
			log.L(ctx).Errorf("Panic within database transaction: %s", debug.Stack())
			if err == nil {
				err = i18n.NewError(ctx, msgs.MsgPersistenceErrorInDBTransaction, recover())
			}
		}
		for _, fn := range tx.finalizers {
			// Finalizers are called with success or failure
			fn(err)
		}
		if err == nil {
			for _, fn := range tx.postCommits {
				fn()
			}
		}
		if !completed {
			panic(err) // having logged this, we continue to panic rather than switching to normal error handling
		}
	}()

	// Run the database transaction itself
	err = db.Transaction(func(gormTX *gorm.DB) error {
		tx.db = gormTX
		innerErr := fn(tx)
		for _, fn := range tx.preCommits {
			if innerErr == nil {
				innerErr = fn(tx)
			}
		}
		return innerErr
	})

	completed = true
	return err // important that this is the function var used in the defer processing

}
