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
	"testing"

	"github.com/kaleido-io/paladin/config/pkg/confutil"
	"github.com/kaleido-io/paladin/toolkit/pkg/pldapi"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestE2EListenerNoFiltersRealDB(t *testing.T) {
	ctx, txm, done := newTestTransactionManager(t, true)
	defer done()

	// Create listener in default (started)
	err := txm.CreateReceiptListener(ctx, &pldapi.TransactionReceiptListener{
		Name: "listener1",
	})
	require.NoError(t, err)

	// should be started
	l := txm.GetReceiptListener(ctx, "listener1")
	require.NotNil(t, l)
	assert.True(t, *l.Started)

	// delete listener
	err = txm.DeleteReceiptListener(ctx, "listener1")
	require.NoError(t, err)
	l = txm.GetReceiptListener(ctx, "listener1")
	require.Nil(t, l)

	// Create listener stopped
	err = txm.CreateReceiptListener(ctx, &pldapi.TransactionReceiptListener{
		Name:    "listener1",
		Started: confutil.P(false),
	})
	require.NoError(t, err)

	// should be stopped
	l = txm.GetReceiptListener(ctx, "listener1")
	require.NotNil(t, l)
	assert.False(t, *l.Started)

	// start it
	err = txm.StartReceiptListener(ctx, "listener1")
	require.NoError(t, err)

	// should be started
	l = txm.GetReceiptListener(ctx, "listener1")
	require.NotNil(t, l)
	assert.True(t, *l.Started)

	// stop it
	err = txm.StopReceiptListener(ctx, "listener1")
	require.NoError(t, err)

	// should be stopped
	l = txm.GetReceiptListener(ctx, "listener1")
	require.NotNil(t, l)
	assert.False(t, *l.Started)

	// Simulate restart so we can do startup processing
	txm.receiptsInit()

	// Force persistent state to be started
	err = txm.p.DB().Model(&persistedReceiptListener{}).
		Where("name = ?", "listener1").Update("started", true).Error
	require.NoError(t, err)

	// Load the listeners
	err = txm.loadReceiptListeners()
	require.NoError(t, err)

	// Check it's not actually started (yet)
	require.Nil(t, txm.receiptListeners["listener1"].done)

	// Do the startup
	txm.startReceiptListeners()

	// Check it's started now
	l = txm.GetReceiptListener(ctx, "listener1")
	require.NotNil(t, l)
	assert.True(t, *l.Started)

	// Check it's now actually started
	require.NotNil(t, txm.receiptListeners["listener1"].done)

}
