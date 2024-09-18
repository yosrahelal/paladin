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
	"sync"

	"github.com/google/uuid"
	"github.com/kaleido-io/paladin/toolkit/pkg/ptxapi"
	"github.com/kaleido-io/paladin/toolkit/pkg/tktypes"
)

type txStatusRecord struct {
	lock     sync.Mutex
	activity []ptxapi.TransactionActivityRecord
}

func (tm *txManager) getActivityRecords(tx uuid.UUID) []ptxapi.TransactionActivityRecord {
	txr, _ := tm.txCache.Get(tx)
	if txr != nil {
		// Snap the current activity array pointer in the lock and return it directly
		// (it does not get modified, only re-allocated on each update)
		txr.lock.Lock()
		defer txr.lock.Unlock()
		return txr.activity
	}
	return []ptxapi.TransactionActivityRecord{}
}

// add an activity record - this function assumes caller will not add multiple
func (tm *txManager) AddActivityRecord(tx uuid.UUID, msg string) {
	if tm.activityRecordsPerTX == 0 {
		return
	}
	txr, _ := tm.txCache.Get(tx)
	if txr == nil {
		txr = &txStatusRecord{}
		tm.txCache.Set(tx, txr)
	}
	// We add to the front of the list (newest record first) and cap the size
	txr.lock.Lock()
	defer txr.lock.Unlock()
	record := &ptxapi.TransactionActivityRecord{
		Time:    tktypes.TimestampNow(),
		Message: msg,
	}
	copyLen := len(txr.activity)
	if copyLen >= tm.activityRecordsPerTX {
		copyLen = tm.activityRecordsPerTX - 1
	}
	newActivity := make([]ptxapi.TransactionActivityRecord, copyLen+1)
	copy(newActivity[1:], txr.activity[0:copyLen])
	newActivity[0] = *record
	txr.activity = newActivity
}
