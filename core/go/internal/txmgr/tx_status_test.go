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

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
)

func TestAddActivityDisabled(t *testing.T) {
	_, txm, done := newTestTransactionManager(t, false)
	defer done()
	txm.activityRecordsPerTX = 0

	txID := uuid.New()
	txm.AddActivityRecord(txID, "message")

	assert.Empty(t, txm.getActivityRecords(txID))
}

func TestAddActivityWrap(t *testing.T) {
	_, txm, done := newTestTransactionManager(t, false)
	defer done()

	txID := uuid.New()
	for i := 0; i < 100; i++ {
		txm.AddActivityRecord(txID, fmt.Sprintf("message %.2d", i))
	}

	activityRecords := txm.getActivityRecords(txID)
	assert.Equal(t, "message 99", activityRecords[0].Message)
	assert.Equal(t, "message 98", activityRecords[1].Message)
	assert.Len(t, activityRecords, txm.activityRecordsPerTX)

}
