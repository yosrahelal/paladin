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

package components

import (
	"context"

	"github.com/kaleido-io/paladin/toolkit/pkg/tktypes"
	"gorm.io/gorm"
)

type PublicTX struct {
	ID              string             `json:"id"`
	SubmittedHashes []*tktypes.Bytes32 `json:"submittedHashes,omitempty"`
}

type PublicTxRequestOptions struct {
	SignerID string
}

type PublicTxPreparedSubmission interface {
	ID() string
	CleanUp(context.Context)
	Finalize(context.Context)
}

type PublicTxManager interface {
	ManagerLifecycle

	//Syncronous functions that are executed on the callers thread
	PrepareSubmissionBatch(ctx context.Context, reqOptions *PublicTxRequestOptions, txPayloads []interface{}) (preparedSubmission []PublicTxPreparedSubmission, submissionRejected bool, err error)
	SubmitBatch(ctx context.Context, tx *gorm.DB, preparedSubmissions []PublicTxPreparedSubmission) ([]*PublicTX, error)
}
