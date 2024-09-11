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

package privatetxnmgr

import (
	"context"

	"github.com/kaleido-io/paladin/core/internal/components"
	"github.com/kaleido-io/paladin/core/pkg/proto/sequence"
	"github.com/kaleido-io/paladin/toolkit/pkg/prototk"
)

type EmitEvent func(ctx context.Context, event PrivateTransactionEvent)

type PrivateTransactionEvent interface {
	TransactionID() string
}

type privateTransactionEvent struct {
	transactionID string
}

func (e *privateTransactionEvent) TransactionID() string {
	return e.transactionID
}

type TransactionSubmittedEvent struct {
	privateTransactionEvent
	transaction *components.PrivateTransaction
}
type TransactionAssembledEvent struct {
	privateTransactionEvent
	sequence.TransactionAssembledEvent
}
type TransactionSignedEvent struct {
	privateTransactionEvent
	attestationResult *prototk.AttestationResult
}
type TransactionEndorsedEvent struct {
	privateTransactionEvent
	revertReason *string
	endorsement  *prototk.AttestationResult
}
type TransactionDispatchedEvent struct {
	privateTransactionEvent
}
type TransactionConfirmedEvent struct {
	privateTransactionEvent
}
type TransactionRevertedEvent struct {
	privateTransactionEvent
}
type TransactionDelegatedEvent struct {
	privateTransactionEvent
}
