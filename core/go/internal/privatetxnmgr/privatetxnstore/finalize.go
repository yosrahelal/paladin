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

package privatetxnstore

import (
	"context"

	"github.com/google/uuid"
	"github.com/kaleido-io/paladin/core/internal/components"
	"github.com/kaleido-io/paladin/toolkit/pkg/tktypes"
	"gorm.io/gorm"
)

// a transaction finalization operation is an update to the transaction managers tables
// to record a failed transaction.  nothing gets written to any tables owned by the private transaction manager
// but the write is coordinated by our flush writer to minimize the number of database transactions
type TransactionFinalizer struct {
	TransactionID  uuid.UUID
	FailureMessage string
}

// QueueTransactionFinalize
func (s *store) QueueTransactionFinalize(ctx context.Context, contractAddress tktypes.EthAddress, finalizer *TransactionFinalizer, onCommit func(context.Context), onRollback func(context.Context, error)) {

	op := s.writer.Queue(ctx, &dispatchSequenceOperation{
		contractAddress: contractAddress,
		finalizer:       finalizer,
	})
	go func() {
		if _, err := op.WaitFlushed(ctx); err != nil {
			onRollback(ctx, err)
		} else {
			onCommit(ctx)
		}
	}()

}

func (s *store) writeTransactionFinalizerBatch(ctx context.Context, dbTX *gorm.DB, contractAddress tktypes.EthAddress, finalizers []*TransactionFinalizer) error {
	receipts := make([]*components.ReceiptInput, len(finalizers))
	for i, finalizer := range finalizers {
		receipts[i] = &components.ReceiptInput{
			ReceiptType:     components.RT_FailedWithMessage,
			ContractAddress: &contractAddress,
			TransactionID:   finalizer.TransactionID,
			FailureMessage:  finalizer.FailureMessage,
		}
	}

	return s.txMgr.FinalizeTransactions(ctx, dbTX, receipts)
}
