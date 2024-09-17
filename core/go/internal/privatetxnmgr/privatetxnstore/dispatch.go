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
)

type DispatchPersisted struct {
	ID                   string `json:"id"`
	PrivateTransactionID string `json:"privateTransactionID"`
	PublicTransactionID  string `json:"publicTransactionID"`
}

// A dispatch sequence is a collection of private transactions that are submitted together for a given signing address in order
type DispatchSequence struct {
	PrivateTransactionDispatches []*DispatchPersisted
	PublicTransactionsSubmit     func() (publicTxID []string, err error)
}

// a dispatch batch is a collection of dispatch sequences that are submitted together with no ordering requirements between sequences
// purely for a database performance reason, they are included in the same transaction
type DispatchBatch struct {
	DispatchSequences []*DispatchSequence
}

// PersistDispatches persists the dispatches to the store and coordinates with the public transaction manager
// to submit public transactions.
func (s *store) PersistDispatchBatch(ctx context.Context, dispatchBatch *DispatchBatch) error {
	op := s.writer.newWriteOp()
	op.dispatchSequenceOperations = make([]*dispatchSequenceOperation, len(dispatchBatch.DispatchSequences))
	for i, dispatchSequence := range dispatchBatch.DispatchSequences {
		//TODO why are we copying to a different struct rather than just expose this struct type on the function signature?
		dispatchSequenceOp := &dispatchSequenceOperation{
			dispatches:               dispatchSequence.PrivateTransactionDispatches,
			publicTransactionsSubmit: dispatchSequence.PublicTransactionsSubmit,
		}
		op.dispatchSequenceOperations[i] = dispatchSequenceOp
	}

	// Send the write operation with all of the batch sequence operations to the flush worker thread
	s.writer.queue(ctx, op)

	//wait for the flush to complete
	return op.flush(ctx)
}
