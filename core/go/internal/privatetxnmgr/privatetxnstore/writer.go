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

	"github.com/kaleido-io/paladin/core/internal/flushwriter"

	"gorm.io/gorm"

	"github.com/kaleido-io/paladin/toolkit/pkg/log"
	"github.com/kaleido-io/paladin/toolkit/pkg/tktypes"
)

/*
Dispatching a transaction to the baseledger transaction manager is a point of no return and as part
of the hand over, we must get some assurance from the baseledger transaction manager that ordering will
be preserved.  So, we need to have the nonce allocated and written to the baseledger transaction manager's
database table in the same database transaction as the we update the state of the private transaction
table to record the dispatch. It would be a bottleneck on performance if we were to create a new database
transaction for each transaction that is dispatched given that there could be many hundreds, or even thousands
per second across all smart contract domains.  So we have a flush worker pattern here where a small number (relative to
the number of transaction processing threads ) of worker threads batch up several transactions across multiple
domain instances and run the database update for the dispatch and call the baseledger transaction manager
to atomically allocate and record the nonce under that same transaction.
*/

// the submit will happen on the user transaction manager's flush writer context so
// that it can be co-ordinated with the user transaction submission
// do we have any other checkpoints (e.g. on delegate?)

// a syncPointOperation is either a dispatch (handover to public transaction manager)
// or a finalizer (handover to TxManager to mark a transaction as reverted)
// never both.  We probably could make the mutual exclusive nature more explicit by using interfaces but its not worth the added complexity

type syncPointOperation struct {
	contractAddress   tktypes.EthAddress
	finalizeOperation *finalizeOperation
	dispatchOperation *dispatchOperation
}

func (dso *syncPointOperation) WriteKey() string {
	return dso.contractAddress.String()
}

type noResult struct{}

func (s *store) runBatch(ctx context.Context, dbTX *gorm.DB, values []*syncPointOperation) ([]flushwriter.Result[*noResult], error) {

	finalizeOperations := make([]*finalizeOperation, 0, len(values))
	dispatchOperations := make([]*dispatchOperation, 0, len(values))

	for _, op := range values {
		if op.finalizeOperation != nil {
			finalizeOperations = append(finalizeOperations, op.finalizeOperation)
		}
		if op.dispatchOperation != nil {
			dispatchOperations = append(dispatchOperations, op.dispatchOperation)
		}
	}

	// If we have any finalizers, we need to call them now
	//big assumption here that all operations in the batch have the same `contractAddress` which happens to be a safe
	// assumption at time of coding because WriteKey returns the contract address
	// but probably should consider a less brittle way to codify this assertion
	if len(finalizeOperations) > 0 {
		err := s.writeFinalizeOperations(ctx, dbTX, values[0].contractAddress, finalizeOperations)
		if err != nil {
			log.L(ctx).Errorf("Error persisting finalizers: %s", err)
			return nil, err
		}
	}

	if len(dispatchOperations) > 0 {
		err := s.writeDispatchOperations(ctx, dbTX, dispatchOperations)
		if err != nil {
			log.L(ctx).Errorf("Error persisting finalizers: %s", err)
			return nil, err
		}
	}

	// We don't actually provide any result, so just build an array of nil results
	return make([]flushwriter.Result[*noResult], len(values)), nil

}
