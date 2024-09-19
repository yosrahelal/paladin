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
	"fmt"
	"hash/fnv"
	"time"

	"github.com/google/uuid"
	"github.com/kaleido-io/paladin/core/internal/msgs"

	"github.com/kaleido-io/paladin/toolkit/pkg/confutil"
	"github.com/kaleido-io/paladin/toolkit/pkg/tktypes"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"

	"github.com/hyperledger/firefly-common/pkg/i18n"
	"github.com/kaleido-io/paladin/toolkit/pkg/log"
)

/*
Dispatching a transaction to the baseledger transaction manager is a point of no return and as part
of the hand over, we must get some assurance from the baseledger transaction manager that ordering will
be preserved.  So, we need to have the nonce allocated and written to the baseledger transaction manager's
database table in the same database transaction as the we update the state of the private transaction
table to record the dispatch. It would be a bottleneck on performance if we were to create a new database
transaction for each transaction that is dispatched given that there could be many hundreds, or even thousands
per second accross all smart contract domains.  So we have a flush worker pattern here where a small number (relative to
the number of transaction processing threads ) of worker threads batch up several transactions across multiple
domain instances and run the database update for the dispatch and call the baseledger transaction manager
to atomically allocate and record the nonce under that same transaction.
*/

// TODO do we need any other type of write other than dispatch?
// the submit will happen on the user transaction manager's flush writer context so
// that it can be co-ordinated with the user transaction submission
// do we have any other checkpoints (e.g. on delegate?)
type dispatchSequenceOperation struct {
	dispatches               []*DispatchPersisted
	publicTransactionsSubmit func() (publicTxID []string, err error)
}

type writeOperation struct {
	id                         string
	contractAddress            string
	done                       chan error
	isShutdown                 bool
	dispatchSequenceOperations []*dispatchSequenceOperation
}

type writer struct {
	store        *store
	bgCtx        context.Context
	cancelCtx    context.CancelFunc
	batchTimeout time.Duration
	batchMaxSize int
	workerCount  uint32
	workQueues   []chan *writeOperation
	workersDone  []chan struct{}
}

type writeOperationBatch struct {
	id             string
	opened         time.Time
	ops            []*writeOperation
	timeoutContext context.Context
	timeoutCancel  func()
}

func newWriter(bgCtx context.Context, s *store, conf *WriterConfig) *writer {
	workerCount := confutil.IntMin(conf.WorkerCount, 1, *WriterConfigDefaults.WorkerCount)
	batchMaxSize := confutil.IntMin(conf.BatchMaxSize, 1, *WriterConfigDefaults.BatchMaxSize)
	batchTimeout := confutil.DurationMin(conf.BatchTimeout, 0, *WriterConfigDefaults.BatchTimeout)
	w := &writer{
		store:        s,
		workerCount:  (uint32)(workerCount),
		batchTimeout: batchTimeout,
		batchMaxSize: batchMaxSize,
		workersDone:  make([]chan struct{}, workerCount),
		workQueues:   make([]chan *writeOperation, workerCount),
	}
	w.bgCtx, w.cancelCtx = context.WithCancel(bgCtx)
	for i := 0; i < workerCount; i++ {
		w.workersDone[i] = make(chan struct{})
		w.workQueues[i] = make(chan *writeOperation, batchMaxSize)
		go w.worker(i)
	}
	return w
}

func (w *writer) newWriteOp(contractAddress string) *writeOperation {
	return &writeOperation{
		id:              tktypes.ShortID(),
		contractAddress: contractAddress,
		done:            make(chan error, 1), // 1 slot to ensure we don't block the writer
	}
}

func (op *writeOperation) flush(ctx context.Context) error {
	select {
	case err := <-op.done:
		log.L(ctx).Debugf("Flushed write operation %s (err=%v)", op.id, err)
		return err
	case <-ctx.Done():
		return i18n.NewError(ctx, msgs.MsgContextCanceled)
	}
}

func (w *writer) queue(ctx context.Context, op *writeOperation) {
	// there can be several flush worker threads but significantly fewer than the number of
	// private contracts (domain instances) we would expect to be running concurrently
	// however we do need to maintain some affinity between any one domain instance and a worker thread
	// changing the number of worker threads will require a config change and a restart so no
	// need for dynamic balancing. A simple modulo of a hash will suffice.
	if op.contractAddress == "" {
		op.done <- i18n.NewError(ctx, msgs.MsgStateOpInvalid)
		return
	}
	h := fnv.New32a() // simple non-cryptographic hash algo
	_, _ = h.Write([]byte(op.contractAddress))
	routine := h.Sum32() % w.workerCount
	log.L(ctx).Debugf("Queuing write operation %s to worker state_writer_%.4d", op.id, routine)
	select {
	case w.workQueues[routine] <- op: // it's queued
	case <-ctx.Done(): // timeout of caller context
		// Just return, as they are giving up on the request so there's no need to queue it
		// If they flush they will get an error
	case <-w.bgCtx.Done(): // shutdown
		// Push an error back to the operator before we return (note we allocate a slot to make this safe)
		op.done <- i18n.NewError(ctx, msgs.MsgStateManagerQuiescing)
	}
}

func (w *writer) worker(i int) {
	defer close(w.workersDone[i])
	workerID := fmt.Sprintf("writer_%.4d", i)
	ctx := log.WithLogField(w.bgCtx, "job", workerID)
	l := log.L(ctx)
	var batch *writeOperationBatch
	batchCount := 0
	workQueue := w.workQueues[i]
	var shutdownRequest *writeOperation
	for shutdownRequest == nil {
		var timeoutContext context.Context
		var timedOut bool
		if batch != nil {
			timeoutContext = batch.timeoutContext
		} else {
			timeoutContext = ctx
		}
		select {
		case op := <-workQueue:
			if op.isShutdown {
				// flush out the queue
				shutdownRequest = op
				timedOut = true
				break
			}
			if batch == nil {
				batch = &writeOperationBatch{
					id:     fmt.Sprintf("%.4d_%.9d", i, batchCount),
					opened: time.Now(),
				}
				batch.timeoutContext, batch.timeoutCancel = context.WithTimeout(ctx, w.batchTimeout)
				batchCount++
			}
			batch.ops = append(batch.ops, op)
			l.Debugf("Added write operation %s to batch %s (len=%d)", op.id, batch.id, len(batch.ops))
		case <-timeoutContext.Done():
			timedOut = true
			select {
			case <-ctx.Done():
				l.Debugf("State writer ending")
				return
			default:
			}
		}

		if batch != nil && (timedOut || (len(batch.ops) >= w.batchMaxSize)) {
			batch.timeoutCancel()
			l.Debugf("Running batch %s (len=%d,timeout=%t,age=%dms)", batch.id, len(batch.ops), timedOut, time.Since(batch.opened).Milliseconds())
			w.runBatch(ctx, batch)
			batch = nil
		}

		if shutdownRequest != nil {
			close(shutdownRequest.done)
		}
	}
}

func (w *writer) runBatch(ctx context.Context, b *writeOperationBatch) {

	/*To reliably allocate a nonce in a gapless sequence without locking out a bunch of threads for too long and without gitting deadlocks:
	- Before we go into a database transaction, check that we have a fresh record of the latest nonce in memory for the given signing address - reading DB and/or calling out to the blockchain node if needed
	 - On the private transaction manager thread: take a lock on the nonce allocator for the signing address
	 - defer a call to release the lock with a rollback ( i.e. by default, if the stack unwinds, we don't change the "next" nonce value)
	 - send a message to the flush worker's channel to
	   		- allocate increment the next nonce (or nonces, depending on how many transactions are being dispatched for that signing address in that flush batch - noting that the same flush batch will be potentially processing transactions for multiple signign keys from multile private transaction manger threads)
			- write the records to both ( BLT manager and Private transaction manager) tables
	 - wait for the flush worker to complete the operation and release the lock with a rollforward (i.e. next reader to get the lock will see the new nonce value)
	   - NOTE we have held the lock for quite a long time by now so if any other private transaction manager threads are trying to get a nonce for the same signign key, then the are slowed down. But that's ok because we assume it is extremely rare that multiple private transaction managers will be trying to use the same signing key
	 - if the flush worker fails, and the DB transaction is rolled back we need to roll back the lock and the nonce value
	 	- is there a timeout on the private transaction manager thread waiting for the flush worker? If it hasn't signalled completion in time, do we assume failure? Do we read the database? If in doubt, we can tell the none allocator to refresh its cache by reading the DB and/or calling the blockchain node
	 - if the
	*/

	// For each operation in the batch, we need to call the baseledger transaction manager to allocate its nonce
	// which it can only guaranteed to be gapless and unique if it is done during the database transaction that inserts the dispatch record.
	// However, this is
	// Build lists of things to insert (we are insert only)

	err := w.store.p.DB().Transaction(func(tx *gorm.DB) (err error) {
		if len(b.ops) > 0 {
			for _, op := range b.ops {
				//for each batchSequence operation, call the public transaction manager to allocate a nonce
				for _, dispatchSequenceOp := range op.dispatchSequenceOperations {
					// Call the public transaction manager to allocate nonces for all transactions in the sequence
					// and persist them to the database under the current transaction
					publicTxIDs, err := dispatchSequenceOp.publicTransactionsSubmit()
					if err != nil {
						log.L(ctx).Errorf("Error submitting public transaction: %s", err)
						// TODO  this is a really bad situation because it will cause all dispatches in the flush to rollback
						// Should we skip this dispatch ( or this mini batch of dispatches?)
						return err
					}
					if len(publicTxIDs) != len(dispatchSequenceOp.dispatches) {
						errorMessage := fmt.Sprintf("Expected %d public transaction IDs, got %d", len(dispatchSequenceOp.dispatches), len(publicTxIDs))
						log.L(ctx).Errorf(errorMessage)
						return i18n.NewError(ctx, msgs.MsgEngineInternalError, errorMessage)
					}

					//TODO this results in an `INSERT` for each dispatchSequence
					//Would it be more efficient to pass an array for the whole flush?
					// could get complicated on the public transaction manager side because
					// it needs to allocate a nonce for each dispatch and that is specific to signing key
					for dispatchIndex, dispatch := range dispatchSequenceOp.dispatches {

						//fill in the foreign key before persisting in our dispatch table
						dispatch.PublicTransactionID = publicTxIDs[dispatchIndex]

						dispatch.ID = uuid.New().String()
					}
					log.L(ctx).Debugf("Writing dispatch batch %d", len(dispatchSequenceOp.dispatches))

					err = tx.
						Table("dispatches").
						Clauses(clause.OnConflict{
							Columns: []clause.Column{
								{Name: "private_transaction_id"},
								{Name: "public_transaction_id"},
							},
							DoNothing: true, // immutable
						}).
						Create(dispatchSequenceOp.dispatches).
						Error

					if err != nil {
						log.L(ctx).Errorf("Error persisting dispatches: %s", err)
						return err
					}

				}

			}

		}

		return err
	})

	// Mark all the ops complete - for good or bad
	for _, op := range b.ops {
		op.done <- err
	}
}

func (w *writer) stop() {
	for i, workerDone := range w.workersDone {
		select {
		case <-workerDone:
		case <-w.bgCtx.Done():
		default:
			// Quiesce the worker
			shutdownOp := &writeOperation{
				isShutdown: true,
				done:       make(chan error),
			}
			w.workQueues[i] <- shutdownOp
			<-shutdownOp.done
		}
		<-workerDone
	}
	w.cancelCtx()
}
