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

package publictxstore

import (
	"context"
	"fmt"
	"hash/fnv"
	"time"

	"github.com/kaleido-io/paladin/core/internal/msgs"
	"github.com/kaleido-io/paladin/core/internal/statestore"
	"github.com/kaleido-io/paladin/core/pkg/persistence"
	"gorm.io/gorm"

	"github.com/kaleido-io/paladin/toolkit/pkg/confutil"
	"github.com/kaleido-io/paladin/toolkit/pkg/tktypes"

	"github.com/hyperledger/firefly-common/pkg/i18n"
	"github.com/kaleido-io/paladin/toolkit/pkg/log"
)

var pubTxWriterConfigDefaults = statestore.DBWriterConfig{
	WorkerCount:  confutil.P(10),
	BatchTimeout: confutil.P("25ms"),
	BatchMaxSize: confutil.P(100),
}

type writeOperation struct {
	id         string
	done       chan error
	isShutdown bool
	tx         *PublicTransaction
}

type pubTxWriter struct {
	p            persistence.Persistence
	bgCtx        context.Context
	cancelCtx    context.CancelFunc
	batchTimeout time.Duration
	batchMaxSize int
	workerCount  uint32
	workQueues   []chan *writeOperation
	workersDone  []chan struct{}
}

type stateWriterBatch struct {
	id             string
	opened         time.Time
	ops            []*writeOperation
	timeoutContext context.Context
	timeoutCancel  func()
}

func newPubTxWriter(bgCtx context.Context, conf *statestore.DBWriterConfig) *pubTxWriter {
	workerCount := confutil.IntMin(conf.WorkerCount, 1, *pubTxWriterConfigDefaults.WorkerCount)
	batchMaxSize := confutil.IntMin(conf.BatchMaxSize, 1, *pubTxWriterConfigDefaults.BatchMaxSize)
	batchTimeout := confutil.DurationMin(conf.BatchTimeout, 0, *pubTxWriterConfigDefaults.BatchTimeout)
	sw := &pubTxWriter{
		workerCount:  (uint32)(workerCount),
		batchTimeout: batchTimeout,
		batchMaxSize: batchMaxSize,
		workersDone:  make([]chan struct{}, workerCount),
		workQueues:   make([]chan *writeOperation, workerCount),
	}
	sw.bgCtx, sw.cancelCtx = context.WithCancel(bgCtx)
	for i := 0; i < workerCount; i++ {
		sw.workersDone[i] = make(chan struct{})
		sw.workQueues[i] = make(chan *writeOperation, batchMaxSize)
		go sw.worker(i)
	}
	return sw
}

func (sw *pubTxWriter) newWriteOp(tx *PublicTransaction) *writeOperation {
	return &writeOperation{
		id:   tktypes.ShortID(),
		tx:   tx,
		done: make(chan error, 1), // 1 slot to ensure we don't block the writer
	}
}

// func (op *writeOperation) flush(ctx context.Context) error {
// 	select {
// 	case err := <-op.done:
// 		log.L(ctx).Debugf("Flushed write operation %s (err=%v)", op.id, err)
// 		return err
// 	case <-ctx.Done():
// 		return i18n.NewError(ctx, msgs.MsgContextCanceled)
// 	}
// }

func (sw *pubTxWriter) queue(ctx context.Context, op *writeOperation) {
	// All insert/nonce-allocation requests for the same domain go to the same worker
	// currently. This allows assertions to be made between threads writing schemas,
	// threads writing state updates, and threads writing new states.
	if op.tx == nil {
		op.done <- i18n.NewError(ctx, msgs.MsgStateOpInvalid)
		return
	}
	h := fnv.New32a() // simple non-cryptographic hash algo
	_, _ = h.Write([]byte(op.tx.ID.String()))
	routine := h.Sum32() % sw.workerCount
	log.L(ctx).Debugf("Queuing write operation %s to worker state_writer_%.4d", op.id, routine)
	select {
	case sw.workQueues[routine] <- op: // it's queued
	case <-ctx.Done(): // timeout of caller context
		// Just return, as they are giving up on the request so there's no need to queue it
		// If they flush they will get an error
	case <-sw.bgCtx.Done(): // shutdown
		// Push an error back to the operator before we return (note we allocate a slot to make this safe)
		op.done <- i18n.NewError(ctx, msgs.MsgStateManagerQuiescing)
	}
}

func (sw *pubTxWriter) worker(i int) {
	defer close(sw.workersDone[i])
	workerID := fmt.Sprintf("state_writer_%.4d", i)
	ctx := log.WithLogField(sw.bgCtx, "job", workerID)
	l := log.L(ctx)
	var batch *stateWriterBatch
	batchCount := 0
	workQueue := sw.workQueues[i]
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
				batch = &stateWriterBatch{
					id:     fmt.Sprintf("%.4d_%.9d", i, batchCount),
					opened: time.Now(),
				}
				batch.timeoutContext, batch.timeoutCancel = context.WithTimeout(ctx, sw.batchTimeout)
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

		if batch != nil && (timedOut || (len(batch.ops) >= sw.batchMaxSize)) {
			batch.timeoutCancel()
			l.Debugf("Running batch %s (len=%d,timeout=%t,age=%dms)", batch.id, len(batch.ops), timedOut, time.Since(batch.opened).Milliseconds())
			sw.runBatch(ctx, batch)
			batch = nil
		}

		if shutdownRequest != nil {
			close(shutdownRequest.done)
		}
	}
}

func (sw *pubTxWriter) runBatch(ctx context.Context, b *stateWriterBatch) {

	// Build lists of things to insert (we are insert only)
	var pubTxs []*PublicTransaction
	var pubTxHashes []*PublicTransactionHash
	for _, op := range b.ops {
		tx := op.tx
		pubTxs = append(pubTxs, tx)
		pubTxHashes = append(pubTxHashes, tx.SubmittedHashes...)

	}
	log.L(ctx).Debugf("Writing txs batch txs=%d, hashes=%d", len(pubTxs), len(pubTxHashes))

	err := sw.p.DB().Transaction(func(tx *gorm.DB) (err error) {
		if len(pubTxs) > 0 {
			err = tx.
				Table("public_transactions").Omit("SubmittedHashes").
				Create(pubTxs).
				Error
		}
		if len(pubTxHashes) > 0 {
			err = tx.
				Table("public_transaction_hashes").
				Create(pubTxHashes).
				Error
		}
		return err
	})

	// Mark all the ops complete - for good or bad
	for _, op := range b.ops {
		op.done <- err
	}
}

func (sw *pubTxWriter) stop() {
	for i, workerDone := range sw.workersDone {
		select {
		case <-workerDone:
		case <-sw.bgCtx.Done():
		default:
			// Quiesce the worker
			shutdownOp := &writeOperation{
				isShutdown: true,
				done:       make(chan error),
			}
			sw.workQueues[i] <- shutdownOp
			<-shutdownOp.done
		}
		<-workerDone
	}
	sw.cancelCtx()
}
