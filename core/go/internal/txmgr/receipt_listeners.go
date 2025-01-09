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
	"context"
	"encoding/json"
	"sync"

	"github.com/google/uuid"
	"github.com/hyperledger/firefly-common/pkg/i18n"
	"github.com/kaleido-io/paladin/core/internal/components"
	"github.com/kaleido-io/paladin/core/internal/msgs"
	"github.com/kaleido-io/paladin/toolkit/pkg/log"
	"github.com/kaleido-io/paladin/toolkit/pkg/pldapi"
	"github.com/kaleido-io/paladin/toolkit/pkg/tktypes"
	"gorm.io/gorm"
)

type persistedReceiptListener struct {
	Name    string          `gorm:"column:name"`
	Filters tktypes.RawJSON `gorm:"column:options"`
	Options tktypes.RawJSON `gorm:"column:options"`
}

func (persistedReceiptListener) TableName() string {
	return "transaction_receipt_listeners"
}

type persistedReceiptCheckpoint struct {
	Listener string `gorm:"column:listener"`
	Sequence uint64 `gorm:"column:sequence"`
}

func (persistedReceiptCheckpoint) TableName() string {
	return "transaction_receipt_checkpoints"
}

type persistedReceiptBlock struct {
	Listener    string              `gorm:"column:listener"`
	Source      *tktypes.EthAddress `gorm:"column:source"`
	Transaction uuid.UUID           `gorm:"column:transaction"`
}

func (persistedReceiptBlock) TableName() string {
	return "transaction_receipt_checkpoints"
}

type receiptListener struct {
	tm *txManager

	ctx       context.Context
	cancelCtx context.CancelFunc

	spec       *pldapi.TransactionReceiptListener
	checkpoint *uint64

	newReceipts chan bool

	newReceivers chan bool
	receiverLock sync.Mutex
	receivers    []components.ReceiptReceiver
	done         chan struct{}
}

type receiptDeliveryBatch struct {
	ID       uint64
	Receipts []*pldapi.TransactionReceiptFull
	Blocks   []*persistedReceiptBlock
}

func (tm *txManager) loadReceiptListeners(ctx context.Context) error {

	var lastPageEnd *string
	const loadPageSize = 100
	for {

		var page []*persistedReceiptListener
		q := tm.p.DB().
			WithContext(ctx).
			Order("name").
			Limit(loadPageSize)
		if lastPageEnd != nil {
			q = q.Where("name > ?", *lastPageEnd)
		}
		if err := q.Find(&page).Error; err != nil {
			return err
		}

		for _, pl := range page {
			if _, err := tm.loadListener(ctx, pl); err != nil {
				return err
			}
		}

		if len(page) < loadPageSize {
			log.L(ctx).Infof("loaded %d receipted listeners", len(tm.receiptListeners))
			return nil
		}

		lastPageEnd = &page[len(page)-1].Name
	}

}

func (tm *txManager) validateListenerSpec(ctx context.Context, spec *pldapi.TransactionReceiptListener) error {
	if err := tktypes.ValidateSafeCharsStartEndAlphaNum(ctx, spec.Name, tktypes.DefaultNameMaxLen, "name"); err != nil {
		return err
	}
	icrb, err := spec.Options.IncompleteStateReceiptBehavior.Validate()
	if err != nil {
		return err
	}
	spec.Options.IncompleteStateReceiptBehavior = icrb.Enum()
	_, err = tm.buildListenerDBQuery(ctx, spec, tm.p.DB())
	return err
}

func (tm *txManager) buildListenerDBQuery(ctx context.Context, spec *pldapi.TransactionReceiptListener, dbTX *gorm.DB) (*gorm.DB, error) {
	q := dbTX
	switch spec.Filters.Type.V() {
	case pldapi.TransactionTypePrivate:
		if spec.Filters.Domain != "" {
			q = q.Where("domain = ?", spec.Filters.Domain) // specific private domain
		} else {
			q = q.Where("domain <> ''") // private
		}
	case pldapi.TransactionTypePublic:
		if spec.Filters.Domain != "" {
			return nil, i18n.NewError(ctx, msgs.MsgTxMgrBadReceiptListenerTypeDomain, spec.Name, spec.Filters.Type, spec.Filters.Domain)
		}
		q = q.Where("domain = ''") // private
	case "":
	default:
		return nil, i18n.NewError(ctx, msgs.MsgTxMgrBadReceiptListenerTypeDomain, spec.Name, spec.Filters.Type, spec.Filters.Domain)
	}
	q = q.Order("sequence").Limit(tm.receiptsReadPageSize)
	// Only return non-blocked sequences
	q = q.Joins(`Block WHERE "Block"."listener" = ?`, spec.Name)
	q = q.Where(`"Block"."transaction" IS NULL`)
	return q, nil
}

func (tm *txManager) loadListener(ctx context.Context, pl *persistedReceiptListener) (*receiptListener, error) {
	spec := &pldapi.TransactionReceiptListener{
		Name: pl.Name,
	}
	if err := json.Unmarshal(pl.Filters, &spec.Filters); err != nil {
		return nil, i18n.WrapError(ctx, err, msgs.MsgTxMgrBadReceiptListenerFilter, pl.Name)
	}
	if err := json.Unmarshal(pl.Filters, &spec.Options); err != nil {
		return nil, i18n.WrapError(ctx, err, msgs.MsgTxMgrBadReceiptListenerOptions, pl.Name)
	}
	if err := tm.validateListenerSpec(ctx, spec); err != nil {
		return nil, err
	}
	l := &receiptListener{
		tm:          tm,
		spec:        spec,
		newReceipts: make(chan bool, 1),
	}

	tm.receiptListenerLock.Lock()
	defer tm.receiptListenerLock.Unlock()
	if tm.receiptListeners[pl.Name] != nil {
		return nil, i18n.NewError(ctx, msgs.MsgTxMgrReceiptListenerDupLoad, pl.Name)
	}
	tm.receiptListeners[pl.Name] = l
	return l, nil
}

func (l *receiptListener) start(bgCtx context.Context) {
	if l.done == nil {
		l.ctx, l.cancelCtx = context.WithCancel(log.WithLogField(bgCtx, "receipt-listener", l.spec.Name))
		l.done = make(chan struct{})
		go l.runListener()
	}
}

func (l *receiptListener) stop() {
	if l.done != nil {
		l.cancelCtx()
		<-l.done
		l.done = nil
	}
}

func (l *receiptListener) notifyNewReceipts() {
	select {
	case l.newReceipts <- true:
	default:
	}
}

func (l *receiptListener) addReceiver(r components.ReceiptReceiver) {
	l.receiverLock.Lock()
	defer l.receiverLock.Unlock()

	l.receivers = append(l.receivers, r)
	select {
	case l.newReceivers <- true:
	default:
	}
}

func (l *receiptListener) removeReceiver(r components.ReceiptReceiver) {
	l.receiverLock.Lock()
	defer l.receiverLock.Unlock()

	if len(l.receivers) > 0 {
		newReceivers := make([]components.ReceiptReceiver, len(l.receivers)-1)
		for _, existing := range l.receivers {
			if existing != r {
				newReceivers = append(newReceivers, existing)
			}
		}
		l.receivers = newReceivers
	}
}

func (l *receiptListener) loadCheckpoint() error {
	var checkpoints []*persistedReceiptCheckpoint
	err := l.tm.receiptsRetry.Do(l.ctx, func(attempt int) (retryable bool, err error) {
		return true, l.tm.p.DB().
			WithContext(l.ctx).
			Where("listener = ?", l.spec.Name).
			Limit(1).
			Find(&checkpoints).
			Error
	})
	if err != nil {
		return err // context cancelled
	}
	if len(checkpoints) == 0 {
		if l.spec.Filters.MinSequence != nil {
			l.checkpoint = l.spec.Filters.MinSequence
			log.L(l.ctx).Infof("Started receipt listener with minSequence=%d", *l.checkpoint)
		} else {
			log.L(l.ctx).Infof("Started receipt listener from start of chain")
		}
	} else {
		cpSequence := checkpoints[0].Sequence
		l.checkpoint = &cpSequence
		log.L(l.ctx).Infof("Started receipt listener with checkpoint=%d", cpSequence)
	}
	return nil
}

func (l *receiptListener) readPage() ([]*transactionReceipt, error) {
	var receipts []*transactionReceipt
	err := l.tm.receiptsRetry.Do(l.ctx, func(attempt int) (retryable bool, err error) {
		q, err := l.tm.buildListenerDBQuery(l.ctx, l.spec, l.tm.p.DB())
		if err == nil && l.checkpoint != nil {
			q = q.Where("sequence > ?", *l.checkpoint)
		}
		if err == nil {
			err = q.Find(&receipts).Error
		}
		return true, err
	})
	return receipts, err
}

func (l *receiptListener) processPersistedReceipt(b *receiptDeliveryBatch, pr *transactionReceipt) error {
	// Build the full receipt
	fr, err := l.tm.buildFullReceipt(l.ctx, &pldapi.TransactionReceipt{
		ID:                     pr.TransactionID,
		TransactionReceiptData: *mapPersistedReceipt(pr),
	}, l.spec.Options.DomainReceipts)
	if err != nil {
		return err
	}
	// If we don't have the state receipt, and we're told to block, then block
	if fr.TransactionReceiptDataOnchainEvent != nil && fr.Domain != "" &&
		(fr.States == nil || fr.States.HasUnavailable()) &&
		l.spec.Options.IncompleteStateReceiptBehavior.V() == pldapi.IncompleteStateReceiptBehaviorBlockContract {
		log.L(l.ctx).Debugf("States currently unavailable for TXID %s in blockchain TX %s blocking contract %s", fr.ID, fr.TransactionHash, fr.Source)
		b.Blocks = append(b.Blocks, &persistedReceiptBlock{
			Listener:    l.spec.Name,
			Source:      &fr.Source,
			Transaction: fr.ID,
		})
		return nil
	}
	// Otherwise we can process the receipt
	log.L(l.ctx).Infof("Added receipt for TX %s (domain='%s') to batch %d", fr.ID, fr.Domain, b.ID)
	b.Receipts = append(b.Receipts, fr)
	return nil
}

func (l *receiptListener) nextReceiver(b *receiptDeliveryBatch) (r components.ReceiptReceiver, err error) {

	for {
		l.receiverLock.Lock()
		if len(l.receivers) > 0 {
			r = l.receivers[int(b.ID)%len(l.receivers)]
		}
		l.receiverLock.Unlock()

		if r != nil {
			return r, nil
		}

		select {
		case <-l.newReceivers:
		case <-l.ctx.Done():
			return nil, i18n.NewError(l.ctx, msgs.MsgContextCanceled)
		}
	}

}

func (l *receiptListener) deliverBatch(b *receiptDeliveryBatch) error {
	r, err := l.nextReceiver(b)
	if err != nil {
		return err
	}

	log.L(l.ctx).Infof("Delivering receipt batch %d (receipts=%d)", b.ID, len(b.Receipts))
	err = r.DeliverReceiptBatch(l.ctx, b.Receipts)
	log.L(l.ctx).Infof("Delivered receipt batch %d (err=%v)", b.ID, err)
	return err
}

func (l *receiptListener) runListener() {
	defer close(l.done)

	err := l.tm.receiptsRetry.Do(l.ctx, func(attempt int) (retryable bool, err error) {
		return true, l.loadCheckpoint()
	})
	if err != nil {
		log.L(l.ctx).Warnf("listener stopping before reading checkpoint: %s", err)
		return
	}

	var batchID uint64
	for {

		// Read the next page of receipts from non-blocked sources
		page, err := l.readPage()
		if err != nil {
			log.L(l.ctx).Warnf("listener stopping: %s", err) // cancelled context
			return
		}

		// Process each one building up a batch to process
		var batch receiptDeliveryBatch
		batch.ID = batchID
		batchID++
		for _, r := range page {
			err := l.tm.receiptsRetry.Do(l.ctx, func(attempt int) (retryable bool, err error) {
				return true, l.processPersistedReceipt(&batch, r)
			})
			if err != nil {
				log.L(l.ctx).Warnf("listener stopping (while processing receipts): %s", err)
				return
			}
		}

		// If our batch contains some work, we need to wait for someone to process that work
		// (note we're not holding any resource open at this point - no DB TX or anything).
		if len(batch.Receipts) > 0 {
			err := l.tm.receiptsRetry.Do(l.ctx, func(attempt int) (retryable bool, err error) {
				return true, l.deliverBatch(&batch)
			})
			if err != nil {
				log.L(l.ctx).Warnf("listener stopping (batch %d containing %d events not delivered): %s", batchID, len(batch.Receipts), err) // cancelled context
				return
			}
		}

	}
}
