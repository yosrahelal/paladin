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
	"github.com/kaleido-io/paladin/config/pkg/confutil"
	"github.com/kaleido-io/paladin/config/pkg/pldconf"
	"github.com/kaleido-io/paladin/core/internal/components"
	"github.com/kaleido-io/paladin/core/internal/filters"
	"github.com/kaleido-io/paladin/core/internal/msgs"
	"github.com/kaleido-io/paladin/toolkit/pkg/log"
	"github.com/kaleido-io/paladin/toolkit/pkg/pldapi"
	"github.com/kaleido-io/paladin/toolkit/pkg/query"
	"github.com/kaleido-io/paladin/toolkit/pkg/retry"
	"github.com/kaleido-io/paladin/toolkit/pkg/tktypes"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

type persistedReceiptListener struct {
	Name    string            `gorm:"column:name"`
	Created tktypes.Timestamp `gorm:"column:created"`
	Started *bool             `gorm:"column:started"`
	Filters tktypes.RawJSON   `gorm:"column:filters"`
	Options tktypes.RawJSON   `gorm:"column:options"`
}

var receiptListenerFilters = filters.FieldMap{
	"name":    filters.StringField("name"),
	"created": filters.TimestampField("created"),
}

func (persistedReceiptListener) TableName() string {
	return "receipt_listeners"
}

type persistedReceiptCheckpoint struct {
	Listener string            `gorm:"column:listener"`
	Sequence uint64            `gorm:"column:sequence"`
	Time     tktypes.Timestamp `gorm:"column:time"`
}

func (persistedReceiptCheckpoint) TableName() string {
	return "receipt_listener_checkpoints"
}

type persistedReceiptBlock struct {
	Listener    string              `gorm:"column:listener"`
	Source      *tktypes.EthAddress `gorm:"column:source"`
	Transaction uuid.UUID           `gorm:"column:transaction"`
	Created     tktypes.Timestamp   `gorm:"column:created"`
}

func (persistedReceiptBlock) TableName() string {
	return "receipt_listener_blocks"
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
	receivers    []*registeredReceiptReceiver
	done         chan struct{}
}

type registeredReceiptReceiver struct {
	id uuid.UUID
	l  *receiptListener
	components.ReceiptReceiver
}

type receiptDeliveryBatch struct {
	ID       uint64
	Receipts []*pldapi.TransactionReceiptFull
	Blocks   []*persistedReceiptBlock
}

func (tm *txManager) receiptsInit() {
	tm.receiptsRetry = retry.NewRetryIndefinite(&tm.conf.ReceiptListeners.Retry, &pldconf.TxManagerDefaults.ReceiptListeners.Retry)
	tm.receiptsReadPageSize = confutil.IntMin(tm.conf.ReceiptListeners.ReadPageSize, 1, *pldconf.TxManagerDefaults.ReceiptListeners.ReadPageSize)
	tm.receiptListeners = make(map[string]*receiptListener)
	tm.receiptListenersLoadPageSize = 100 /* not currently tunable */

}

func (tm *txManager) CreateReceiptListener(ctx context.Context, spec *pldapi.TransactionReceiptListener) error {

	log.L(ctx).Infof("Creating receipt listener '%s'", spec.Name)
	if err := tm.validateListenerSpec(ctx, spec); err != nil {
		return err
	}

	started := (spec.Started == nil /* default is true */) || *spec.Started
	dbSpec := &persistedReceiptListener{
		Name:    spec.Name,
		Started: &started,
		Created: tktypes.TimestampNow(),
		Filters: tktypes.JSONString(&spec.Filters),
		Options: tktypes.JSONString(&spec.Options),
	}
	if insertErr := tm.p.DB().
		WithContext(ctx).
		Create(dbSpec).
		Error; insertErr != nil {

		log.L(ctx).Errorf("Failed to create receipt listener '%s': %s", spec.Name, insertErr)

		// Check for a simple duplicate object
		if existing := tm.GetReceiptListener(ctx, spec.Name); existing != nil {
			return i18n.NewError(ctx, msgs.MsgTxMgrDuplicateReceiptListenerName, spec.Name)
		}

		// Otherwise return the error
		return insertErr
	}

	// Load the created listener now - we do not expect (or attempt to reconcile) a post-validation failure to load
	l, err := tm.loadListener(ctx, dbSpec)
	if err == nil && *l.spec.Started {
		l.start()
	}
	return err
}

func (rr *registeredReceiptReceiver) Close() {
	rr.l.removeReceiver(rr.id)
}

func (tm *txManager) AddReceiptReceiver(ctx context.Context, name string, r components.ReceiptReceiver) (components.ReceiptReceiverCloser, error) {
	tm.receiptListenerLock.Lock()
	defer tm.receiptListenerLock.Unlock()

	l := tm.receiptListeners[name]
	if l == nil {
		return nil, i18n.NewError(ctx, msgs.MsgTxMgrReceiptListenerNotLoaded, name)
	}

	return l.addReceiver(r), nil
}

func (tm *txManager) GetReceiptListener(ctx context.Context, name string) *pldapi.TransactionReceiptListener {

	tm.receiptListenerLock.Lock()
	defer tm.receiptListenerLock.Unlock()

	l := tm.receiptListeners[name]
	if l != nil {
		return l.spec
	}
	return nil

}

func (tm *txManager) StartReceiptListener(ctx context.Context, name string) error {
	return tm.setReceiptListenerStatus(ctx, name, true)
}

func (tm *txManager) StopReceiptListener(ctx context.Context, name string) error {
	return tm.setReceiptListenerStatus(ctx, name, false)
}

func (tm *txManager) setReceiptListenerStatus(ctx context.Context, name string, started bool) error {
	tm.receiptListenerLock.Lock()
	defer tm.receiptListenerLock.Unlock()

	log.L(ctx).Infof("Setting receipt listener '%s' status. Started=%t", name, started)

	l := tm.receiptListeners[name]
	if l == nil {
		return i18n.NewError(ctx, msgs.MsgTxMgrReceiptListenerNotLoaded, name)
	}
	err := tm.p.DB().
		WithContext(ctx).
		Model(&persistedReceiptListener{}).
		Where("name = ?", name).
		Update("started", started).
		Error
	if err != nil {
		return err
	}
	l.spec.Started = &started
	if started {
		l.start()
	} else {
		l.stop()
	}
	return nil
}

func (tm *txManager) DeleteReceiptListener(ctx context.Context, name string) error {
	tm.receiptListenerLock.Lock()
	defer tm.receiptListenerLock.Unlock()

	l := tm.receiptListeners[name]
	if l == nil {
		return i18n.NewError(ctx, msgs.MsgTxMgrReceiptListenerNotLoaded, name)
	}

	l.stop()

	err := tm.p.DB().
		WithContext(ctx).
		Where("name = ?", name).
		Delete(&persistedReceiptListener{}).
		Error
	if err != nil {
		return err
	}

	delete(tm.receiptListeners, name)
	return nil
}

func (tm *txManager) QueryReceiptListeners(ctx context.Context, dbTX *gorm.DB, jq *query.QueryJSON) ([]*pldapi.TransactionReceiptListener, error) {
	qw := &queryWrapper[persistedReceiptListener, pldapi.TransactionReceiptListener]{
		p:           tm.p,
		table:       "receipt_listeners",
		defaultSort: "-created",
		filters:     receiptListenerFilters,
		query:       jq,
		mapResult: func(pl *persistedReceiptListener) (*pldapi.TransactionReceiptListener, error) {
			return tm.mapListener(ctx, pl)
		},
	}
	return qw.run(ctx, dbTX)
}

func (tm *txManager) notifyNewReceipts(receipts []*transactionReceipt) {
	log := log.L(tm.bgCtx)
	for _, l := range tm.getReceiptListenerList() {
		hasMatch := false
		for _, r := range receipts {
			if l.checkMatch(r) {
				log.Debugf("Receipt %s (domain='%s') triggering re-poll of listener '%s'", r.TransactionID, r.Domain, l.spec.Name)
				hasMatch = true
				break
			}
		}
		if hasMatch {
			l.notifyNewReceipts()
		}
	}
}

func (tm *txManager) loadReceiptListeners() error {

	var lastPageEnd *string
	ctx := tm.bgCtx
	for {

		var page []*persistedReceiptListener
		q := tm.p.DB().
			WithContext(ctx).
			Order("name").
			Limit(tm.receiptListenersLoadPageSize)
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

		if len(page) < tm.receiptListenersLoadPageSize {
			log.L(ctx).Infof("loaded %d receipted listeners", len(tm.receiptListeners))
			return nil
		}

		lastPageEnd = &page[len(page)-1].Name
	}

}

func (tm *txManager) getReceiptListenerList() []*receiptListener {

	tm.receiptListenerLock.Lock()
	defer tm.receiptListenerLock.Unlock()

	listeners := make([]*receiptListener, 0, len(tm.receiptListeners))
	for _, l := range tm.receiptListeners {
		listeners = append(listeners, l)
	}
	return listeners
}

func (tm *txManager) startReceiptListeners() {

	tm.receiptListenerLock.Lock()
	defer tm.receiptListenerLock.Unlock()

	for _, l := range tm.receiptListeners {
		if *l.spec.Started {
			l.start()
		}
	}
}

func (tm *txManager) stopReceiptListeners() {

	tm.receiptListenerLock.Lock()
	defer tm.receiptListenerLock.Unlock()

	for _, l := range tm.receiptListeners {
		l.stop()
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

// Build parts of the matching that can be pre-filtered efficiently in the DB.
//
// IMPORTANT: Make sure to also update checkMatch() when adding filter dimensions
func (tm *txManager) buildListenerDBQuery(ctx context.Context, spec *pldapi.TransactionReceiptListener, dbTX *gorm.DB) (*gorm.DB, error) {
	q := dbTX

	// Filter based on the type and/or domain
	if spec.Filters.Type == nil {
		if spec.Filters.Domain != "" {
			return nil, i18n.NewError(ctx, msgs.MsgTxMgrBadReceiptListenerTypeDomain, spec.Name, "", spec.Filters.Domain)
		}
	} else {
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
		default:
			return nil, i18n.NewError(ctx, msgs.MsgTxMgrBadReceiptListenerTypeDomain, spec.Name, spec.Filters.Type, spec.Filters.Domain)
		}
	}

	// Standard parts
	q = q.Order("sequence").Limit(tm.receiptsReadPageSize)
	// Only return non-blocked sequences
	q = q.Joins(`Block`, dbTX.Where(&persistedReceiptBlock{Listener: spec.Name}))
	q = q.Where(`"Block"."transaction" IS NULL`)
	return q, nil
}

// Applies all the rules in-memory to a receipt, including:
// - Those which we pre-filter in the DB
// - Those too complex to efficiently pre-filter in the DB
// We do both, so that we can use this as a trigger-guard for re-polling the
// DB, as well as a post-filter on results from the DB.
//
// Note that blocked sequences are ONLY maintained in the DB, so we can never bypass the DB polling.
//
// IMPORTANT: Make sure to also consider adding pre-filters to buildListenerDBQuery() when adding filter dimensions
func (l *receiptListener) checkMatch(r *transactionReceipt) bool {
	matches := true
	spec := l.spec

	// Filter based on the type and/or domain
	if spec.Filters.Type != nil {
		switch spec.Filters.Type.V() {
		case pldapi.TransactionTypePrivate:
			if spec.Filters.Domain != "" {
				matches = matches && (r.Domain == spec.Filters.Domain)
			} else {
				matches = matches && (r.Domain != "")
			}
		case pldapi.TransactionTypePublic:
			matches = matches && (r.Domain == "")
		default:
			matches = false
		}
	}

	if l.spec.Filters.SequenceAbove != nil {
		matches = matches && r.Sequence > *l.spec.Filters.SequenceAbove
	}

	return matches
}

func (tm *txManager) mapListener(ctx context.Context, pl *persistedReceiptListener) (*pldapi.TransactionReceiptListener, error) {
	spec := &pldapi.TransactionReceiptListener{
		Name:    pl.Name,
		Started: pl.Started,
		Created: pl.Created,
	}
	if err := json.Unmarshal(pl.Filters, &spec.Filters); err != nil {
		return nil, i18n.WrapError(ctx, err, msgs.MsgTxMgrBadReceiptListenerFilter, pl.Name)
	}
	if err := json.Unmarshal(pl.Options, &spec.Options); err != nil {
		return nil, i18n.WrapError(ctx, err, msgs.MsgTxMgrBadReceiptListenerOptions, pl.Name)
	}
	if err := tm.validateListenerSpec(ctx, spec); err != nil {
		return nil, err
	}
	return spec, nil
}

func (tm *txManager) loadListener(ctx context.Context, pl *persistedReceiptListener) (*receiptListener, error) {

	spec, err := tm.mapListener(ctx, pl)
	if err != nil {
		return nil, err
	}

	l := &receiptListener{
		tm:           tm,
		spec:         spec,
		newReceivers: make(chan bool, 1),
		newReceipts:  make(chan bool, 1),
	}

	tm.receiptListenerLock.Lock()
	defer tm.receiptListenerLock.Unlock()
	if tm.receiptListeners[pl.Name] != nil {
		return nil, i18n.NewError(ctx, msgs.MsgTxMgrReceiptListenerDupLoad, pl.Name)
	}
	tm.receiptListeners[pl.Name] = l
	return l, nil
}

func (l *receiptListener) initStart() {
	l.ctx, l.cancelCtx = context.WithCancel(log.WithLogField(l.tm.bgCtx, "receipt-listener", l.spec.Name))
	l.done = make(chan struct{})
}

func (l *receiptListener) start() {
	if l.done == nil {
		l.initStart()
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

func (l *receiptListener) addReceiver(r components.ReceiptReceiver) *registeredReceiptReceiver {
	l.receiverLock.Lock()
	defer l.receiverLock.Unlock()

	registered := &registeredReceiptReceiver{
		id:              uuid.New(),
		l:               l,
		ReceiptReceiver: r,
	}
	l.receivers = append(l.receivers, registered)

	select {
	case l.newReceivers <- true:
	default:
	}

	return registered
}

func (l *receiptListener) removeReceiver(rid uuid.UUID) {
	l.receiverLock.Lock()
	defer l.receiverLock.Unlock()

	if len(l.receivers) > 0 {
		newReceivers := make([]*registeredReceiptReceiver, 0, len(l.receivers)-1)
		for _, existing := range l.receivers {
			if existing.id != rid {
				newReceivers = append(newReceivers, existing)
			}
		}
		l.receivers = newReceivers
	}
}

func (l *receiptListener) loadCheckpoint() error {
	var checkpoints []*persistedReceiptCheckpoint
	err := l.tm.p.DB().
		WithContext(l.ctx).
		Where("listener = ?", l.spec.Name).
		Limit(1).
		Find(&checkpoints).
		Error
	if err != nil {
		return err
	}
	if len(checkpoints) == 0 {
		if l.spec.Filters.SequenceAbove != nil {
			l.checkpoint = l.spec.Filters.SequenceAbove
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
	if !l.checkMatch(pr) {
		return nil
	}

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
			Created:     tktypes.TimestampNow(),
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

func (l *receiptListener) updateCheckpoint(newSequence uint64) error {
	err := l.tm.p.DB().
		WithContext(l.ctx).
		Clauses(clause.OnConflict{
			Columns: []clause.Column{
				{Name: "listener"},
			},
			DoUpdates: clause.AssignmentColumns([]string{
				"sequence",
				"time",
			}),
		}).
		Create(&persistedReceiptCheckpoint{
			Listener: l.spec.Name,
			Sequence: newSequence,
			Time:     tktypes.TimestampNow(),
		}).
		Error
	if err != nil {
		return err
	}
	l.checkpoint = &newSequence
	return nil
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

		// Whether we processed any receipts or not, we can move our checkpoint forwards
		if len(page) > 0 {
			err := l.tm.receiptsRetry.Do(l.ctx, func(attempt int) (retryable bool, err error) {
				return true, l.updateCheckpoint(page[len(page)-1].Sequence)
			})
			if err != nil {
				log.L(l.ctx).Warnf("listener stopping (before updating checkpoint for batch %d): %s", batchID, err) // cancelled context
				return
			}
		}

		// If our page was not full, wait for notification of new receipts before we look again
		if len(page) < l.tm.receiptsReadPageSize {
			select {
			case <-l.newReceipts:
			case <-l.ctx.Done():
				log.L(l.ctx).Warnf("listener stopping (waiting for new receipts)") // cancelled context
				return
			}
		}

	}
}
