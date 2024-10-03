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

package statemgr

import (
	"context"
	"sync"

	"github.com/google/uuid"
	"github.com/hyperledger/firefly-common/pkg/i18n"
	"github.com/kaleido-io/paladin/core/internal/components"
	"github.com/kaleido-io/paladin/core/internal/filters"
	"github.com/kaleido-io/paladin/core/internal/msgs"

	"github.com/kaleido-io/paladin/toolkit/pkg/log"
	"github.com/kaleido-io/paladin/toolkit/pkg/query"
	"github.com/kaleido-io/paladin/toolkit/pkg/tktypes"
)

type domainContext struct {
	ss              *stateStore
	domainName      string
	contractAddress tktypes.EthAddress
	ctx             context.Context
	stateLock       sync.Mutex
	latch           chan struct{}
	unFlushed       *writeOperation
	flushing        *writeOperation
	flushResult     chan error
}

func (ss *stateStore) RunInDomainContext(domainName string, contractAddress tktypes.EthAddress, fn components.DomainContextFunction) error {
	return ss.getDomainContext(domainName, contractAddress).run(fn)
}

func (ss *stateStore) RunInDomainContextFlush(domainName string, contractAddress tktypes.EthAddress, fn components.DomainContextFunction) error {
	dc := ss.getDomainContext(domainName, contractAddress)
	err := dc.run(fn)
	if err == nil {
		err = dc.Flush()
	}
	if err == nil {
		err = dc.checkFlushCompletion(true)
	}
	return err
}

func (ss *stateStore) getDomainContext(domainName string, contractAddress tktypes.EthAddress) *domainContext {
	ss.domainLock.Lock()
	defer ss.domainLock.Unlock()

	domainKey := domainName + ":" + contractAddress.String()
	dc := ss.domainContexts[domainKey]
	if dc == nil {
		dc = &domainContext{
			ss:              ss,
			domainName:      domainName,
			contractAddress: contractAddress,
			ctx:             log.WithLogField(ss.bgCtx, "domain_context", domainName),
			latch:           make(chan struct{}, 1),
			unFlushed:       ss.writer.newWriteOp(domainName, contractAddress),
		}
		ss.domainContexts[domainKey] = dc
	}
	return dc
}

// The latch protects to ensure only a single routine executes against the DSI interface concurrently.
// We have no opinion in this module about how long-lived the function that holds the latch is -
// it can be a long lived go-routine, or short lived event handlers on lots of different go-routines
// (obviously a mixture of both would not work).
func (dc *domainContext) takeLatch() error {
	select {
	case <-dc.ctx.Done():
		return i18n.NewError(dc.ctx, msgs.MsgContextCanceled)
	case dc.latch <- struct{}{}:
		return nil
	}
}

func (dc *domainContext) returnLatch() {
	<-dc.latch
}

func (dc *domainContext) run(fn func(ctx context.Context, dsi components.DomainStateInterface) error) error {
	// Latch is held for entire function call, but the call happens on the caller's routine.
	// (state is locked separately)
	if err := dc.takeLatch(); err != nil {
		return err
	}
	defer dc.returnLatch()
	return fn(dc.ctx, dc)
}

func (dc *domainContext) getUnFlushedStates() (spending []tktypes.HexBytes, spent []tktypes.HexBytes, nullifiers []*components.StateNullifier, err error) {
	// Take lock and check flush state
	dc.stateLock.Lock()
	defer dc.stateLock.Unlock()
	if flushErr := dc.checkFlushCompletion(false); flushErr != nil {
		return nil, nil, nil, flushErr
	}

	for _, l := range dc.unFlushed.stateLocks {
		if l.Spending {
			spending = append(spending, l.State)
		}
	}
	for _, s := range dc.unFlushed.stateSpends {
		spent = append(spent, s.State)
	}
	nullifiers = append(nullifiers, dc.unFlushed.stateNullifiers...)
	if dc.flushing != nil {
		for _, l := range dc.flushing.stateLocks {
			if l.Spending {
				spending = append(spending, l.State)
			}
		}
		for _, s := range dc.flushing.stateSpends {
			spent = append(spent, s.State)
		}
		nullifiers = append(nullifiers, dc.flushing.stateNullifiers...)
	}
	return spending, spent, nullifiers, nil
}

func (dc *domainContext) mergedUnFlushed(schema components.Schema, dbStates []*components.State, query *query.QueryJSON, requireNullifier bool) (_ []*components.State, err error) {
	dc.stateLock.Lock()
	defer dc.stateLock.Unlock()
	if flushErr := dc.checkFlushCompletion(false); flushErr != nil {
		return nil, flushErr
	}

	// Get the list of new un-flushed states, which are not already locked for spend
	var allUnFlushedStates []*components.StateWithLabels
	var allUnFlushedStateSpends []*components.StateSpend
	var allUnFlushedStateLocks []*components.StateLock
	var allUnflushedNullifiers []*components.StateNullifier
	for _, ops := range []*writeOperation{dc.unFlushed, dc.flushing} {
		if ops != nil {
			allUnFlushedStates = append(allUnFlushedStates, ops.states...)
			allUnFlushedStateLocks = append(allUnFlushedStateLocks, ops.stateLocks...)
			allUnFlushedStateSpends = append(allUnFlushedStateSpends, ops.stateSpends...)
			allUnflushedNullifiers = append(allUnflushedNullifiers, ops.stateNullifiers...)
		}
	}

	matches := make([]*components.StateWithLabels, 0, len(dc.unFlushed.states))
	for _, state := range allUnFlushedStates {
		spent := false
		for _, spend := range allUnFlushedStateSpends {
			if spend.State.Equals(state.ID) {
				spent = true
			}
		}
		if !spent {
			for _, lock := range allUnFlushedStateLocks {
				if lock.State.Equals(state.ID) {
					spent = lock.Spending
					break
				}
			}
		}
		// Cannot return it if it's spent or locked for spending
		if spent {
			continue
		}

		if requireNullifier {
			hasNullifier := false
			for _, nullifier := range allUnflushedNullifiers {
				if nullifier.State.Equals(state.ID) {
					state.Nullifier = nullifier
					hasNullifier = true
					break
				}
			}
			if !hasNullifier {
				continue
			}
		}

		// Now we see if it matches the query
		labelSet := dc.ss.labelSetFor(schema)
		match, err := filters.EvalQuery(dc.ctx, query, labelSet, state.LabelValues)
		if err != nil {
			return nil, err
		}
		if match {
			dup := false
			for _, dbState := range dbStates {
				if dbState.ID.Equals(state.ID) {
					dup = true
					break
				}
			}
			if !dup {
				log.L(dc.ctx).Debugf("Matched state %s from un-flushed writes", &state.ID)
				matches = append(matches, state)
			}
		}
	}

	if len(matches) > 0 {
		// Build the merged list - this involves extra cost, as we deliberately don't reconstitute
		// the labels in JOIN on DB load (affecting every call at the DB side), instead we re-parse
		// them as we need them
		return dc.mergeInMemoryMatches(schema, dbStates, matches, query)
	}

	return dbStates, nil
}

func (dc *domainContext) mergeInMemoryMatches(schema components.Schema, states []*components.State, extras []*components.StateWithLabels, query *query.QueryJSON) (_ []*components.State, err error) {

	// Reconstitute the labels for all the loaded states into the front of an aggregate list
	fullList := make([]*components.StateWithLabels, len(states), len(states)+len(extras))
	persistedStateIDs := make(map[string]bool)
	for i, s := range states {
		if fullList[i], err = schema.RecoverLabels(dc.ctx, s); err != nil {
			return nil, err
		}
		persistedStateIDs[s.ID.String()] = true
	}

	// Copy the matches to the end of that same list
	// However, we can't be certain that some of the states that were in the flushing list, haven't made it
	// to the DB yet - so we do need to de-dup here.
	for _, s := range extras {
		if !persistedStateIDs[s.ID.String()] {
			fullList = append(fullList, s)
		}
	}

	// Sort it in place - note we ensure we always have a sort instruction on the DB
	sortInstructions := query.Sort
	if err = filters.SortValueSetInPlace(dc.ctx, dc.ss.labelSetFor(schema), fullList, sortInstructions...); err != nil {
		return nil, err
	}

	// We only want the states (not the labels needed during sort),
	// and only up to the limit that might have been breached adding in our in-memory states
	len := len(fullList)
	if query.Limit != nil && len > *query.Limit {
		len = *query.Limit
	}
	retList := make([]*components.State, len)
	for i := 0; i < len; i++ {
		retList[i] = fullList[i].State
	}
	return retList, nil

}

func (dc *domainContext) FindAvailableStates(schemaID string, query *query.QueryJSON) (s []*components.State, err error) {

	// Build a list of spending states
	spending, spent, _, err := dc.getUnFlushedStates()
	if err != nil {
		return nil, err
	}
	spending = append(spending, spent...)

	// Run the query against the DB
	schema, states, err := dc.ss.findStates(dc.ctx, dc.domainName, dc.contractAddress, schemaID, query, StateStatusAvailable, spending...)
	if err != nil {
		return nil, err
	}

	// Merge in un-flushed states to results
	return dc.mergedUnFlushed(schema, states, query, false)
}

func (dc *domainContext) FindAvailableNullifiers(schemaID string, query *query.QueryJSON) (s []*components.State, err error) {

	// Build a list of unflushed and spending nullifiers
	spending, spent, nullifiers, err := dc.getUnFlushedStates()
	if err != nil {
		return nil, err
	}
	statesWithNullifiers := make([]tktypes.HexBytes, len(nullifiers))
	for i, n := range nullifiers {
		statesWithNullifiers[i] = n.State
	}

	// Run the query against the DB
	schema, states, err := dc.ss.findAvailableNullifiers(dc.ctx, dc.domainName, dc.contractAddress, schemaID, query, statesWithNullifiers, spending, spent)
	if err != nil {
		return nil, err
	}

	// Attach nullifiers to states
	for _, s := range states {
		if s.Nullifier == nil {
			for _, n := range nullifiers {
				if n.State.Equals(s.ID) {
					s.Nullifier = n
					break
				}
			}
		}
	}

	// Merge in un-flushed states to results
	return dc.mergedUnFlushed(schema, states, query, true)
}

func (dc *domainContext) UpsertStates(transactionID *uuid.UUID, stateUpserts []*components.StateUpsert) (states []*components.State, err error) {

	states = make([]*components.State, len(stateUpserts))
	withValues := make([]*components.StateWithLabels, len(stateUpserts))
	for i, ns := range stateUpserts {
		schema, err := dc.ss.GetSchema(dc.ctx, dc.domainName, ns.SchemaID, true)
		if err != nil {
			return nil, err
		}

		withValues[i], err = schema.ProcessState(dc.ctx, dc.contractAddress, ns.Data, ns.ID)
		if err != nil {
			return nil, err
		}
		states[i] = withValues[i].State
		if transactionID != nil {
			states[i].Locked = &components.StateLock{
				Transaction: *transactionID,
				State:       withValues[i].State.ID,
				Creating:    ns.Creating,
				Spending:    ns.Spending,
			}
			log.L(dc.ctx).Infof("Upserting state %s locked to tx=%s creating=%t spending=%t", states[i].ID, transactionID, states[i].Locked.Creating, states[i].Locked.Spending)
		} else {
			log.L(dc.ctx).Infof("Upserting state %s UNLOCKED", states[i].ID)
		}
	}

	// Take lock and check flush state
	dc.stateLock.Lock()
	defer dc.stateLock.Unlock()
	if flushErr := dc.checkFlushCompletion(false); flushErr != nil {
		return nil, flushErr
	}

	// We need to de-duplicate out any previous un-flushed state writes of the same ID
	deDuppedUnFlushedStates := make([]*components.StateWithLabels, 0, len(dc.unFlushed.states))
	for _, existing := range dc.unFlushed.states {
		var replaced bool
		for _, s := range withValues {
			if existing.ID.Equals(s.ID) {
				replaced = true
				break
			}
		}
		if !replaced {
			deDuppedUnFlushedStates = append(deDuppedUnFlushedStates, existing)
		}
	}
	// Now we can add our own un-flushed writes to the de-duplicated lists
	dc.unFlushed.states = append(deDuppedUnFlushedStates, withValues...)
	// Then add all the state locks if this is transaction flush (which need individual de-duping too)
	if transactionID != nil {
		for _, s := range withValues {
			_, err = dc.setUnFlushedLock(*transactionID, s.State.ID, func(sl *components.StateLock) {
				// Upsert semantics for states will replace any existing locks with the explicitly set locks in the upsert
				sl.Creating = s.Locked.Creating
				sl.Spending = s.Locked.Spending
			})
		}
	}

	return states, nil
}

func (dc *domainContext) UpsertNullifiers(nullifiers []*components.StateNullifier) error {
	// Take lock and check flush state
	dc.stateLock.Lock()
	defer dc.stateLock.Unlock()
	if flushErr := dc.checkFlushCompletion(false); flushErr != nil {
		return flushErr
	}

	dc.unFlushed.stateNullifiers = append(dc.unFlushed.stateNullifiers, nullifiers...)
	return nil
}

func (dc *domainContext) lockStates(transactionID uuid.UUID, stateIDStrings []string, setLockState func(*components.StateLock)) (err error) {
	stateIDs := make([]tktypes.HexBytes, len(stateIDStrings))
	for i, id := range stateIDStrings {
		stateIDs[i], err = tktypes.ParseHexBytes(dc.ctx, id)
		if err != nil {
			return err
		}
	}

	// Take lock and check flush state
	dc.stateLock.Lock()
	defer dc.stateLock.Unlock()
	if flushErr := dc.checkFlushCompletion(false); flushErr != nil {
		return flushErr
	}

	// Update an existing un-flushed record, or add a new one.
	// Note we might fail on a clash (and the caller should then reset this transaction)
	for _, id := range stateIDs {
		if _, err := dc.setUnFlushedLock(transactionID, id, setLockState); err != nil {
			return err
		}
	}
	return nil
}

func (dc *domainContext) setUnFlushedLock(transactionID uuid.UUID, stateID tktypes.HexBytes, setLockState func(*components.StateLock)) (*components.StateLock, error) {
	// Update an existing un-flushed record if one exists
	for _, lock := range dc.unFlushed.stateLocks {
		if lock.State.Equals(stateID) {
			if lock.Transaction != transactionID {
				// This represents a failure to call ResetTransaction() correctly
				return nil, i18n.NewError(dc.ctx, msgs.MsgStateLockConflictUnexpected, lock.Transaction, transactionID)
			}
			setLockState(lock)
			return lock, nil
		}
	}
	// Otherwise create a new one
	l := &components.StateLock{State: stateID, Transaction: transactionID}
	dc.unFlushed.stateLocks = append(dc.unFlushed.stateLocks, l)
	setLockState(l)
	return l, nil
}

func (dc *domainContext) setUnFlushedSpend(transactionID uuid.UUID, stateID tktypes.HexBytes) (*components.StateSpend, error) {
	// Check for an existing record
	for _, spend := range dc.unFlushed.stateSpends {
		if spend.State.Equals(stateID) {
			if spend.Transaction != transactionID {
				// Should never happen - two transactions cannot spend the same state
				return nil, i18n.NewError(dc.ctx, msgs.MsgStateSpendConflictUnexpected, spend.Transaction, transactionID)
			}
			return spend, nil
		}
	}
	s := &components.StateSpend{State: stateID, Transaction: transactionID}
	dc.unFlushed.stateSpends = append(dc.unFlushed.stateSpends, s)
	return s, nil
}

func (dc *domainContext) setUnFlushedConfirm(transactionID uuid.UUID, stateID tktypes.HexBytes) (*components.StateConfirm, error) {
	// Check for an existing record
	for _, confirm := range dc.unFlushed.stateConfirms {
		if confirm.State.Equals(stateID) {
			if confirm.Transaction != transactionID {
				// Should never happen - two transactions cannot confirm the same state
				return nil, i18n.NewError(dc.ctx, msgs.MsgStateConfirmConflictUnexpected, confirm.Transaction, transactionID)
			}
			return confirm, nil
		}
	}
	s := &components.StateConfirm{State: stateID, Transaction: transactionID}
	dc.unFlushed.stateConfirms = append(dc.unFlushed.stateConfirms, s)
	return s, nil
}

func (dc *domainContext) MarkStatesRead(transactionID uuid.UUID, stateIDs []string) (err error) {
	return dc.lockStates(transactionID, stateIDs, func(*components.StateLock) {})
}

func (dc *domainContext) MarkStatesSpending(transactionID uuid.UUID, stateIDs []string) (err error) {
	return dc.lockStates(transactionID, stateIDs, func(l *components.StateLock) { l.Spending = true })
}

func (dc *domainContext) MarkStatesSpent(transactionID uuid.UUID, stateIDStrings []string) (err error) {
	stateIDs := make([]tktypes.HexBytes, len(stateIDStrings))
	for i, id := range stateIDStrings {
		stateIDs[i], err = tktypes.ParseHexBytes(dc.ctx, id)
		if err != nil {
			return err
		}
	}

	// Take lock and check flush state
	dc.stateLock.Lock()
	defer dc.stateLock.Unlock()
	if flushErr := dc.checkFlushCompletion(false); flushErr != nil {
		return flushErr
	}

	// Add a new un-flushed spend record
	for _, id := range stateIDs {
		if _, err := dc.setUnFlushedSpend(transactionID, id); err != nil {
			return err
		}
	}
	return nil
}

func (dc *domainContext) MarkStatesConfirmed(transactionID uuid.UUID, stateIDStrings []string) (err error) {
	stateIDs := make([]tktypes.HexBytes, len(stateIDStrings))
	for i, id := range stateIDStrings {
		stateIDs[i], err = tktypes.ParseHexBytes(dc.ctx, id)
		if err != nil {
			return err
		}
	}

	// Take lock and check flush state
	dc.stateLock.Lock()
	defer dc.stateLock.Unlock()
	if flushErr := dc.checkFlushCompletion(false); flushErr != nil {
		return flushErr
	}

	// Add a new un-flushed confirmation record
	for _, id := range stateIDs {
		if _, err := dc.setUnFlushedConfirm(transactionID, id); err != nil {
			return err
		}
	}
	return nil
}

func (dc *domainContext) ResetTransaction(transactionID uuid.UUID) error {
	// Take lock and check flush state
	dc.stateLock.Lock()
	defer dc.stateLock.Unlock()
	if flushErr := dc.checkFlushCompletion(false); flushErr != nil {
		return flushErr
	}

	// Remove anything un-flushed for this transaction, as we will delete everything instead
	newStateLocks := make([]*components.StateLock, 0, len(dc.unFlushed.stateLocks))
	for _, l := range dc.unFlushed.stateLocks {
		if l.Transaction != transactionID {
			newStateLocks = append(newStateLocks, l)
		}
	}
	dc.unFlushed.stateLocks = newStateLocks
	// Add the delete to be flushed
	dc.unFlushed.transactionLockDeletes = append(dc.unFlushed.transactionLockDeletes, transactionID)
	return nil
}

func (dc *domainContext) Flush(successCallbacks ...components.DomainContextFunction) error {
	dc.stateLock.Lock()
	defer dc.stateLock.Unlock()

	// Note the implementation of this function ensures this is safe while holding the lock
	// we can't get to the point dc.flushing is non-nil, until we can be confident
	// dc.flushed is also non-nil and will be closed.
	//
	// This is a long-lived lock, but it only happens when we're double-flushing
	// (the previous flush didn't finish before the next is initiated)
	if flushErr := dc.checkFlushCompletion(true); flushErr != nil {
		return flushErr
	}

	// Cycle it out
	dc.flushing = dc.unFlushed
	dc.flushResult = make(chan error, 1)
	dc.unFlushed = dc.ss.writer.newWriteOp(dc.domainName, dc.contractAddress)

	// We pass the vars directly to the routine, so the routine does not need the lock
	go dc.flushOp(dc.flushing, dc.flushResult, successCallbacks...)
	return nil
}

// flushOp MUST NOT take the stateLock
func (dc *domainContext) flushOp(op *writeOperation, flushed chan error, successCallbacks ...components.DomainContextFunction) {
	dc.ss.writer.queue(dc.ctx, op)
	err := op.flush(dc.ctx)
	flushed <- err
	if err == nil {
		for _, cb := range successCallbacks {
			callback := cb
			go func() { _ = dc.run(callback) }()
		}
	}
}

// checkFlushCompletion MUST be called holding the lock
func (dc *domainContext) checkFlushCompletion(block bool) error {
	if dc.flushing == nil {
		return nil
	}
	var flushErr error
	if block {
		flushErr = <-dc.flushResult
	} else {
		select {
		case flushErr = <-dc.flushResult:
		default:
			log.L(dc.ctx).Debugf("flush is still active")
			return nil
		}
	}
	// If we reached here, we've popped a flush result - clear the status
	dc.flushing = nil
	dc.flushResult = nil
	// If there was an error, we need to clean out the whole un-flushed state before we return it
	if flushErr != nil {
		dc.unFlushed = dc.ss.writer.newWriteOp(dc.domainName, dc.contractAddress)
		return i18n.WrapError(dc.ctx, flushErr, msgs.MsgStateFlushFailedDomainReset, dc.domainName)
	}
	return nil
}
