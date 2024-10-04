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
	ss              *stateManager
	domainName      string
	contractAddress tktypes.EthAddress
	stateLock       sync.Mutex
	unFlushed       *writeOperation
	flushing        *writeOperation
	flushErr        error // an error has been recorded and a reset is required

	// State locks are an in memory structure only, recording a set of locks associated with each transaction.
	// These are held only in memory, and used during DB queries to create a view on top of the database
	// that can make both additional states available, and remove visibility to states.
	txLocks map[uuid.UUID][]*components.StateLock
}

func (ss *stateManager) NewDomainContext(domainName string, contractAddress tktypes.EthAddress) components.DomainContext {
	return &domainContext{
		ss:              ss,
		domainName:      domainName,
		contractAddress: contractAddress,
		txLocks:         make(map[uuid.UUID][]*components.StateLock),
	}
}

func (dc *domainContext) getUnFlushedStates(ctx context.Context) (spending []tktypes.HexBytes, spent []tktypes.HexBytes, nullifiers []*components.StateNullifier, err error) {
	// Take lock and check flush state
	dc.stateLock.Lock()
	defer dc.stateLock.Unlock()
	if flushErr := dc.checkResetInitUnFlushed(ctx); flushErr != nil {
		return nil, nil, nil, flushErr
	}

	for _, locks := range dc.txLocks {
		for _, l := range locks {
			if l.Spending {
				spending = append(spending, l.State)
			}
		}
	}
	nullifiers = append(nullifiers, dc.unFlushed.stateNullifiers...)
	if dc.flushing != nil {
		nullifiers = append(nullifiers, dc.flushing.stateNullifiers...)
	}
	return spending, spent, nullifiers, nil
}

func (dc *domainContext) mergedUnFlushed(ctx context.Context, schema components.Schema, dbStates []*components.State, query *query.QueryJSON, requireNullifier bool) (_ []*components.State, err error) {
	dc.stateLock.Lock()
	defer dc.stateLock.Unlock()
	if flushErr := dc.checkResetInitUnFlushed(ctx); flushErr != nil {
		return nil, flushErr
	}

	// Get the list of new un-flushed states, which are not already locked for spend
	var allUnFlushedStates []*components.StateWithLabels
	var allUnflushedNullifiers []*components.StateNullifier
	for _, ops := range []*writeOperation{dc.unFlushed, dc.flushing} {
		if ops != nil {
			allUnFlushedStates = append(allUnFlushedStates, ops.states...)
			allUnflushedNullifiers = append(allUnflushedNullifiers, ops.stateNullifiers...)
		}
	}

	matches := make([]*components.StateWithLabels, 0, len(dc.unFlushed.states))
	schemaId := schema.Persisted().ID
	for _, state := range allUnFlushedStates {
		if !state.Schema.Equals(&schemaId) {
			continue
		}
		spent := false
		for _, locks := range dc.txLocks {
			for _, lock := range locks {
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
		match, err := filters.EvalQuery(ctx, query, labelSet, state.LabelValues)
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
				log.L(ctx).Debugf("Matched state %s from un-flushed writes", &state.ID)
				matches = append(matches, state)
			}
		}
	}

	if len(matches) > 0 {
		// Build the merged list - this involves extra cost, as we deliberately don't reconstitute
		// the labels in JOIN on DB load (affecting every call at the DB side), instead we re-parse
		// them as we need them
		return dc.mergeInMemoryMatches(ctx, schema, dbStates, matches, query)
	}

	return dbStates, nil
}

func (dc *domainContext) mergeInMemoryMatches(ctx context.Context, schema components.Schema, states []*components.State, extras []*components.StateWithLabels, query *query.QueryJSON) (_ []*components.State, err error) {

	// Reconstitute the labels for all the loaded states into the front of an aggregate list
	fullList := make([]*components.StateWithLabels, len(states), len(states)+len(extras))
	persistedStateIDs := make(map[string]bool)
	for i, s := range states {
		if fullList[i], err = schema.RecoverLabels(ctx, s); err != nil {
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
	if err = filters.SortValueSetInPlace(ctx, dc.ss.labelSetFor(schema), fullList, sortInstructions...); err != nil {
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

func (dc *domainContext) FindAvailableStates(ctx context.Context, schemaID string, query *query.QueryJSON) (s []*components.State, err error) {

	// Build a list of spending states
	spending, spent, _, err := dc.getUnFlushedStates(ctx)
	if err != nil {
		return nil, err
	}
	spending = append(spending, spent...)

	// Run the query against the DB
	schema, states, err := dc.ss.findStates(ctx, dc.domainName, dc.contractAddress, schemaID, query, StateStatusAvailable, spending...)
	if err != nil {
		return nil, err
	}

	// Merge in un-flushed states to results
	return dc.mergedUnFlushed(ctx, schema, states, query, false)
}

func (dc *domainContext) FindAvailableNullifiers(ctx context.Context, schemaID string, query *query.QueryJSON) (s []*components.State, err error) {

	// Build a list of unflushed and spending nullifiers
	spending, spent, nullifiers, err := dc.getUnFlushedStates(ctx)
	if err != nil {
		return nil, err
	}
	statesWithNullifiers := make([]tktypes.HexBytes, len(nullifiers))
	for i, n := range nullifiers {
		statesWithNullifiers[i] = n.State
	}

	// Run the query against the DB
	schema, states, err := dc.ss.findAvailableNullifiers(ctx, dc.domainName, dc.contractAddress, schemaID, query, statesWithNullifiers, spending, spent)
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
	return dc.mergedUnFlushed(ctx, schema, states, query, true)
}

func (dc *domainContext) UpsertStates(ctx context.Context, transactionID *uuid.UUID, stateUpserts []*components.StateUpsert) (states []*components.State, err error) {

	states = make([]*components.State, len(stateUpserts))
	withValues := make([]*components.StateWithLabels, len(stateUpserts))
	for i, ns := range stateUpserts {
		schema, err := dc.ss.GetSchema(ctx, dc.domainName, ns.SchemaID, true)
		if err != nil {
			return nil, err
		}

		withValues[i], err = schema.ProcessState(ctx, dc.contractAddress, ns.Data, ns.ID)
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
			log.L(ctx).Infof("Upserting state %s locked to tx=%s creating=%t spending=%t", states[i].ID, transactionID, states[i].Locked.Creating, states[i].Locked.Spending)
		} else {
			log.L(ctx).Infof("Upserting state %s UNLOCKED", states[i].ID)
		}
	}

	// Take lock and check flush state
	dc.stateLock.Lock()
	defer dc.stateLock.Unlock()
	if flushErr := dc.checkResetInitUnFlushed(ctx); flushErr != nil {
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
			_, err = dc.updateStateLocks(ctx, *transactionID, s.State.ID, func(sl *components.StateLock) {
				// Upsert semantics for states will replace any existing locks with the explicitly set locks in the upsert
				sl.Creating = s.Locked.Creating
				sl.Spending = s.Locked.Spending
			})
		}
	}

	return states, nil
}

func (dc *domainContext) UpsertNullifiers(ctx context.Context, nullifiers []*components.StateNullifier) error {
	// Take lock and check flush state
	dc.stateLock.Lock()
	defer dc.stateLock.Unlock()
	if flushErr := dc.checkResetInitUnFlushed(ctx); flushErr != nil {
		return flushErr
	}

	dc.unFlushed.stateNullifiers = append(dc.unFlushed.stateNullifiers, nullifiers...)
	return nil
}

func (dc *domainContext) lockStates(ctx context.Context, transactionID uuid.UUID, stateIDStrings []string, setLockState func(*components.StateLock)) (err error) {
	stateIDs := make([]tktypes.HexBytes, len(stateIDStrings))
	for i, id := range stateIDStrings {
		stateIDs[i], err = tktypes.ParseHexBytes(ctx, id)
		if err != nil {
			return err
		}
	}

	// Take lock and check flush state
	dc.stateLock.Lock()
	defer dc.stateLock.Unlock()
	if flushErr := dc.checkResetInitUnFlushed(ctx); flushErr != nil {
		return flushErr
	}

	// Update an existing un-flushed record, or add a new one.
	// Note we might fail on a clash (and the caller should then reset this transaction)
	for _, id := range stateIDs {
		if _, err := dc.updateStateLocks(ctx, transactionID, id, setLockState); err != nil {
			return err
		}
	}
	return nil
}

func (dc *domainContext) updateStateLocks(ctx context.Context, transactionID uuid.UUID, stateID tktypes.HexBytes, setLockState func(*components.StateLock)) (*components.StateLock, error) {
	// Update an existing un-flushed record if one exists
	locks := dc.txLocks[transactionID]
	for _, lock := range locks {
		if lock.State.Equals(stateID) {
			if lock.Transaction != transactionID {
				// This represents a failure to call ResetTransaction() correctly
				return nil, i18n.NewError(ctx, msgs.MsgStateLockConflictUnexpected, lock.Transaction, transactionID)
			}
			setLockState(lock)
			return lock, nil
		}
	}
	// Otherwise create a new one
	l := &components.StateLock{State: stateID, Transaction: transactionID}
	locks = append(locks, l)
	dc.txLocks[transactionID] = locks
	setLockState(l)
	return l, nil
}

func (dc *domainContext) MarkStatesRead(ctx context.Context, transactionID uuid.UUID, stateIDs []string) (err error) {
	return dc.lockStates(ctx, transactionID, stateIDs, func(*components.StateLock) {})
}

func (dc *domainContext) MarkStatesSpending(ctx context.Context, transactionID uuid.UUID, stateIDs []string) (err error) {
	return dc.lockStates(ctx, transactionID, stateIDs, func(l *components.StateLock) { l.Spending = true })
}

// Clear all in-memory locks associated with individual transactions, because they are no longer needed/applicable
// Most likely because the state transitions have now been finalized
func (dc *domainContext) ClearTransactions(ctx context.Context, transactions []uuid.UUID) {
	dc.stateLock.Lock()
	defer dc.stateLock.Unlock()

	for _, transaction := range transactions {
		delete(dc.txLocks, transaction)
	}
}

func (dc *domainContext) GetStateLockCopy() map[uuid.UUID][]components.StateLock {
	dc.stateLock.Lock()
	defer dc.stateLock.Unlock()

	txLocksCopy := make(map[uuid.UUID][]components.StateLock)
	for tx, locks := range dc.txLocks {
		locksCopy := make([]components.StateLock, len(locks))
		for i, l := range locks {
			locksCopy[i] = *l // note we copy the whole state lock struct, not the pointer
		}
		txLocksCopy[tx] = locksCopy
	}
	return txLocksCopy
}

// Reset puts the world back to the point that has been so far flushed to storage.
//
// Must be called after a flush error before the context can be used, as on a flush
// error the caller must reset their processing to the last point of consistency
// as they cannot trust in-memory state
//
// Note it does not cancel or check the status of any in-progress flush, as the
// things that are flushed are inert records in isolation.
// Reset instead is intended to be a boundary where the calling code knows explicitly
// that any state-locks and states that haven't reached a confirmed flush must
// be re-written into the DomainContext.
func (dc *domainContext) Reset(ctx context.Context) {
	dc.stateLock.Lock()
	defer dc.stateLock.Unlock()

	dc.unFlushed = nil
	dc.txLocks = make(map[uuid.UUID][]*components.StateLock)
	dc.flushErr = nil
}

func (dc *domainContext) InitiateFlush(ctx context.Context, asyncCallback func(err error)) error {
	dc.stateLock.Lock()
	defer dc.stateLock.Unlock()

	// Sync check if there's already an error
	if dc.flushErr != nil {
		return i18n.WrapError(ctx, dc.flushErr, msgs.MsgStateFlushFailedDomainReset, dc.domainName)
	}

	// If we are already flushing, then we wait for that flush while holding the lock
	// here - until we can queue up the next flush.
	// e.g. we only get one flush ahead
	if dc.flushing != nil {
		select {
		case <-dc.flushing.flushed:
		case <-ctx.Done():
			// The caller gave up on us, we cannot flush
			return i18n.NewError(ctx, msgs.MsgContextCanceled)
		}
		// If we find an uncleared flush error, we are the ones that put it on for all calls to return
		// and then return it ourselves
		if dc.flushing.flushResult != nil {
			log.L(ctx).Errorf("flush %s failed - domain context must be reset", dc.flushing.id)
			dc.flushErr = dc.flushing.flushResult
			return i18n.WrapError(ctx, dc.flushErr, msgs.MsgStateFlushFailedDomainReset, dc.domainName)
		}
	}

	// Ok we're good to go async
	dc.flushing = dc.unFlushed
	dc.unFlushed = nil
	// Always dispatch a routine for the callback
	// even if there's a nil dc.flushing - meaning nothing to do
	go dc.waitForFlush(ctx, asyncCallback, dc.flushing)
	return nil
}

// MUST hold the lock to call this function
// Simply checks there isn't an un-cleared error that means the caller must reset.
func (dc *domainContext) checkResetInitUnFlushed(ctx context.Context) error {
	if dc.flushErr != nil {
		return i18n.WrapError(ctx, dc.flushErr, msgs.MsgStateFlushFailedDomainReset, dc.domainName)
	}
	if dc.unFlushed == nil {
		dc.unFlushed = dc.ss.writer.newWriteOp(dc.domainName, dc.contractAddress)
	}
	return nil
}

// MUST NOT hold the lock to call this function - instead pass in a list of all the
// unflushed writers (max 2 in practice) that need to be successful for this flush to
// be considered complete
func (dc *domainContext) waitForFlush(ctx context.Context, cb func(error), flushing *writeOperation) {
	var err error
	// We might have found by the time we got the lock to flush, there was nothing to do
	if flushing != nil {
		log.L(ctx).Debugf("waiting for flush %s", flushing.id)
		err = flushing.flush(ctx)
		flushing.flushResult = err // for any other routines the blocked waiting
		log.L(ctx).Debugf("flush %s completed (err=%v)", flushing.id, err)
		close(flushing.flushed)
	}
	cb(err)
}
