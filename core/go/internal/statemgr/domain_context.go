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
	"fmt"
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
	context.Context

	id                 uuid.UUID
	ss                 *stateManager
	domainName         string
	customHashFunction bool
	contractAddress    tktypes.EthAddress
	stateLock          sync.Mutex
	unFlushed          *writeOperation
	flushing           *writeOperation
	domainContexts     map[uuid.UUID]*domainContext
	closed             bool

	// We track creatingStates states beyond the flush - until the transaction that created them is removed, or a full reset
	// This is because the DB will never return them as "available"
	creatingStates map[string]*components.StateWithLabels

	// State locks are an in memory structure only, recording a set of locks associated with each transaction.
	// These are held only in memory, and used during DB queries to create a view on top of the database
	// that can make both additional states available, and remove visibility to states.
	txLocks []*components.StateLock
}

// Very important that callers Close domain contexts they open
func (ss *stateManager) NewDomainContext(ctx context.Context, domain components.Domain, contractAddress tktypes.EthAddress) components.DomainContext {
	id := uuid.New()
	log.L(ctx).Debugf("Domain context %s for domain %s contract %s closed", id, domain.Name(), contractAddress)

	ss.domainContextLock.Lock()
	defer ss.domainContextLock.Unlock()

	dc := &domainContext{
		Context:            log.WithLogField(ctx, "domain_ctx", fmt.Sprintf("%s_%s", domain.Name(), id)),
		id:                 id,
		ss:                 ss,
		domainName:         domain.Name(),
		customHashFunction: domain.CustomHashFunction(),
		contractAddress:    contractAddress,
		creatingStates:     make(map[string]*components.StateWithLabels),
		domainContexts:     make(map[uuid.UUID]*domainContext),
	}
	ss.domainContexts[id] = dc
	return dc
}

// nil if not found
func (ss *stateManager) GetDomainContext(ctx context.Context, id uuid.UUID) components.DomainContext {
	ss.domainContextLock.Lock()
	defer ss.domainContextLock.Unlock()

	ret, found := ss.domainContexts[id]
	if found {
		return ret
	}
	return nil // means an actual nil value to the interface
}

func (ss *stateManager) ListDomainContexts() []components.DomainContextInfo {
	ss.domainContextLock.Lock()
	defer ss.domainContextLock.Unlock()

	dcs := make([]components.DomainContextInfo, 0, len(ss.domainContexts))
	for _, dc := range ss.domainContexts {
		dcs = append(dcs, dc.Info())
	}
	return dcs

}

func (dCtx *domainContext) getUnFlushedSpends() (spending []tktypes.HexBytes, nullifiers []*components.StateNullifier, nullifierIDs []tktypes.HexBytes, err error) {
	// Take lock and check flush state
	dCtx.stateLock.Lock()
	defer dCtx.stateLock.Unlock()
	if flushErr := dCtx.checkResetInitUnFlushed(); flushErr != nil {
		return nil, nil, nil, flushErr
	}

	for _, l := range dCtx.txLocks {
		if l.Type.V() == components.StateLockTypeSpend {
			spending = append(spending, l.State)
		}
	}
	nullifiers = append(nullifiers, dCtx.unFlushed.stateNullifiers...)
	if dCtx.flushing != nil {
		nullifiers = append(nullifiers, dCtx.flushing.stateNullifiers...)
	}
	nullifierIDs = make([]tktypes.HexBytes, len(nullifiers))
	for i, nullifier := range nullifiers {
		nullifierIDs[i] = nullifier.ID
	}
	return spending, nullifiers, nullifierIDs, nil
}

func (dCtx *domainContext) mergeUnFlushedApplyLocks(schema components.Schema, dbStates []*components.State, query *query.QueryJSON, requireNullifier bool) (_ []*components.State, err error) {
	dCtx.stateLock.Lock()
	defer dCtx.stateLock.Unlock()
	if flushErr := dCtx.checkResetInitUnFlushed(); flushErr != nil {
		return nil, flushErr
	}

	// Get the list of new un-flushed states, which are not already locked for spend
	matches := make([]*components.StateWithLabels, 0, len(dCtx.creatingStates))
	schemaId := schema.Persisted().ID
	for _, state := range dCtx.creatingStates {
		if !state.Schema.Equals(&schemaId) {
			continue
		}
		spent := false
		for _, lock := range dCtx.txLocks {
			if lock.State.Equals(state.ID) && lock.Type.V() == components.StateLockTypeSpend {
				spent = true
				break
			}
		}
		// Cannot return it if it's spent or locked for spending
		if spent {
			continue
		}

		if requireNullifier && state.Nullifier == nil {
			continue
		}

		// Now we see if it matches the query
		labelSet := dCtx.ss.labelSetFor(schema)
		match, err := filters.EvalQuery(dCtx, query, labelSet, state.LabelValues)
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
				log.L(dCtx).Debugf("Matched state %s from un-flushed writes", &state.ID)
				// Take a shallow copy, as we'll apply the locks as they exist right now
				shallowCopy := *state
				matches = append(matches, &shallowCopy)
			}
		}
	}

	retStates := dbStates
	if len(matches) > 0 {
		// Build the merged list - this involves extra cost, as we deliberately don't reconstitute
		// the labels in JOIN on DB load (affecting every call at the DB side), instead we re-parse
		// them as we need them
		if retStates, err = dCtx.mergeInMemoryMatches(schema, dbStates, matches, query); err != nil {
			return nil, err
		}
	}

	return dCtx.applyLocks(retStates), nil
}

func (dCtx *domainContext) Info() components.DomainContextInfo {
	return components.DomainContextInfo{
		ID:              dCtx.id,
		DomainName:      dCtx.domainName,
		ContractAddress: dCtx.contractAddress,
	}
}

func (dCtx *domainContext) mergeInMemoryMatches(schema components.Schema, states []*components.State, extras []*components.StateWithLabels, query *query.QueryJSON) (_ []*components.State, err error) {

	// Reconstitute the labels for all the loaded states into the front of an aggregate list
	fullList := make([]*components.StateWithLabels, len(states), len(states)+len(extras))
	persistedStateIDs := make(map[string]bool)
	for i, s := range states {
		if fullList[i], err = schema.RecoverLabels(dCtx, s); err != nil {
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
	if err = filters.SortValueSetInPlace(dCtx, dCtx.ss.labelSetFor(schema), fullList, sortInstructions...); err != nil {
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

func (dCtx *domainContext) FindAvailableStates(schemaID tktypes.Bytes32, query *query.QueryJSON) (components.Schema, []*components.State, error) {

	// Build a list of spending states
	spending, _, _, err := dCtx.getUnFlushedSpends()
	if err != nil {
		return nil, nil, err
	}

	// Run the query against the DB
	schema, states, err := dCtx.ss.findStates(dCtx, dCtx.domainName, dCtx.contractAddress, schemaID, query, StateStatusAvailable, spending...)
	if err != nil {
		return nil, nil, err
	}

	// Merge in un-flushed states to results
	states, err = dCtx.mergeUnFlushedApplyLocks(schema, states, query, false)
	return schema, states, err
}

func (dCtx *domainContext) FindAvailableNullifiers(schemaID tktypes.Bytes32, query *query.QueryJSON) (components.Schema, []*components.State, error) {

	// Build a list of unflushed and spending nullifiers
	spending, nullifiers, nullifierIDs, err := dCtx.getUnFlushedSpends()
	if err != nil {
		return nil, nil, err
	}
	statesWithNullifiers := make([]tktypes.HexBytes, len(nullifiers))
	for i, n := range nullifiers {
		statesWithNullifiers[i] = n.State
	}

	// Run the query against the DB
	schema, states, err := dCtx.ss.findAvailableNullifiers(dCtx, dCtx.domainName, dCtx.contractAddress, schemaID, query, spending, nullifierIDs)
	if err != nil {
		return nil, nil, err
	}

	// Merge in un-flushed states to results
	states, err = dCtx.mergeUnFlushedApplyLocks(schema, states, query, true)
	return schema, states, err
}

func (dCtx *domainContext) UpsertStates(stateUpserts ...*components.StateUpsert) (states []*components.State, err error) {

	states = make([]*components.State, len(stateUpserts))
	stateLocks := make([]*components.StateLock, 0, len(stateUpserts))
	withValues := make([]*components.StateWithLabels, len(stateUpserts))
	toMakeAvailable := make([]*components.StateWithLabels, 0, len(stateUpserts))
	for i, ns := range stateUpserts {
		schema, err := dCtx.ss.GetSchema(dCtx, dCtx.domainName, ns.SchemaID, true)
		if err != nil {
			return nil, err
		}

		vs, err := schema.ProcessState(dCtx, dCtx.contractAddress, ns.Data, ns.ID, dCtx.customHashFunction)
		if err != nil {
			return nil, err
		}
		withValues[i] = vs
		states[i] = withValues[i].State
		if ns.CreatedBy != nil {
			createLock := &components.StateLock{
				Type:        components.StateLockTypeCreate.Enum(),
				Transaction: *ns.CreatedBy,
				State:       withValues[i].State.ID,
			}
			stateLocks = append(stateLocks, createLock)
			toMakeAvailable = append(toMakeAvailable, vs)
			log.L(dCtx).Infof("Upserting state %s with create lock tx=%s", states[i].ID, ns.CreatedBy)
		} else {
			log.L(dCtx).Infof("Upserting state %s (no create lock)", states[i].ID)
		}
	}

	// Take lock and check flush state
	dCtx.stateLock.Lock()
	defer dCtx.stateLock.Unlock()
	if flushErr := dCtx.checkResetInitUnFlushed(); flushErr != nil {
		return nil, flushErr
	}

	// Only those transactions with a creating TX lock can be returned from queries
	// (any other states supplied for flushing are just to ensure we have a copy of the state
	// for data availability when the existing/later confirm is available)
	for _, s := range toMakeAvailable {
		dCtx.creatingStates[s.ID.String()] = s
	}
	err = dCtx.addStateLocks(stateLocks...)
	if err != nil {
		return nil, err
	}

	// Add all the states to the flush that will go to the DB
	dCtx.unFlushed.states = append(dCtx.unFlushed.states, withValues...)
	return states, nil
}

func (dCtx *domainContext) UpsertNullifiers(nullifiers ...*components.NullifierUpsert) error {
	// Take lock and check flush state
	dCtx.stateLock.Lock()
	defer dCtx.stateLock.Unlock()
	if flushErr := dCtx.checkResetInitUnFlushed(); flushErr != nil {
		return flushErr
	}

	for _, nullifierInput := range nullifiers {
		nullifier := &components.StateNullifier{
			DomainName: dCtx.domainName,
			ID:         nullifierInput.ID,
			State:      nullifierInput.State,
		}
		nullifier.DomainName = dCtx.domainName
		creatingState := dCtx.creatingStates[nullifier.State.String()]
		if creatingState == nil {
			return i18n.NewError(dCtx, msgs.MsgStateNullifierStateNotInCtx, nullifier.State, nullifier.ID)
		} else if creatingState.Nullifier != nil && !creatingState.Nullifier.ID.Equals(nullifier.ID) {
			return i18n.NewError(dCtx, msgs.MsgStateNullifierConflict, nullifier.State, creatingState.Nullifier.ID)
		}
		creatingState.Nullifier = nullifier
		dCtx.unFlushed.stateNullifiers = append(dCtx.unFlushed.stateNullifiers, nullifier)
	}

	return nil
}

func (dCtx *domainContext) addStateLocks(locks ...*components.StateLock) error {
	for _, l := range locks {
		lockType, err := l.Type.Validate()
		if err != nil {
			return err
		}

		if l.Transaction == (uuid.UUID{}) {
			return i18n.NewError(dCtx, msgs.MsgStateLockNoTransaction)
		} else if len(l.State) == 0 {
			return i18n.NewError(dCtx, msgs.MsgStateLockNoState)
		}

		// For creating the state must be in our map (via Upsert) or we will fail to return it
		creatingState := dCtx.creatingStates[l.State.String()]
		if lockType == components.StateLockTypeCreate && creatingState == nil {
			return i18n.NewError(dCtx, msgs.MsgStateLockCreateNotInContext, l.State)
		}

		// Note we do NOT check for conflicts on existing state locks
		log.L(dCtx).Debugf("state %s adding %s lock tx=%s)", l.State, lockType, l.Transaction)
		dCtx.txLocks = append(dCtx.txLocks, l)
	}
	return nil
}

func (dCtx *domainContext) applyLocks(states []*components.State) []*components.State {
	for _, s := range states {
		s.Locks = []*components.StateLock{}
		for _, l := range dCtx.txLocks {
			if l.State.Equals(s.ID) {
				s.Locks = append(s.Locks, l)
			}
		}
	}
	return states
}

func (dCtx *domainContext) AddStateLocks(locks ...*components.StateLock) (err error) {
	// Take lock and check flush state
	dCtx.stateLock.Lock()
	defer dCtx.stateLock.Unlock()
	if flushErr := dCtx.checkResetInitUnFlushed(); flushErr != nil {
		return flushErr
	}

	return dCtx.addStateLocks(locks...)
}

// Clear all in-memory locks associated with individual transactions, because they are no longer needed/applicable
// Most likely because the state transitions have now been finalized.
//
// Note it's important that this occurs after the confirmation record of creation of a state is fully committed
// to the database, as the in-memory "creating" record for a state will be removed as part of this.
func (dCtx *domainContext) ResetTransactions(transactions ...uuid.UUID) {
	dCtx.stateLock.Lock()
	defer dCtx.stateLock.Unlock()

	newLocks := make([]*components.StateLock, 0)
	for _, lock := range dCtx.txLocks {
		skip := false
		for _, tx := range transactions {
			if lock.Transaction == tx {
				if lock.Type.V() == components.StateLockTypeCreate {
					// Clean up the creating record
					delete(dCtx.creatingStates, lock.State.String())
				}
				skip = true
				break
			}
		}
		if !skip {
			newLocks = append(newLocks, lock)
		}
	}
	dCtx.txLocks = newLocks
}

func (dc *domainContext) StateLocksByTransaction() map[uuid.UUID][]components.StateLock {
	dc.stateLock.Lock()
	defer dc.stateLock.Unlock()

	txLocksCopy := make(map[uuid.UUID][]components.StateLock)
	for _, l := range dc.txLocks {
		txLocksCopy[l.Transaction] = append(txLocksCopy[l.Transaction], *l)
	}
	return txLocksCopy
}

// Reset puts the world back to fresh - including completing any flush.
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
func (dCtx *domainContext) Reset() {
	dCtx.stateLock.Lock()
	defer dCtx.stateLock.Unlock()

	err := dCtx.clearExistingFlush()
	if err != nil {
		log.L(dCtx).Warnf("Reset recovering from flush error: %s", err)
	}

	dCtx.creatingStates = make(map[string]*components.StateWithLabels)
	dCtx.flushing = nil
	dCtx.unFlushed = nil
	dCtx.txLocks = nil
}

func (dCtx *domainContext) Close() {
	dCtx.stateLock.Lock()
	dCtx.closed = true
	dCtx.stateLock.Unlock()

	log.L(dCtx).Debugf("Domain context %s for domain %s contract %s closed", dCtx.id, dCtx.domainName, dCtx.contractAddress)

	dCtx.ss.domainContextLock.Lock()
	defer dCtx.ss.domainContextLock.Unlock()
	delete(dCtx.ss.domainContexts, dCtx.id)
}

func (dCtx *domainContext) clearExistingFlush() error {
	// If we are already flushing, then we wait for that flush while holding the lock
	// here - until we can queue up the next flush.
	// e.g. we only get one flush ahead
	if dCtx.flushing != nil {
		select {
		case <-dCtx.flushing.flushed:
		case <-dCtx.Done():
			// The caller gave up on us, we cannot flush
			return i18n.NewError(dCtx, msgs.MsgContextCanceled)
		}
		return dCtx.flushing.flushResult
	}
	return nil
}

func (dCtx *domainContext) InitiateFlush(asyncCallback func(err error)) error {
	dCtx.stateLock.Lock()
	defer dCtx.stateLock.Unlock()

	// Sync check if there's already an error
	if err := dCtx.clearExistingFlush(); err != nil {
		return err
	}

	// Ok we're good to go async
	flushing := dCtx.unFlushed
	dCtx.flushing = flushing
	dCtx.unFlushed = nil
	// Always dispatch a routine for the callback
	// even if there's a nil flushing - meaning nothing to do
	if flushing != nil {
		flushing.flushed = make(chan struct{})
		dCtx.ss.writer.queue(dCtx, flushing)
	}
	go dCtx.doFlush(asyncCallback, flushing)
	return nil
}

// MUST hold the lock to call this function
// Simply checks there isn't an un-cleared error that means the caller must reset.
func (dCtx *domainContext) checkResetInitUnFlushed() error {
	if dCtx.closed {
		return i18n.NewError(dCtx, msgs.MsgStateDomainContextClosed)
	}
	// Peek if there's a broken flush that needs a reset
	if dCtx.flushing != nil {
		select {
		case <-dCtx.flushing.flushed:
			if dCtx.flushing.flushResult != nil {
				log.L(dCtx).Errorf("flush %s failed - domain context must be reset", dCtx.flushing.id)
				return i18n.WrapError(dCtx, dCtx.flushing.flushResult, msgs.MsgStateFlushFailedDomainReset, dCtx.domainName, dCtx.contractAddress)

			}
		default:
		}
	}
	if dCtx.unFlushed == nil {
		dCtx.unFlushed = dCtx.ss.writer.newWriteOp(dCtx.domainName, dCtx.contractAddress)
	}
	return nil
}

// MUST NOT hold the lock to call this function - instead pass in a list of all the
// unflushed writers (max 2 in practice) that need to be successful for this flush to
// be considered complete
func (dCtx *domainContext) doFlush(cb func(error), flushing *writeOperation) {
	var err error
	// We might have found by the time we got the lock to flush, there was nothing to do
	if flushing != nil {
		log.L(dCtx).Debugf("waiting for flush %s", flushing.id)
		err = flushing.flush(dCtx)
		flushing.flushResult = err // for any other routines the blocked waiting
		log.L(dCtx).Debugf("flush %s completed (err=%v)", flushing.id, err)
		close(flushing.flushed)
	}
	cb(err)
}
