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

package components

import (
	"context"

	"github.com/google/uuid"
	"github.com/hyperledger/firefly-signer/pkg/abi"
	"github.com/kaleido-io/paladin/core/internal/filters"
	"github.com/kaleido-io/paladin/toolkit/pkg/query"
	"github.com/kaleido-io/paladin/toolkit/pkg/tktypes"
)

type StateManager interface {
	ManagerLifecycle
	RunInDomainContext(domainName string, contractAddress tktypes.EthAddress, fn DomainContextFunction) error
	RunInDomainContextFlush(domainName string, contractAddress tktypes.EthAddress, fn DomainContextFunction) error
	EnsureABISchemas(ctx context.Context, domainName string, defs []*abi.Parameter) ([]Schema, error)
}

type DomainContextFunction func(ctx context.Context, dsi DomainStateInterface) error

// The DSI is the state interface that is exposed outside of the statestore package, for the
// transaction engine to use to safely query and update the state in the context of a particular
// domain.
//
// A single locked execution context is available per domain private contract, per paladin runtime.
// In the future we may consider more granular execution contexts to increase parallelism.
//
// The locked execution context works only in-memory until explicitly committed, at which point
// all the operations queued up are flushed to the DB asynchronously.
//
// We can then continue to build the next set of flushable operations, while the first set is
// still flushing (a simple pipeline approach).
type DomainStateInterface interface {

	// FindAvailableStates is the main query function, only returning states that are available.
	// Note this does not lock these states in any way, you must call that afterwards as:
	// 1) We don't know which will be selected as important by the domain - some might be un-used
	// 2) We deliberately return states that are locked to a transaction (but not spent yet) - which means the
	//    result of the any assemble that uses those states, will be a transaction that must
	//    be on the same transaction where those states are locked.
	FindAvailableStates(schemaID string, query *query.QueryJSON) (s []*State, err error)

	// FindAvailableNullifiers is similar to FindAvailableStates, but for domains that leverage
	// nullifiers to record spending.
	FindAvailableNullifiers(schemaID string, query *query.QueryJSON) (s []*State, err error)

	// MarkStatesSpending writes a lock record so the state is now locked for spending, and
	// thus subsequent calls to FindAvailableStates will not return these states.
	MarkStatesSpending(transactionID uuid.UUID, stateIDs []string) error

	// MarkStatesRead writes a lock record so the state is now locked to this transaction
	// for reading - thus subsequent calls to FindAvailableStates will return these states
	// with the lock record attached.
	// That will inform them they need to join to this transaction if they wish to use those states.
	MarkStatesRead(transactionID uuid.UUID, stateIDs []string) error

	// MarkStatesSpent writes a spend record so the state is now considered spent, and can
	// no longer be used as an input to a future transaction.
	MarkStatesSpent(transactionID uuid.UUID, stateIDs []string) error

	// MarkStatesConfirmed writes a confirmation record so the state is now confirmed and unspent.
	MarkStatesConfirmed(transactionID uuid.UUID, stateIDs []string) error

	// UpsertStates creates or updates states.
	// They are available immediately within the domain for return in FindAvailableStates
	// on the domain (even before the flush).
	// If a non-nil transaction ID is supplied, then the states are mark locked to the specified
	// transaction. They can then be locked-for-creation, locked-for-spending, for simply
	// locked for existence to avoid other transactions spending them.
	UpsertStates(transactionID *uuid.UUID, states []*StateUpsert) (s []*State, err error)

	// UpsertNullifiers creates nullifier records associated with states.
	// Nullifiers are an alternate state identifier (separate from the state ID) that can be used
	// when recording spent states.
	UpsertNullifiers(nullifiers []*StateNullifier) error

	// ResetTransaction queues up removal of all lock records for a given transaction
	// Note that the private data of the states themselves are not removed
	ResetTransaction(transactionID uuid.UUID) error

	// Flush moves the un-flushed set into flushing status, queueing to a DB writer to batch write
	// to the database.
	// Subsequent calls to the DMI will add to a new un-flushed set.
	//
	// If there is already a flush in progress, this call will BLOCK until that flush has finished.
	//
	// The flush itself then happens asynchronously - any error will be reported back to the next call
	// that happens after the error occurs, and the unFlushed state will be cleared at that point.
	//
	// This reverts the domain back in the same way as a crash-restart.
	//
	// Callback is invoked ONLY on a successful flush, asynchronously on the Domain Context.
	// So if supplied, the caller must not rely on it being called, and must not block holding the
	// domain context until it is called.
	//
	// NOTE: For special cases where a domain callback requires a sync flush or error to complete processing,
	//       use RunInDomainContextFlush()
	Flush(successCallback ...DomainContextFunction) error
}

type State struct {
	ID              tktypes.HexBytes   `json:"id"                  gorm:"primaryKey"`
	Created         tktypes.Timestamp  `json:"created"             gorm:"autoCreateTime:nano"`
	DomainName      string             `json:"domain"              gorm:"primaryKey"`
	Schema          tktypes.Bytes32    `json:"schema"`
	ContractAddress tktypes.EthAddress `json:"contractAddress"`
	Data            tktypes.RawJSON    `json:"data"`
	Labels          []*StateLabel      `json:"-"                   gorm:"foreignKey:state;references:id;"`
	Int64Labels     []*StateInt64Label `json:"-"                   gorm:"foreignKey:state;references:id;"`
	Confirmed       *StateConfirm      `json:"confirmed,omitempty" gorm:"foreignKey:state;references:id;"`
	Spent           *StateSpend        `json:"spent,omitempty"     gorm:"foreignKey:state;references:id;"`
	Locked          *StateLock         `json:"locked,omitempty"    gorm:"foreignKey:state;references:id;"`
	Nullifier       *StateNullifier    `json:"nullifier,omitempty" gorm:"foreignKey:state;references:id;"`
}

type StateUpsert struct {
	ID       tktypes.HexBytes
	SchemaID string
	Data     tktypes.RawJSON
	Creating bool
	Spending bool
}

// StateWithLabels is a newly prepared state that has not yet been persisted
type StateWithLabels struct {
	*State
	LabelValues filters.ValueSet
}

func (s *StateWithLabels) ValueSet() filters.ValueSet {
	return s.LabelValues
}

type StateLabel struct {
	DomainName string           `gorm:"primaryKey"`
	State      tktypes.HexBytes `gorm:"primaryKey"`
	Label      string
	Value      string
}

type StateInt64Label struct {
	DomainName string           `gorm:"primaryKey"`
	State      tktypes.HexBytes `gorm:"primaryKey"`
	Label      string
	Value      int64
}

// State record can be updated before, during and after confirm records are written
// For example the confirmation of the existence of states will be coming all the time
// from the base ledger, for which we will never receive the private state itself.
// Immutable once written
type StateConfirm struct {
	DomainName  string           `json:"domain"       gorm:"primaryKey"`
	State       tktypes.HexBytes `json:"-"            gorm:"primaryKey"`
	Transaction uuid.UUID        `json:"transaction"`
}

// State record can be updated before, during and after spend records are written
// Immutable once written
type StateSpend struct {
	DomainName  string           `json:"domain"       gorm:"primaryKey"`
	State       tktypes.HexBytes `json:"-"            gorm:"primaryKey"`
	Transaction uuid.UUID        `json:"transaction"`
}

// State locks record which transaction a state is being locked to, either
// spending a previously confirmed state, or an optimistic record of creating
// (and maybe later spending) a state that is yet to be confirmed.
type StateLock struct {
	DomainName  string           `json:"domain"       gorm:"primaryKey"`
	State       tktypes.HexBytes `json:"-"            gorm:"primaryKey"`
	Transaction uuid.UUID        `json:"transaction"`
	Creating    bool             `json:"creating"`
	Spending    bool             `json:"spending"`
}

// State nullifiers are used when a domain chooses to use a separate identifier
// specifically for spending states (i.e. not the state ID).
// Domains that choose to leverage this architecture will create nullifier
// entries for all unspent states, and create a StateSpend entry for the
// nullifier (not for the state) when it is spent.
// Immutable once written
type StateNullifier struct {
	DomainName string           `json:"domain"          gorm:"primaryKey"`
	Nullifier  tktypes.HexBytes `json:"nullifier"       gorm:"primaryKey"`
	State      tktypes.HexBytes `json:"-"`
	Spent      *StateSpend      `json:"spent,omitempty" gorm:"foreignKey:state;references:nullifier;"`
}

type Schema interface {
	Type() SchemaType
	IDString() string
	Signature() string
	Persisted() *SchemaPersisted
	ProcessState(ctx context.Context, contractAddress tktypes.EthAddress, data tktypes.RawJSON, id tktypes.HexBytes) (*StateWithLabels, error)
	RecoverLabels(ctx context.Context, s *State) (*StateWithLabels, error)
}

type SchemaType string

const (
	// ABI schema uses the same semantics as events for defining indexed fields (must be top-level)
	SchemaTypeABI SchemaType = "abi"
)

type SchemaPersisted struct {
	ID         tktypes.Bytes32   `json:"id"          gorm:"primaryKey"`
	Created    tktypes.Timestamp `json:"created"     gorm:"autoCreateTime:false"` // we calculate the created time ourselves due to complex in-memory caching
	DomainName string            `json:"domain"`
	Type       SchemaType        `json:"type"`
	Signature  string            `json:"signature"`
	Definition tktypes.RawJSON   `json:"definition"`
	Labels     []string          `json:"labels"      gorm:"type:text[]; serializer:json"`
}
