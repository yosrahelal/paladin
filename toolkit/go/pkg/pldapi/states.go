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

package pldapi

import (
	"context"
	"encoding/json"
	"strings"

	"github.com/google/uuid"
	"github.com/hyperledger/firefly-common/pkg/i18n"
	"github.com/kaleido-io/paladin/toolkit/pkg/tkmsgs"
	"github.com/kaleido-io/paladin/toolkit/pkg/tktypes"
)

type SchemaType string

const (
	// ABI schema uses the same semantics as events for defining indexed fields (must be top-level)
	SchemaTypeABI SchemaType = "abi"
)

func (st SchemaType) Enum() tktypes.Enum[SchemaType] {
	return tktypes.Enum[SchemaType](st)
}

func (st SchemaType) Options() []string {
	return []string{
		string(SchemaTypeABI),
	}
}

// Queries against the state store can be made in the context of a
// transaction UUID, or one of the standard qualifiers
// (confirmed/unconfirmed/spent/all)
//
// Note this is not modelled as a normal Paladin Enum, as you can fall back to a UUID.
type StateStatusQualifier string

const StateStatusAvailable StateStatusQualifier = "available"
const StateStatusConfirmed StateStatusQualifier = "confirmed"
const StateStatusUnconfirmed StateStatusQualifier = "unconfirmed"
const StateStatusSpent StateStatusQualifier = "spent"
const StateStatusAll StateStatusQualifier = "all"

func (q *StateStatusQualifier) UnmarshalJSON(b []byte) error {
	var text string
	err := json.Unmarshal(b, &text)
	if err == nil {
		qText := StateStatusQualifier(strings.ToLower(text))
		switch qText {
		case StateStatusAvailable,
			StateStatusConfirmed,
			StateStatusUnconfirmed,
			StateStatusSpent,
			StateStatusAll:
			*q = qText
		default:
			u, err := uuid.Parse(string(text))
			if err != nil {
				return i18n.NewError(context.Background(), tkmsgs.MsgTypesInvalidStateQualifier)
			}
			*q = (StateStatusQualifier)(u.String())
		}
	}
	return err
}

type Schema struct {
	ID         tktypes.Bytes32          `docstruct:"Schema" json:"id"          gorm:"primaryKey"`
	Created    tktypes.Timestamp        `docstruct:"Schema" json:"created"     gorm:"autoCreateTime:false"` // we calculate the created time ourselves due to complex in-memory caching
	DomainName string                   `docstruct:"Schema" json:"domain"`
	Type       tktypes.Enum[SchemaType] `docstruct:"Schema" json:"type"`
	Signature  string                   `docstruct:"Schema" json:"signature"`
	Definition tktypes.RawJSON          `docstruct:"Schema" json:"definition"`
	Labels     []string                 `docstruct:"Schema" json:"labels"      gorm:"type:text[]; serializer:json"`
}

type State struct {
	ID              tktypes.HexBytes   `docstruct:"State" json:"id"                  gorm:"primaryKey"`
	Created         tktypes.Timestamp  `docstruct:"State" json:"created"             gorm:"autoCreateTime:nano"`
	DomainName      string             `docstruct:"State" json:"domain"              gorm:"primaryKey"`
	Schema          tktypes.Bytes32    `docstruct:"State" json:"schema"`
	ContractAddress tktypes.EthAddress `docstruct:"State" json:"contractAddress"`
	Data            tktypes.RawJSON    `docstruct:"State" json:"data"`
	Labels          []*StateLabel      `docstruct:"State" json:"-"                   gorm:"foreignKey:state;references:id;"`
	Int64Labels     []*StateInt64Label `docstruct:"State" json:"-"                   gorm:"foreignKey:state;references:id;"`
	Confirmed       *StateConfirm      `docstruct:"State" json:"confirmed,omitempty" gorm:"foreignKey:state;references:id;"`
	Spent           *StateSpend        `docstruct:"State" json:"spent,omitempty"     gorm:"foreignKey:state;references:id;"`
	Locks           []*StateLock       `docstruct:"State" json:"locks,omitempty"     gorm:"-"` // in memory only processing here
	Nullifier       *StateNullifier    `docstruct:"State" json:"nullifier,omitempty" gorm:"foreignKey:state;references:id;"`
}

type StateWithData struct {
	ID     tktypes.HexBytes `json:"id"`
	Schema tktypes.Bytes32  `json:"schema"`
	Data   tktypes.HexBytes `json:"data"`
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
	DomainName  string           `json:"-"                 gorm:"primaryKey"`
	State       tktypes.HexBytes `json:"-"                 gorm:"primaryKey"`
	Transaction uuid.UUID        `docstruct:"StateConfirm" json:"transaction"`
}

// State record can be updated before, during and after spend records are written
// Immutable once written
type StateSpend struct {
	DomainName  string           `json:"-"                 gorm:"primaryKey"`
	State       tktypes.HexBytes `json:"-"                 gorm:"primaryKey"`
	Transaction uuid.UUID        `docstruct:"StateSpend" json:"transaction"`
}

type StateLockType string

const (
	StateLockTypeCreate StateLockType = "create"
	StateLockTypeRead   StateLockType = "read"
	StateLockTypeSpend  StateLockType = "spend"
)

func (tt StateLockType) Enum() tktypes.Enum[StateLockType] {
	return tktypes.Enum[StateLockType](tt)
}

func (tt StateLockType) Options() []string {
	return []string{
		string(StateLockTypeCreate),
		string(StateLockTypeRead),
		string(StateLockTypeSpend),
	}
}

// State locks record which transaction a state is being locked to, either
// spending a previously confirmed state, or an optimistic record of creating
// (and maybe later spending) a state that is yet to be confirmed.
type StateLock struct {
	DomainName  string                      `json:"-"`
	State       tktypes.HexBytes            `json:"-"`
	Transaction uuid.UUID                   `docstruct:"StateLock" json:"transaction"`
	Type        tktypes.Enum[StateLockType] `docstruct:"StateLock" json:"type"`
}

// State nullifiers are used when a domain chooses to use a separate identifier
// specifically for spending states (i.e. not the state ID).
// Domains that choose to leverage this architecture will create nullifier
// entries for all unspent states, and create a StateSpend entry for the
// nullifier (not for the state) when it is spent.
// Immutable once written
type StateNullifier struct {
	DomainName string           `json:"domain"          gorm:"primaryKey"`
	ID         tktypes.HexBytes `json:"id"              gorm:"primaryKey"`
	State      tktypes.HexBytes `json:"-"`
	Spent      *StateSpend      `json:"spent,omitempty" gorm:"foreignKey:state;references:id;"`
}
