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
	"strings"

	"github.com/google/uuid"
	"github.com/hyperledger/firefly-common/pkg/i18n"
	"github.com/kaleido-io/paladin/core/internal/msgs"
	"gorm.io/gorm"
)

// Queries against the state store can be made in the context of a
// transaction UUID, or one of the standard qualifiers
// (confirmed/unconfirmed/spent/all)
type StateStatusQualifier string

const StateStatusAvailable = "available"
const StateStatusConfirmed = "confirmed"
const StateStatusUnconfirmed = "unconfirmed"
const StateStatusSpent = "spent"
const StateStatusAll = "all"

func (q *StateStatusQualifier) UnmarshalText(b []byte) error {
	text := strings.ToLower(string(b))
	switch text {
	case StateStatusAvailable,
		StateStatusConfirmed,
		StateStatusUnconfirmed,
		StateStatusSpent,
		StateStatusAll:
		*q = StateStatusQualifier(text)
	default:
		u, err := uuid.Parse(string(text))
		if err != nil {
			return i18n.NewError(context.Background(), msgs.MsgStateInvalidQualifier)
		}
		*q = (StateStatusQualifier)(u.String())
	}
	return nil
}

// Only called for one of the static qualifiers - not for a domain context
func (q StateStatusQualifier) whereClause(db *gorm.DB /* must be the DB not the query */) (*gorm.DB, bool) {
	switch q {
	case StateStatusAvailable:
		return db.
				Where(`"Spent"."transaction" IS NULL`).
				Where(`"Confirmed"."transaction" IS NOT NULL`),
			true
	case StateStatusConfirmed:
		return db.
				Where(`"Confirmed"."transaction" IS NOT NULL`).
				Where(`"Spent"."transaction" IS NULL`),
			true
	case StateStatusUnconfirmed:
		return db.
				Where(`"Confirmed"."transaction" IS NULL`),
			true
	case StateStatusSpent:
		return db.
				Where(`"Spent"."transaction" IS NOT NULL`),
			true
	case StateStatusAll:
		return db.Where("TRUE"),
			true
	default:
		// This is a domain context query - so the caller should pass it to the appropriate domain context
		// rather than just executing the query directly against the DB
		return nil, false
	}
}
