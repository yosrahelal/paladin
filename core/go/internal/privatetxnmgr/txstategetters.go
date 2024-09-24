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

package privatetxnmgr

import (
	"context"

	"github.com/google/uuid"
	"gorm.io/gorm"

	"github.com/kaleido-io/paladin/core/internal/components"
)

type Transaction struct {
	gorm.Model
	ID                 uuid.UUID  `gorm:"type:uuid;default:uuid_generate_v4()"`
	From               string     `gorm:"type:text"`
	SequenceID         *uuid.UUID `gorm:"type:uuid"`
	DomainID           string     `gorm:"type:uuid"`
	SchemaID           string     `gorm:"type:uuid"`
	AssembledRound     int64      `gorm:"type:int"`
	AttestationPlan    string     `gorm:"type:text[]; serializer:json"`
	AttestationResults string     `gorm:"type:text[]; serializer:json"`
	Contract           string     `gorm:"type:uuid"`
	PayloadJSON        *string    `gorm:"type:text"`
	PayloadRLP         *string    `gorm:"type:text"`

	PreReqTxs         []string `gorm:"type:text[]; serializer:json"`
	DispatchNode      string   `gorm:"type:text"`
	DispatchAddress   string   `gorm:"type:text"`
	DispatchTxID      string   `gorm:"type:text"`
	DispatchTxPayload string   `gorm:"type:text"`
	ConfirmedTxHash   string   `gorm:"type:text"`
}

type TransactionWrapper struct {
	Transaction
	*components.PrivateTransaction
}

type TxStateGetters interface {
	HACKGetPrivateTx() *components.PrivateTransaction
	GetContractAddress(ctx context.Context) string
	GetTxID(ctx context.Context) string
}

func (t *TransactionWrapper) HACKGetPrivateTx() *components.PrivateTransaction {
	return t.PrivateTransaction
}

func (t *TransactionWrapper) GetContractAddress(ctx context.Context) string {
	return t.Contract
}

func (t *TransactionWrapper) GetTxID(ctx context.Context) string {
	return t.Transaction.ID.String()
}
