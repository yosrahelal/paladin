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

	"github.com/google/uuid"
	"github.com/kaleido-io/paladin/core/internal/components"
	"github.com/kaleido-io/paladin/core/internal/filters"
	"github.com/kaleido-io/paladin/toolkit/pkg/log"
	"github.com/kaleido-io/paladin/toolkit/pkg/pldapi"
	"github.com/kaleido-io/paladin/toolkit/pkg/query"
	"github.com/kaleido-io/paladin/toolkit/pkg/tktypes"
	"gorm.io/gorm"
)

// DB persisted record for a prepared transaction
type preparedTransaction struct {
	ID          uuid.UUID         `gorm:"column:id"`
	Created     tktypes.Timestamp `gorm:"column:created"`
	Transaction tktypes.RawJSON   `gorm:"column:transaction"`
	ExtraData   tktypes.RawJSON   `gorm:"column:extra_data"`
}

func (preparedTransaction) TableName() string {
	return "prepared_txns"
}

type preparedStateType string

const (
	preparedSpend   preparedStateType = "spend"
	preparedRead    preparedStateType = "read"
	preparedConfirm preparedStateType = "confirm"
	preparedInfo    preparedStateType = "info"
)

type preparedTransactionState struct {
	Transaction uuid.UUID         `gorm:"column:transaction"`
	StateID     tktypes.HexBytes  `gorm:"column:state"`
	Type        preparedStateType `gorm:"column:type"`
	State       *pldapi.StateBase `gorm:"foreignKey:state;references:id;"`
}

func (preparedTransactionState) TableName() string {
	return "prepared_txn_states"
}

var preparedTransactionFilters = filters.FieldMap{
	"id":      filters.UUIDField(`"transaction"`),
	"created": filters.TimestampField("created"),
}

func (tm *txManager) WritePreparedTransactions(ctx context.Context, dbTX *gorm.DB, prepared ...*components.PrepareTransactionWithRefs) (err error) {

	var preparedTxInserts []*preparedTransaction
	var preparedTxStateInserts []*preparedTransactionState
	for _, p := range prepared {
		p.Transaction.ID = nil
		p.Transaction.Created = 0
		dbPreparedTx := &preparedTransaction{
			ID:        *p.Transaction.ID,
			ExtraData: p.ExtraData,
		}
		if dbPreparedTx.Transaction, err = json.Marshal(p.Transaction); err != nil {
			return err
		}
		preparedTxInserts = append(preparedTxInserts, dbPreparedTx)
		for _, stateID := range p.States.Spent {
			preparedTxStateInserts = append(preparedTxStateInserts, &preparedTransactionState{
				Transaction: p.ID,
				StateID:     stateID,
				Type:        preparedSpend,
			})
		}
		for _, stateID := range p.States.Read {
			preparedTxStateInserts = append(preparedTxStateInserts, &preparedTransactionState{
				Transaction: p.ID,
				StateID:     stateID,
				Type:        preparedRead,
			})
		}
		for _, stateID := range p.States.Confirmed {
			preparedTxStateInserts = append(preparedTxStateInserts, &preparedTransactionState{
				Transaction: p.ID,
				StateID:     stateID,
				Type:        preparedConfirm,
			})
		}
		for _, stateID := range p.States.Info {
			preparedTxStateInserts = append(preparedTxStateInserts, &preparedTransactionState{
				Transaction: p.ID,
				StateID:     stateID,
				Type:        preparedInfo,
			})
		}
		log.L(ctx).Infof("Inserting prepared %s transaction for transaction %s with spent=%d read=%d confirmed=%d info=%d",
			p.Transaction.Type, p.ID, len(p.States.Spent), len(p.States.Read), len(p.States.Confirmed), len(p.States.Info))
	}

	if len(preparedTxInserts) > 0 {
		err = dbTX.WithContext(ctx).
			Create(preparedTxInserts).
			Error
	}

	if err == nil && len(preparedTxStateInserts) > 0 {
		err = dbTX.WithContext(ctx).
			Omit("State").
			Create(preparedTxStateInserts).
			Error
	}

	return err

}

func (tm *txManager) QueryPreparedTransactions(ctx context.Context, dbTX *gorm.DB, jq *query.QueryJSON) ([]*pldapi.PreparedTransaction, error) {
	qw := &queryWrapper[preparedTransaction, pldapi.PreparedTransaction]{
		p:           tm.p,
		table:       "prepared_txns",
		defaultSort: "-created",
		filters:     preparedTransactionFilters,
		query:       jq,
		mapResult: func(pt *preparedTransaction) (*pldapi.PreparedTransaction, error) {
			preparedTx := &pldapi.PreparedTransaction{
				ID:        pt.ID,
				ExtraData: pt.ExtraData,
			}
			return preparedTx, json.Unmarshal(pt.Transaction, &preparedTx.Transaction)
		},
	}
	preparedTransactions, err := qw.run(ctx, dbTX)
	if err != nil {
		return nil, err
	}
	if len(preparedTransactions) > 0 {
		transactionIDs := make([]uuid.UUID, len(preparedTransactions))
		for i, pt := range preparedTransactions {
			transactionIDs[i] = pt.ID
		}
		var preparedStates []*preparedTransactionState
		err dbTX
	}
	return preparedTransactions, nil
}
