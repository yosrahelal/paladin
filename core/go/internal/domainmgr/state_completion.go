/*
 * Copyright © 2025 Kaleido, Inc.
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

package domainmgr

import (
	"context"

	"github.com/LFDT-Paladin/paladin/core/internal/components"
	"github.com/LFDT-Paladin/paladin/core/pkg/persistence"
	"github.com/LFDT-Paladin/paladin/sdk/go/pkg/pldtypes"
	"github.com/google/uuid"
	"gorm.io/gorm/clause"
)

// privateStateCompletion tracks confirmed transactions for opted-in domains that are still
// waiting for one or more private states. A row exists only while the transaction is incomplete.
// The table is bounded to the number of currently-outstanding incomplete transactions.
type privateStateCompletion struct {
	Contract         string `gorm:"column:contract;primaryKey"`
	TransactionID    string `gorm:"column:transaction_id;primaryKey"`
	BlockNumber      int64  `gorm:"column:block_number"`
	NextMissingState string `gorm:"column:next_missing_state"`
}

func (privateStateCompletion) TableName() string {
	return "private_state_completion"
}

// WriteStateCompletionForTx is called from the event indexer within the event-stream DB
// transaction after a successful transaction is confirmed for a domain that supports the
// completion index. It calls CheckStateCompletion and either removes a now-complete row or
// upserts a row recording the next missing state.
func (dm *domainManager) WriteStateCompletionForTx(ctx context.Context, dbTX persistence.DBTX, psc components.DomainSmartContract, txID uuid.UUID, blockNumber int64) error {
	txStates, err := dm.stateStore.GetTransactionStates(ctx, dbTX, txID)
	if err != nil {
		return err
	}

	nextMissingStateID, err := psc.Domain().CheckStateCompletion(ctx, dbTX, txID, txStates)
	if err != nil {
		return err
	}

	contractStr := psc.Address().String()
	txIDStr := txID.String()

	if nextMissingStateID == nil {
		// Transaction is already complete — remove any stale row (idempotent).
		return dbTX.DB().
			WithContext(ctx).
			Where("contract = ? AND transaction_id = ?", contractStr, txIDStr).
			Delete(&privateStateCompletion{}).
			Error
	}

	// Upsert: insert or update the row with the current next missing state.
	return dbTX.DB().
		WithContext(ctx).
		Clauses(clause.OnConflict{
			Columns:   []clause.Column{{Name: "contract"}, {Name: "transaction_id"}},
			DoUpdates: clause.AssignmentColumns([]string{"block_number", "next_missing_state"}),
		}).
		Create(&privateStateCompletion{
			Contract:         contractStr,
			TransactionID:    txIDStr,
			BlockNumber:      blockNumber,
			NextMissingState: nextMissingStateID.String(),
		}).
		Error
}

// UpdateStateCompletion is called from the state manager within the state-write DB transaction
// after new states are written. It finds completion rows whose next_missing_state matches one
// of the arrived states and re-evaluates them via CheckStateCompletion.
func (dm *domainManager) UpdateStateCompletion(ctx context.Context, dbTX persistence.DBTX, arrivedStateIDs []pldtypes.HexBytes) error {
	if len(arrivedStateIDs) == 0 {
		return nil
	}

	// Convert to string slice for the IN query.
	arrivedStrs := make([]string, len(arrivedStateIDs))
	for i, id := range arrivedStateIDs {
		arrivedStrs[i] = id.String()
	}

	var rows []privateStateCompletion
	if err := dbTX.DB().
		WithContext(ctx).
		Where("next_missing_state IN ?", arrivedStrs).
		Find(&rows).
		Error; err != nil {
		return err
	}

	for _, row := range rows {
		if err := dm.reEvaluateCompletionRow(ctx, dbTX, row); err != nil {
			return err
		}
	}
	return nil
}

func (dm *domainManager) reEvaluateCompletionRow(ctx context.Context, dbTX persistence.DBTX, row privateStateCompletion) error {
	contractAddr, err := pldtypes.ParseEthAddress(row.Contract)
	if err != nil {
		return err
	}

	dsc, err := dm.GetSmartContractByAddress(ctx, dbTX, *contractAddr)
	if err != nil {
		return err
	}

	txID, err := uuid.Parse(row.TransactionID)
	if err != nil {
		return err
	}

	txStates, err := dm.stateStore.GetTransactionStates(ctx, dbTX, txID)
	if err != nil {
		return err
	}

	nextMissingStateID, err := dsc.Domain().CheckStateCompletion(ctx, dbTX, txID, txStates)
	if err != nil {
		return err
	}

	if nextMissingStateID == nil {
		// Transaction is now complete — remove the row.
		return dbTX.DB().
			WithContext(ctx).
			Where("contract = ? AND transaction_id = ?", row.Contract, row.TransactionID).
			Delete(&privateStateCompletion{}).
			Error
	}

	// Still waiting for a (possibly different) state — update the row.
	return dbTX.DB().
		WithContext(ctx).
		Model(&privateStateCompletion{}).
		Where("contract = ? AND transaction_id = ?", row.Contract, row.TransactionID).
		Update("next_missing_state", nextMissingStateID.String()).
		Error
}

// CheckStateCompletionForContract returns true if there are no outstanding incomplete transactions
// for the given contract in or before the given block. A false result means at least one confirmed
// transaction in that block range is still waiting for private state data.
func (dm *domainManager) CheckStateCompletionForContract(ctx context.Context, dbTX persistence.DBTX, contract string, block int64) (bool, error) {
	var count int64
	err := dbTX.DB().
		WithContext(ctx).
		Model(&privateStateCompletion{}).
		Where("contract = ? AND block_number <= ?", contract, block).
		Count(&count).
		Error
	if err != nil {
		return false, err
	}
	return count == 0, nil
}
