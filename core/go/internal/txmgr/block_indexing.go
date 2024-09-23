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

	"github.com/google/uuid"
	"github.com/kaleido-io/paladin/core/internal/components"
	"github.com/kaleido-io/paladin/core/pkg/blockindexer"
	"github.com/kaleido-io/paladin/toolkit/pkg/log"
	"github.com/kaleido-io/paladin/toolkit/pkg/ptxapi"
	"github.com/kaleido-io/paladin/toolkit/pkg/tktypes"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

func (tm *txManager) blockIndexerPreCommit(
	ctx context.Context,
	dbTX *gorm.DB,
	blocks []*blockindexer.IndexedBlock,
	transactions []*blockindexer.IndexedTransactionNotify,
) (blockindexer.PostCommit, error) {

	// Pass the list of transactions to the public transaction manager, who will pass us back a list
	// of matches that we need to write receipts for and/or notify the private transaction manager
	// of the completion.
	publicTxMatches, err := tm.publicTxMgr.MatchUpdateConfirmedTransactions(ctx, dbTX, transactions)
	if err != nil {
		return nil, err
	}

	// Work out which we need to write public receipts for, and which we need to ask the private TX mgr about
	privateNotifications := make([]*components.PublicTxMatch, 0, len(publicTxMatches))
	for _, pubTx := range publicTxMatches {
		if pubTx.ParentType == string(ptxapi.TransactionTypePrivate) {
			privateNotifications = append(privateNotifications, pubTx)
		}
	}

	// Notify the private manager, who might ask us to write some more receipts
	finalizedPrivate := make(map[uuid.UUID]bool)
	if len(privateNotifications) > 0 {
		finalizedPrivate, err = tm.privateTxMgr.NotifyConfirmed(ctx, privateNotifications)
		if err != nil {
			return nil, err
		}
	}

	// Ok now we can finally determine which receipts we need - in the ORIGINAL order
	receipts := make([]*transactionReceipt, 0, len(publicTxMatches))
	for _, pubTx := range publicTxMatches {
		if pubTx.ParentType == string(ptxapi.TransactionTypePrivate) || // it's public
			finalizedPrivate[pubTx.Transaction] { // or it's a finalized private
			log.L(ctx).Infof("Writing receipt for %s transaction hash=%s block=%d result=%s",
				pubTx.Transaction, pubTx.Hash, pubTx.BlockNumber, pubTx.Result)
			receipts = append(receipts, tm.buildReceipt(ctx, pubTx, dbTX))
		}
	}

	// Write the receipts themselves - only way of duplicates should be a rewind of
	// the block explorer, so we simply OnConflict ignore
	if len(receipts) > 0 {
		err := dbTX.
			Table("transaction_receipts").
			Clauses(clause.OnConflict{
				Columns:   []clause.Column{{Name: "transaction"}},
				DoNothing: true, // immutable
			}).
			Create(receipts).
			Error
		if err != nil {
			return nil, err
		}
	}

	return func() {
		// We need to notify the public TX manager when the DB transaction for these has completed
		if len(publicTxMatches) > 0 {
			tm.publicTxMgr.NotifyConfirmPersisted(ctx, publicTxMatches)
		}
	}, nil
}

func (tm *txManager) buildReceipt(ctx context.Context, pubTx *components.PublicTxMatch, dbTX *gorm.DB) *transactionReceipt {
	receipt := &transactionReceipt{
		TransactionID:   pubTx.Transaction,
		Indexed:         tktypes.TimestampNow(),
		Success:         pubTx.Result.V() == blockindexer.TXResult_SUCCESS,
		TransactionHash: &pubTx.Hash,
		BlockNumber:     &pubTx.BlockNumber,
		RevertData:      pubTx.RevertReason,
	}
	if len(pubTx.RevertReason) > 0 {
		revertErrString := tm.calculateRevertError(ctx, dbTX, pubTx.RevertReason).Error()
		receipt.FailureMessage = &revertErrString
	}
	return receipt
}
