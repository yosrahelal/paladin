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

package publictxstore

import (
	"context"

	"github.com/google/uuid"
	"github.com/hyperledger/firefly-signer/pkg/ethsigner"
	"github.com/hyperledger/firefly-signer/pkg/ethtypes"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"

	"github.com/hyperledger/firefly-common/pkg/fftypes"
	"github.com/kaleido-io/paladin/core/internal/components"
	"github.com/kaleido-io/paladin/core/pkg/blockindexer"
	"github.com/kaleido-io/paladin/toolkit/pkg/confutil"
	"github.com/kaleido-io/paladin/toolkit/pkg/tktypes"
)

// public_transactions
type PublicTransaction struct {
	ID                     uuid.UUID           `gorm:"column:id;primaryKey"`
	Created                tktypes.Timestamp   `gorm:"column:created;autoCreateTime:nano"`
	Updated                tktypes.Timestamp   `gorm:"column:updated;autoCreateTime:nano"`
	Status                 string              `gorm:"column:status"`
	SubStatus              string              `gorm:"column:sub_status"`
	TxFrom                 string              `gorm:"column:tx_from"`
	TxTo                   *tktypes.EthAddress `gorm:"column:tx_to,omitempty"`
	TxNonce                uint64              `gorm:"column:tx_nonce"`
	TxGasLimit             *uint64             `gorm:"column:tx_gas_limit,omitempty"`
	TxValue                *uint64             `gorm:"column:tx_value,omitempty"`
	TxGasPrice             *uint64             `gorm:"column:tx_gas_price,omitempty"`
	TxMaxFeePerGas         *uint64             `gorm:"column:tx_max_fee_per_gas,omitempty"`
	TxMaxPriorityFeePerGas *uint64             `gorm:"column:tx_max_priority_fee_per_gas,omitempty"`
	TxData                 *string             `gorm:"column:tx_data,omitempty"`
	TxHash                 *tktypes.Bytes32    `gorm:"column:tx_hash,omitempty"`
	FirstSubmit            *tktypes.Timestamp  `gorm:"column:first_submit,omitempty"`
	LastSubmit             *tktypes.Timestamp  `gorm:"column:last_submit,omitempty"`
	ErrorMessage           *string             `gorm:"column:error_message,omitempty"`
	SubmittedHashes        []*PublicTransactionHash
}

// public_transaction_hashes
type PublicTransactionHash struct {
	PublicTxID uuid.UUID       `gorm:"column:public_tx_id"`
	Hash       tktypes.Bytes32 `gorm:"column:hash;primaryKey"`
}

func (pts *pubTxStore) GetTransactionByID(ctx context.Context, txID string) (*components.PublicTX, error) {
	// ptx, cached := pts.publicTxCache.Get(txID)
	// if cached {
	// 	return ptx, nil
	// }

	var dbTxModel *PublicTransaction
	if err := pts.p.DB().WithContext(ctx).Table("public_transactions").Omit("SubmittedHashes").Where("id = ?", txID).Limit(1).First(&dbTxModel).Error; err != nil {
		return nil, err
	}

	// retrieve associated transaction hashes
	if dbTxModel != nil {

		// Retrieve all hashes for the transaction
		var txHashes []*PublicTransactionHash
		if err := pts.p.DB().WithContext(ctx).Table("public_transaction_hashes").
			Where("public_tx_id = ?", dbTxModel.ID).Find(&txHashes).Error; err != nil {
			return nil, err
		}
		dbTxModel.SubmittedHashes = append(dbTxModel.SubmittedHashes, txHashes...)

	}

	pubTxObject := MapDBToInternal(dbTxModel)

	// pts.publicTxCache.Set(txID, pubTxObject)
	return pubTxObject, nil
}

func (pts *pubTxStore) InsertTransaction(ctx context.Context, dbTx *gorm.DB, tx *components.PublicTX) error {
	if dbTx == nil {
		pts.writer.queue(ctx, pts.writer.newWriteOp(MapInternalToDB(tx)))
	} else {
		dbTx.Table("public_transactions").Omit("SubmittedHashes").Create(MapInternalToDB(tx))
	}
	return nil
}
func (pts *pubTxStore) UpdateTransaction(ctx context.Context, txID string, updates *components.BaseTXUpdates) error {
	var dbTxModel *PublicTransaction
	if err := pts.p.DB().WithContext(ctx).Table("public_transactions").Omit("SubmittedHashes").Where("id = ?", txID).Limit(1).First(&dbTxModel).Error; err != nil {
		return err
	}
	// Track if we need to perform an update
	updated := false

	// Apply updates only to non-nil fields
	if updates.Status != nil {
		dbTxModel.Status = string(*updates.Status)
		updated = true
	}

	if updates.GasPrice != nil {
		dbTxModel.TxGasPrice = confutil.P(updates.GasPrice.Uint64())
		updated = true
	}
	if updates.MaxPriorityFeePerGas != nil {
		dbTxModel.TxMaxPriorityFeePerGas = confutil.P(updates.MaxPriorityFeePerGas.Uint64())
		updated = true
	}
	if updates.MaxFeePerGas != nil {
		dbTxModel.TxMaxFeePerGas = confutil.P(updates.MaxFeePerGas.Uint64())
		updated = true
	}
	if updates.GasLimit != nil {
		dbTxModel.TxGasLimit = confutil.P(updates.GasLimit.Uint64())
		updated = true
	}
	if updates.TransactionHash != nil {
		dbTxModel.TxHash = updates.TransactionHash
		updated = true
	}
	if updates.FirstSubmit != nil {
		dbTxModel.FirstSubmit = updates.FirstSubmit
		updated = true
	}
	if updates.LastSubmit != nil {
		dbTxModel.LastSubmit = updates.LastSubmit
		updated = true
	}
	if updates.ErrorMessage != nil {
		dbTxModel.ErrorMessage = updates.ErrorMessage
		updated = true
	}

	// Insert new submitted hashes if provided
	if updates.NewSubmittedHashes != nil && len(updates.NewSubmittedHashes) > 0 {
		if err := pts.p.DB().WithContext(ctx).Table("public_transaction_hashes").
			Clauses(clause.OnConflict{
				Columns:   []clause.Column{{Name: "hash"}},
				DoNothing: true, // immutable
			}).
			Create(MapInternalSubmittedHashes(dbTxModel.ID, updates.NewSubmittedHashes)).Error; err != nil {
			return err
		}
		updated = true

	}

	// Save the updated transaction only if there were changes
	if updated {
		if err := pts.p.DB().WithContext(ctx).Table("public_transactions").Omit("SubmittedHashes").Save(&dbTxModel).Error; err != nil {
			return err
		}
	}
	return nil
}

func (pts *pubTxStore) GetConfirmedTransaction(ctx context.Context, txID string) (iTX *blockindexer.IndexedTransaction, err error) {
	return nil, nil
}

func (pts *pubTxStore) UpdateSubStatus(ctx context.Context, txID string, subStatus components.PubTxSubStatus, action components.BaseTxAction, info *fftypes.JSONAny, err *fftypes.JSONAny, actionOccurred *tktypes.Timestamp) error {
	ptx, getTxErr := pts.GetTransactionByID(ctx, txID)
	if getTxErr != nil || ptx == nil {
		return getTxErr
	}
	if ptx.SubStatus != subStatus {
		if err := pts.UpdateTransaction(ctx, txID, &components.BaseTXUpdates{
			SubStatus: &subStatus,
		}); err != nil {
			return err
		}
	}
	return nil

}

func (pts *pubTxStore) ListTransactions(ctx context.Context, filter *components.PubTransactionQueries) ([]*components.PublicTX, error) {
	var transactions []*PublicTransaction
	query := pts.p.DB().WithContext(ctx).Table("public_transactions").Omit("SubmittedHashes")

	// Apply dynamic filters
	if len(filter.InIDs) > 0 {
		query = query.Where("id IN ?", filter.InIDs)
	}

	if len(filter.NotInIDs) > 0 {
		query = query.Where("id NOT IN ?", filter.NotInIDs)
	}
	if len(filter.InStatus) > 0 {
		query = query.Where("status IN ?", filter.InStatus)
	}
	if len(filter.NotFrom) > 0 {
		query = query.Where("tx_from NOT IN ?", filter.NotFrom)
	}
	if filter.From != nil {
		query = query.Where("tx_from = ?", *filter.From)
	}
	if filter.To != nil {
		query = query.Where("tx_to = ?", *filter.To)
	}
	if filter.AfterNonce != nil {
		query = query.Where("nonce > ?", filter.AfterNonce)
	}
	if filter.HasTxValue {
		query = query.Where("tx_value IS NOT NULL")
	}

	if filter.Sort != nil {
		query = query.Order(*filter.Sort)
	} else {
		query = query.Order("created ASC")
	}

	// Limit results if specified
	if filter.Limit != nil {
		query = query.Limit(*filter.Limit)
	}

	// Execute the query and return the results
	if err := query.Find(&transactions).Error; err != nil {
		return nil, err
	}

	// retrieve associated transaction hashes
	if len(transactions) > 0 {
		txIDs := []*uuid.UUID{}
		for _, tx := range transactions {
			txIDs = append(txIDs, &tx.ID)
		}

		// Retrieve all hashes for the transaction IDs
		var txHashes []*PublicTransactionHash
		if err := pts.p.DB().WithContext(ctx).Table("public_transaction_hashes").
			Where("public_tx_id IN ?", txIDs).Find(&txHashes).Error; err != nil {
			return nil, err
		}

		// Create a map to group hashes by transaction ID
		txHashMap := make(map[uuid.UUID][]*PublicTransactionHash)
		for _, txH := range txHashes {
			txHashMap[txH.PublicTxID] = append(txHashMap[txH.PublicTxID], txH)
		}

		// Assign hashes back to the corresponding transactions
		for _, tx := range transactions {
			if hashes, ok := txHashMap[tx.ID]; ok {
				tx.SubmittedHashes = hashes
			}
		}
	}

	return MapDBToInternalBatch(transactions), nil
}

func MapDBToInternalBatch(dbTxs []*PublicTransaction) []*components.PublicTX {
	var internalTxs []*components.PublicTX
	for _, dbTx := range dbTxs {
		internalTx := MapDBToInternal(dbTx)
		internalTxs = append(internalTxs, internalTx)
	}
	return internalTxs
}

func MapDBToInternal(dbTx *PublicTransaction) *components.PublicTX {
	return &components.PublicTX{
		ID:        dbTx.ID,
		Created:   dbTx.Created,
		Updated:   dbTx.Updated,
		Status:    components.PubTxStatus(dbTx.Status),
		SubStatus: components.PubTxSubStatus(dbTx.SubStatus),
		Transaction: &ethsigner.Transaction{
			From:                 []byte(dbTx.TxFrom),
			To:                   dbTx.TxTo.Address0xHex(),
			Nonce:                ethtypes.NewHexIntegerU64(dbTx.TxNonce),
			GasLimit:             safeHexIntegerPtr(dbTx.TxGasLimit),
			Value:                safeHexIntegerPtr(dbTx.TxValue),
			GasPrice:             safeHexIntegerPtr(dbTx.TxGasPrice),
			MaxFeePerGas:         safeHexIntegerPtr(dbTx.TxMaxFeePerGas),
			MaxPriorityFeePerGas: safeHexIntegerPtr(dbTx.TxMaxPriorityFeePerGas),
			Data:                 ethtypes.MustNewHexBytes0xPrefix(*dbTx.TxData),
		},
		TransactionHash: dbTx.TxHash,
		FirstSubmit:     dbTx.FirstSubmit,
		LastSubmit:      dbTx.LastSubmit,
		ErrorMessage:    dbTx.ErrorMessage,
		SubmittedHashes: MapSubmittedHashes(dbTx.SubmittedHashes),
	}
}

func MapSubmittedHashes(dbHashes []*PublicTransactionHash) []string {
	var hashes []string
	for _, h := range dbHashes {
		hashes = append(hashes, h.Hash.String())
	}
	return hashes
}

func MapInternalToDBBatch(internalTxs []*components.PublicTX) []*PublicTransaction {
	var dbTxs []*PublicTransaction
	for _, internalTx := range internalTxs {
		dbTx := MapInternalToDB(internalTx)
		dbTxs = append(dbTxs, dbTx)
	}
	return dbTxs
}

func MapInternalToDB(internalTx *components.PublicTX) *PublicTransaction {
	if internalTx == nil {
		return nil
	}

	// Initialize default values to avoid nil dereference
	var txTo *tktypes.EthAddress
	if internalTx.To != nil {
		txTo = (*tktypes.EthAddress)(internalTx.To)
	}

	var txData *string
	if internalTx.Data != nil {
		txData = confutil.P(internalTx.Data.String())
	}

	return &PublicTransaction{
		ID:                     internalTx.ID,
		Created:                internalTx.Created,
		Updated:                internalTx.Updated,
		Status:                 string(internalTx.Status),
		SubStatus:              string(internalTx.SubStatus),
		TxFrom:                 string(internalTx.From),
		TxTo:                   txTo,
		TxNonce:                internalTx.Nonce.Uint64(),
		TxGasLimit:             safeUint64Ptr(internalTx.GasLimit),
		TxValue:                safeUint64Ptr(internalTx.Value),
		TxGasPrice:             safeUint64Ptr(internalTx.GasPrice),
		TxMaxFeePerGas:         safeUint64Ptr(internalTx.MaxFeePerGas),
		TxMaxPriorityFeePerGas: safeUint64Ptr(internalTx.MaxPriorityFeePerGas),
		TxData:                 txData,
		TxHash:                 internalTx.TransactionHash,
		FirstSubmit:            internalTx.FirstSubmit,
		LastSubmit:             internalTx.LastSubmit,
		ErrorMessage:           internalTx.ErrorMessage,
		SubmittedHashes:        MapInternalSubmittedHashes(internalTx.ID, internalTx.SubmittedHashes),
	}
}

func MapInternalSubmittedHashes(txID uuid.UUID, internalHashes []string) []*PublicTransactionHash {
	if len(internalHashes) == 0 {
		return nil
	}

	var hashes []*PublicTransactionHash
	for _, h := range internalHashes {
		hashes = append(hashes, &PublicTransactionHash{
			Hash:       tktypes.MustParseBytes32(h),
			PublicTxID: txID,
		})
	}
	return hashes
}

func safeUint64Ptr(hi *ethtypes.HexInteger) *uint64 {
	if hi == nil {
		return nil
	}
	return confutil.P(hi.Uint64())
}

func safeHexIntegerPtr(ui *uint64) *ethtypes.HexInteger {
	if ui == nil {
		return nil
	}
	return ethtypes.NewHexIntegerU64(*ui)
}
