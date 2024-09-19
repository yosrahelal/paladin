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
	"math/big"

	"github.com/google/uuid"
	"github.com/hyperledger/firefly-signer/pkg/ethsigner"
	"github.com/hyperledger/firefly-signer/pkg/ethtypes"

	"github.com/hyperledger/firefly-common/pkg/fftypes"
	"github.com/kaleido-io/paladin/core/internal/components"
	"github.com/kaleido-io/paladin/core/pkg/blockindexer"
	"github.com/kaleido-io/paladin/toolkit/pkg/confutil"
	"github.com/kaleido-io/paladin/toolkit/pkg/tktypes"
)

// public_transactions
type PublicTransaction struct {
	ID                     uuid.UUID                `gorm:"column:id;primaryKey"`
	Created                tktypes.Timestamp        `gorm:"column:created;autoCreateTime:nano"`
	Updated                tktypes.Timestamp        `gorm:"column:updated"`
	Status                 string                   `gorm:"column:status"`
	SubStatus              string                   `gorm:"column:sub_status"`
	TxFrom                 string                   `gorm:"column:tx_from"`
	TxTo                   *tktypes.EthAddress      `gorm:"column:tx_to,omitempty"`
	TxNonce                big.Int                  `gorm:"column:tx_nonce"`
	TxGasLimit             *big.Int                 `gorm:"column:tx_gas_limit,omitempty"`
	TxValue                *big.Int                 `gorm:"column:tx_value,omitempty"`
	TxGasPrice             *big.Int                 `gorm:"column:tx_gas_price,omitempty"`
	TxMaxFeePerGas         *big.Int                 `gorm:"column:tx_max_fee_per_gas,omitempty"`
	TxMaxPriorityFeePerGas *big.Int                 `gorm:"column:tx_max_priority_fee_per_gas,omitempty"`
	TxData                 *string                  `gorm:"column:tx_data,omitempty"`
	TxHash                 tktypes.Bytes32          `gorm:"column:tx_hash,omitempty"`
	FirstSubmit            tktypes.Timestamp        `gorm:"column:first_submit,omitempty"`
	LastSubmit             tktypes.Timestamp        `gorm:"column:last_submit,omitempty"`
	ErrorMessage           string                   `gorm:"column:error_message,omitempty"`
	SubmittedHashes        []*PublicTransactionHash `gorm:"foreignKey:public_transactions;references:id;"`
}

type PublicTransactionHash struct {
	PublicTxID uuid.UUID       `gorm:"column:public_tx_id"`
	Hash       tktypes.Bytes32 `gorm:"column:hash"`
}

func (pts *pubTxStore) GetTransactionByID(ctx context.Context, txID string) (*components.PublicTX, error) {
	ptx, cached := pts.publicTxCache.Get(txID)
	if cached {
		return ptx, nil
	}

	var pubTx *PublicTransaction

	query := pts.p.DB().Model(&PublicTransaction{}).Joins("LEFT JOIN public_transaction_hashes ON public_transaction_hashes.public_tx_id = public_transactions.id")
	query.Where("public_transactions.id = ?", txID)
	query = query.Preload("SubmittedHashes")
	query = query.Limit(1)
	if err := query.Find(pubTx).Error; err != nil {
		return nil, err
	}
	pubTxObject := &components.PublicTX{}
	pts.publicTxCache.Set(txID, pubTxObject)
	return pubTxObject, nil
}

func (pts *pubTxStore) InsertTransaction(ctx context.Context, tx *components.PublicTX) error {
	pts.writer.queue(ctx, pts.writer.newWriteOp(tx))
	return nil
}
func (pts *pubTxStore) UpdateTransaction(ctx context.Context, txID string, updates *components.BaseTXUpdates) error {
	// pts.writer.queue(ctx, pts.writer.newWriteOp(tx))
	return nil
}
func (pts *pubTxStore) GetConfirmedTransaction(ctx context.Context, txID string) (iTX *blockindexer.IndexedTransaction, err error) {
	return nil, nil
}

func (pts *pubTxStore) AddSubStatusAction(ctx context.Context, txID string, subStatus components.PubTxSubStatus, action components.BaseTxAction, info *fftypes.JSONAny, err *fftypes.JSONAny, actionOccurred *fftypes.FFTime) error {
	ptx, getTxErr := pts.GetTransactionByID(ctx, txID)
	if getTxErr != nil || ptx == nil {
		return getTxErr
	}
	if ptx.SubStatus != subStatus {
		pts.p.DB().UpdateColumn("", "")
	}
	return nil

}

func (pts *pubTxStore) ListTransactions(ctx context.Context, filter *components.PubTransactionQueries) ([]*components.PublicTX, error) {
	var transactions []*PublicTransaction
	query := pts.p.DB().WithContext(ctx).Model(&PublicTransaction{})

	// Apply dynamic filters
	if len(filter.NotIDAND) > 0 {
		query = query.Where("id NOT IN ?", filter.NotIDAND)
	}
	if len(filter.StatusOR) > 0 {
		query = query.Where("status IN ?", filter.StatusOR)
	}
	if len(filter.NotFromAND) > 0 {
		query = query.Where("tx_from NOT IN ?", filter.NotFromAND)
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
	if filter.HasValue {
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

	return MapDBToCodeBatch(transactions), nil
}

func MapDBToCodeBatch(dbTxs []*PublicTransaction) []*components.PublicTX {
	var codeTxs []*components.PublicTX
	for _, dbTx := range dbTxs {
		codeTx := MapDBToCode(dbTx)
		codeTxs = append(codeTxs, codeTx)
	}
	return codeTxs
}

func MapDBToCode(dbTx *PublicTransaction) *components.PublicTX {
	return &components.PublicTX{
		ID:        dbTx.ID,
		Created:   &dbTx.Created,
		Updated:   &dbTx.Updated,
		Status:    components.PubTxStatus(dbTx.Status),
		SubStatus: components.PubTxSubStatus(dbTx.SubStatus),
		Transaction: &ethsigner.Transaction{
			From:                 []byte(dbTx.TxFrom),
			To:                   dbTx.TxTo.Address0xHex(),
			Nonce:                ethtypes.NewHexInteger(&dbTx.TxNonce),
			GasLimit:             ethtypes.NewHexInteger(dbTx.TxGasLimit),
			Value:                ethtypes.NewHexInteger(dbTx.TxValue),
			GasPrice:             ethtypes.NewHexInteger(dbTx.TxGasPrice),
			MaxFeePerGas:         ethtypes.NewHexInteger(dbTx.TxMaxFeePerGas),
			MaxPriorityFeePerGas: ethtypes.NewHexInteger(dbTx.TxMaxPriorityFeePerGas),
			Data:                 ethtypes.MustNewHexBytes0xPrefix(*dbTx.TxData),
		},
		TransactionHash: &dbTx.TxHash,
		FirstSubmit:     &dbTx.FirstSubmit,
		LastSubmit:      &dbTx.LastSubmit,
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

func MapCodeToDBBatch(codeTxs []*components.PublicTX) []*PublicTransaction {
	var dbTxs []*PublicTransaction
	for _, codeTx := range codeTxs {
		dbTx := MapCodeToDB(codeTx)
		dbTxs = append(dbTxs, dbTx)
	}
	return dbTxs
}

func MapCodeToDB(codeTx *components.PublicTX) *PublicTransaction {
	return &PublicTransaction{
		ID:                     codeTx.ID,
		Created:                *codeTx.Created,
		Updated:                *codeTx.Updated,
		Status:                 string(codeTx.Status),
		SubStatus:              string(codeTx.SubStatus),
		TxFrom:                 string(codeTx.From),
		TxTo:                   (*tktypes.EthAddress)(codeTx.To),
		TxNonce:                *codeTx.Nonce.BigInt(),
		TxGasLimit:             codeTx.GasLimit.BigInt(),
		TxValue:                codeTx.Value.BigInt(),
		TxGasPrice:             codeTx.GasPrice.BigInt(),
		TxMaxFeePerGas:         codeTx.MaxFeePerGas.BigInt(),
		TxMaxPriorityFeePerGas: codeTx.MaxPriorityFeePerGas.BigInt(),
		TxData:                 confutil.P(codeTx.Data.String()),
		TxHash:                 *codeTx.TransactionHash,
		FirstSubmit:            *codeTx.FirstSubmit,
		LastSubmit:             *codeTx.LastSubmit,
		ErrorMessage:           codeTx.ErrorMessage,
		SubmittedHashes:        MapCodeSubmittedHashes(codeTx.ID, codeTx.SubmittedHashes),
	}
}

func MapCodeSubmittedHashes(txID uuid.UUID, codeHashes []string) []*PublicTransactionHash {
	var hashes []*PublicTransactionHash
	for _, h := range codeHashes {
		hashes = append(hashes, &PublicTransactionHash{
			Hash:       tktypes.MustParseBytes32(h),
			PublicTxID: txID,
		})
	}
	return hashes
}
