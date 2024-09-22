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

package publictxmgr

import (
	"fmt"
	"strings"

	"github.com/google/uuid"

	"github.com/kaleido-io/paladin/toolkit/pkg/tktypes"
)

// public_transactions
type persistedPubTx struct {
	SignerNonce     string                   `gorm:"column:signer_nonce;primaryKey"`
	From            tktypes.EthAddress       `gorm:"column:from"`
	Nonce           uint64                   `gorm:"column:nonce"`
	Created         tktypes.Timestamp        `gorm:"column:created;autoCreateTime:nano"`
	Transaction     uuid.UUID                `gorm:"column:transaction"`  // only unique when combined with ResubmitIndex
	ResubmitIndex   int                      `gorm:"column:resubmit_idx"` // can have multiple public TX under a single paladin TX for resubmits
	KeyHandle       string                   `gorm:"column:key_handle"`   // TODO: might need to revisit storing this once we have reverse lookup in the keymanager by address
	To              *tktypes.EthAddress      `gorm:"column:to"`
	Gas             uint64                   `gorm:"column:gas"`
	FixedGasPricing tktypes.RawJSON          `gorm:"column:fixed_gas_pricing"`
	Value           *tktypes.HexUint256      `gorm:"column:value"`
	Data            tktypes.HexBytes         `gorm:"column:data"`
	Suspended       bool                     `gorm:"column:suspended"`                                 // excluded from processing because it's suspended by user
	Completed       *publicCompletion        `gorm:"foreignKey:signer_nonce;references:signer_nonce;"` // excluded from processing because it's done
	Submissions     []*persistedTxSubmission `gorm:"-"`                                                // we do the aggregation, not GORM
}

func (ptx *persistedPubTx) getIDString() string {
	// Use as a single string to identify this transaction in in-memory maps, and helpful too for logging
	return fmt.Sprintf("%s:%d[%s:%d]",
		ptx.Transaction, ptx.ResubmitIndex,
		ptx.From, ptx.Nonce)
}

type persistedTxSubmission struct {
	SignerNonce     string            `gorm:"column:signer_nonce;primaryKey"`
	Created         tktypes.Timestamp `gorm:"column:created:autoCreateTime:false"` // we set this as we track the record in memory too
	TransactionHash tktypes.Bytes32   `gorm:"column:tx_hash"`
	GasPricing      tktypes.RawJSON   `gorm:"column:gas_pricing"` // no filtering allowed on this field as it's complex JSON gasPrice/maxFeePerGas/maxPriorityFeePerGas calculation
}

type publicCompletion struct {
	SignerNonce     string          `gorm:"column:signer_nonce;primaryKey"`
	TransactionHash tktypes.Bytes32 `gorm:"column:tx_hash"`
}

func (s *persistedTxSubmission) WriteKey() string {
	// Just use the from address as the write key, so all submissions on the same signing address get batched together
	return strings.Split(s.SignerNonce, ":")[0]
}

type persistedPubTxIDOnly struct {
	Transaction   uuid.UUID `gorm:"column:transaction"`
	ResubmitIndex int       `gorm:"column:resubmit_idx"`
}

type submissionTxReverseLookup struct {
	TransactionHash tktypes.Bytes32       `gorm:"column:tx_hash"`
	SignerNonce     string                `gorm:"column:signer_nonce_ref;primaryKey"`
	PublicTx        *persistedPubTxIDOnly `gorm:"foreignKey:signer_nonce;references:signer_nonce;"`
}
