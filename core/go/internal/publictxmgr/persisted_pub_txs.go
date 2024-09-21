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
	"github.com/google/uuid"

	"github.com/kaleido-io/paladin/toolkit/pkg/tktypes"
)

// public_transactions
type persistedPubTx struct {
	From            tktypes.EthAddress  `gorm:"column:from;primaryKey"`
	Nonce           uint64              `gorm:"column:nonce;primaryKey"`
	Created         tktypes.Timestamp   `gorm:"column:created;autoCreateTime:nano"`
	Transaction     uuid.UUID           `gorm:"column:transaction"`  // only unique when combined with ResubmitIndex
	ResubmitIndex   int                 `gorm:"column:resubmit_idx"` // can have multiple public TX under a single paladin TX for resubmits
	To              *tktypes.EthAddress `gorm:"column:to"`
	Gas             uint64              `gorm:"column:gas"`
	FixedGasPricing tktypes.RawJSON     `gorm:"column:fixed_gas_pricing"`
	Value           *tktypes.HexUint256 `gorm:"column:value"`
	Data            tktypes.HexBytes    `gorm:"column:data"`
	Completed       bool                `gorm:"column:completed"` // excluded from processing because it's done (set in DB TX passed into us by receipt processor)
	Suspended       bool                `gorm:"column:suspended"` // excluded from processing because it's suspended by user
}

type persistedTxSubmission struct {
	SignerNonceRef  string            `gorm:"column:signer_nonce_ref;primaryKey"` // simplifies lookups for us to do the compound key, rather than having two columns
	Created         tktypes.Timestamp `gorm:"column:created;autoCreateTime:nano"`
	TransactionHash tktypes.HexBytes  `gorm:"column:tx_hash"`
	GasPricing      tktypes.RawJSON   `gorm:"column:gas_pricing"` // no filtering allowed on this field as it's complex JSON gasPrice/maxFeePerGas/maxPriorityFeePerGas calculation
}
