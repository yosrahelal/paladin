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

package ptxapi

import (
	"github.com/google/uuid"
	"github.com/kaleido-io/paladin/toolkit/pkg/tktypes"
)

// These are user-supplied directly on the external interface (vs. calculated)
// If set these affect the submission of the public transaction.
// All are optional
type PublicTxOptions struct {
	Gas                  *tktypes.HexUint64  `json:"gas,omitempty"`
	MaxPriorityFeePerGas *tktypes.HexUint256 `json:"maxPriorityFeePerGas,omitempty"`
	MaxFeePerGas         *tktypes.HexUint256 `json:"maxFeePerGas,omitempty"`
	GasPrice             *tktypes.HexUint256 `json:"gasPrice,omitempty"`
	Value                *tktypes.HexUint256 `json:"value,omitempty"`
}

type PublicTxInput struct {
	From tktypes.EthAddress  `json:"from"`         // unresolved signing account locator (public TX manager will resolve)
	To   *tktypes.EthAddress `json:"to,omitempty"` // target contract address, or nil for deploy
	PublicTxOptions
	Data tktypes.HexBytes `json:"data,omitempty"` // the pre-encoded calldata
}

type PublicTx struct {
	Transaction   uuid.UUID `json:"transaction"`             // the paladin transaction containing this public transaction
	ResubmitIndex int       `json:"resubmitIndex,omitempty"` // resubmission of the public transaction can occur for private transactions, meaning more than one public TX
	PublicTxInput
	Nonce tktypes.HexUint64 `json:"nonce"` // unresolved signing account locator (public TX manager will resolve)
}
