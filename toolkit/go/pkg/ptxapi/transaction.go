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
	"github.com/hyperledger/firefly-signer/pkg/abi"
	"github.com/kaleido-io/paladin/toolkit/pkg/tktypes"
)

type TransactionType string

const (
	TransactionTypePrivate TransactionType = "private"
	TransactionTypePublic  TransactionType = "public"
)

func (tt TransactionType) Enum() tktypes.Enum[TransactionType] {
	return tktypes.Enum[TransactionType](tt)
}

func (tt TransactionType) Options() []string {
	return []string{
		string(TransactionTypePrivate),
		string(TransactionTypePublic),
	}
}

type TransactionStatus string

const (
	TransactionStatusPending TransactionStatus = "pending"
)

func (ts TransactionStatus) Enum() tktypes.Enum[TransactionStatus] {
	return tktypes.Enum[TransactionStatus](ts)
}

func (ts TransactionStatus) Options() []string {
	return []string{
		string(TransactionStatusPending),
	}
}

type TransactionInput struct {
	IdempotencyKey string                        `json:"idempotencyKey,omitempty"`
	Type           tktypes.Enum[TransactionType] `json:"type"`
	Domain         string                        `json:"domain,omitempty"`
	From           string                        `json:"from"`
	To             *tktypes.EthAddress           `json:"to,omitempty"`
	Function       abi.Entry                     `json:"function,omitempty"`
	Inputs         tktypes.RawJSON               `json:"inputs,omitempty"`
}

type Transaction struct {
	ID string `json:"id"`
	TransactionInput
	Created tktypes.Timestamp               `json:"created"`
	Status  tktypes.Enum[TransactionStatus] `json:"status"`
}
