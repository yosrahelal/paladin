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

package ptmgrtypes

import (
	"github.com/kaleido-io/paladin/core/pkg/proto/sequence"
	"github.com/kaleido-io/paladin/toolkit/pkg/prototk"
)

type PrivateTransactionEvent interface {
	GetTransactionID() string
	GetContractAddress() string
	SetContractAddress(string)
}

type PrivateTransactionEventBase struct {
	TransactionID   string
	ContractAddress string
}

func (e *PrivateTransactionEventBase) GetTransactionID() string {
	return e.TransactionID
}

func (e *PrivateTransactionEventBase) GetContractAddress() string {
	return e.ContractAddress
}

func (e *PrivateTransactionEventBase) SetContractAddress(contractAddress string) {
	e.ContractAddress = contractAddress
}

type TransactionSubmittedEvent struct {
	PrivateTransactionEventBase
}
type TransactionAssembledEvent struct {
	PrivateTransactionEventBase
	sequence.TransactionAssembledEvent
}
type TransactionSignedEvent struct {
	PrivateTransactionEventBase
	AttestationResult *prototk.AttestationResult
}
type TransactionEndorsedEvent struct {
	PrivateTransactionEventBase
	RevertReason *string
	Endorsement  *prototk.AttestationResult
}
type TransactionDispatchedEvent struct {
	PrivateTransactionEventBase
	Nonce          uint64
	SigningAddress string
}
type TransactionConfirmedEvent struct {
	PrivateTransactionEventBase
}
type TransactionRevertedEvent struct {
	PrivateTransactionEventBase
}
type TransactionDelegatedEvent struct {
	PrivateTransactionEventBase
}
type TransactionBlockedEvent struct {
	PrivateTransactionEventBase
}
