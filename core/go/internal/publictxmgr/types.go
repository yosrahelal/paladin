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

package publictxmgr

import (
	"context"

	"github.com/google/uuid"
	"github.com/hyperledger/firefly-common/pkg/i18n"
	"github.com/hyperledger/firefly-signer/pkg/ethsigner"
	"github.com/hyperledger/firefly-signer/pkg/ethtypes"
	"github.com/kaleido-io/paladin/core/internal/msgs"
	"github.com/kaleido-io/paladin/toolkit/pkg/tktypes"
)

// PublicTransactionEventType is a enum type that contains all types of transaction process events
// that a transaction handler emits.
type PublicTransactionEventType int

const (
	PublicTXProcessSucceeded PublicTransactionEventType = iota
	PublicTXProcessFailed
)

// PubTxStatus is the current status of a transaction
type PubTxStatus string

func (ro *RequestOptions) Validate(ctx context.Context) error {
	if ro.ID == nil {
		return i18n.NewError(ctx, msgs.MsgMissingTransactionID)
	}

	if ro.SignerID == "" {
		return i18n.NewError(ctx, msgs.MsgErrorMissingSignerID)
	}
	return nil
}

const (
	// PubTxStatusPending indicates the operation has been submitted, but is not yet confirmed as successful or failed
	PubTxStatusPending PubTxStatus = "Pending"
	// PubTxStatusSucceeded the infrastructure runtime has returned success for the operation
	PubTxStatusSucceeded PubTxStatus = "Succeeded"
	// PubTxStatusFailed happens when an error is reported by the infrastructure runtime
	PubTxStatusFailed PubTxStatus = "Failed"
	// BaseTxStatusFailed happens when the indexed transaction hash doesn't match any of the submitted hashes
	PubTxStatusConflict PubTxStatus = "Conflict"
	// PubTxStatusSuspended indicates we are not actively doing any work with this transaction right now, until it's resumed to pending again
	PubTxStatusSuspended PubTxStatus = "Suspended"
)

// TXUpdates specifies a set of updates that are possible on the base structure.
//
// Any non-nil fields will be set.
// Sub-objects are set as a whole, apart from TransactionHeaders where each field
// is considered and stored individually.
// JSONAny fields can be set explicitly to null using fftypes.NullString
//
// This is the update interface for the policy engine to update base status on the
// transaction object.
//
// There are separate setter functions for fields that depending on the persistence
// mechanism might be in separate tables - including History, Receipt, and Confirmations
type BaseTXUpdates struct {
	Status               *PubTxStatus         `json:"status"`
	SubStatus            *PubTxSubStatus      `json:"subStatus"`
	GasPrice             *ethtypes.HexInteger `json:"gasPrice,omitempty"`
	MaxPriorityFeePerGas *ethtypes.HexInteger `json:"maxPriorityFeePerGas,omitempty"`
	MaxFeePerGas         *ethtypes.HexInteger `json:"maxFeePerGas,omitempty"`
	GasLimit             *ethtypes.HexInteger `json:"gas,omitempty"` // note this is required for some methods (eth_estimateGas)
	TransactionHash      *tktypes.Bytes32     `json:"transactionHash,omitempty"`
	FirstSubmit          *tktypes.Timestamp   `json:"firstSubmit,omitempty"`
	LastSubmit           *tktypes.Timestamp   `json:"lastSubmit,omitempty"`
	ErrorMessage         *string              `json:"errorMessage,omitempty"`
	NewSubmittedHashes   []string             `json:"submittedHashes,omitempty"`
}

type PublicTX struct {
	ID         uuid.UUID         `json:"id"`
	Created    tktypes.Timestamp `json:"created"`
	Updated    tktypes.Timestamp `json:"updated"`
	Status     PubTxStatus       `json:"status"`
	SubStatus  PubTxSubStatus    `json:"subStatus"`
	SequenceID string            `json:"sequenceId,omitempty"`
	*ethsigner.Transaction
	TransactionHash *tktypes.Bytes32   `json:"transactionHash,omitempty"`
	FirstSubmit     *tktypes.Timestamp `json:"firstSubmit,omitempty"`
	LastSubmit      *tktypes.Timestamp `json:"lastSubmit,omitempty"`
	ErrorMessage    *string            `json:"errorMessage,omitempty"`
	// submitted transaction hashes are in a separate DB table, we load and manage it in memory in the same object for code convenience
	SubmittedHashes []string `json:"submittedHashes,omitempty"`
}

type PublicTransactionEvent struct {
	Type PublicTransactionEventType
	Tx   *PublicTX
}

// Handler checks received transaction process events and dispatch them to an event
// manager accordingly.
type PublicTxEventNotifier interface {
	Notify(ctx context.Context, e PublicTransactionEvent) error
}

type RequestOptions struct {
	ID       *uuid.UUID
	SignerID string
	GasLimit *ethtypes.HexInteger
}

// PubTxSubStatus is an intermediate status a transaction may go through
type PubTxSubStatus string

const (
	// PubTxSubStatusReceived indicates the transaction has been received by the connector
	PubTxSubStatusReceived PubTxSubStatus = "Received"
	// PubTxSubStatusStale indicates the transaction is now in stale
	PubTxSubStatusStale PubTxSubStatus = "Stale"
	// PubTxSubStatusTracking indicates we are tracking progress of the transaction
	PubTxSubStatusTracking PubTxSubStatus = "Tracking"
	// PubTxSubStatusConfirmed indicates we have confirmed that the transaction has been fully processed
	PubTxSubStatusConfirmed PubTxSubStatus = "Confirmed"
)

type BaseTxAction string

const (
	// BaseTxActionSign indicates the operation has been signed
	BaseTxActionSign BaseTxAction = "Sign"
)

const (
	// BaseTxActionStateTransition is a special value used for state transition entries, which are created using SetSubStatus
	BaseTxActionStateTransition BaseTxAction = "StateTransition"
	// BaseTxActionAssignNonce indicates that a nonce has been assigned to the transaction
	BaseTxActionAssignNonce BaseTxAction = "AssignNonce"
	// BaseTxActionRetrieveGasPrice indicates the operation is getting a gas price
	BaseTxActionRetrieveGasPrice BaseTxAction = "RetrieveGasPrice"
	// BaseTxActionSubmitTransaction indicates that the transaction has been submitted
	BaseTxActionSubmitTransaction BaseTxAction = "SubmitTransaction"
	// BaseTxActionConfirmTransaction indicates that the transaction has been confirmed
	BaseTxActionConfirmTransaction BaseTxAction = "Confirm"
)

type NextNonceCallback func(ctx context.Context, signer string) (uint64, error)

type NonceAssignmentIntent interface {
	Complete(ctx context.Context)
	AssignNextNonce(ctx context.Context) (uint64, error)
	Rollback(ctx context.Context)
}

type NonceCache interface {
	IntentToAssignNonce(ctx context.Context, signer string) (NonceAssignmentIntent, error)
}
