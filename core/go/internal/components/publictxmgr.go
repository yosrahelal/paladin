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

package components

import (
	"context"

	"github.com/google/uuid"
	"github.com/hyperledger/firefly-common/pkg/ffapi"
	"github.com/hyperledger/firefly-common/pkg/fftypes"
	"github.com/hyperledger/firefly-common/pkg/i18n"
	"github.com/hyperledger/firefly-signer/pkg/ethsigner"
	"github.com/hyperledger/firefly-signer/pkg/ethtypes"
	"github.com/kaleido-io/paladin/core/internal/msgs"
	"github.com/kaleido-io/paladin/core/pkg/blockindexer"
	"github.com/kaleido-io/paladin/core/pkg/ethclient"
)

// PublicTransactionEventType is a enum type that contains all types of transaction process events
// that a transaction handler emits.
type PublicTransactionEventType int

const (
	PublicTXProcessSucceeded PublicTransactionEventType = iota
	PublicTXProcessFailed
)

// BaseTxStatus is the current status of a transaction
type BaseTxStatus string

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
	// BaseTxStatusPending indicates the operation has been submitted, but is not yet confirmed as successful or failed
	BaseTxStatusPending BaseTxStatus = "Pending"
	// BaseTxStatusSucceeded the infrastructure runtime has returned success for the operation
	BaseTxStatusSucceeded BaseTxStatus = "Succeeded"
	// BaseTxStatusFailed happens when an error is reported by the infrastructure runtime
	BaseTxStatusFailed BaseTxStatus = "Failed"
	// BaseTxStatusFailed happens when the indexed transaction hash doesn't match any of the submitted hashes
	BaseTxStatusConflict BaseTxStatus = "Conflict"
	// BaseTxStatusSuspended indicates we are not actively doing any work with this transaction right now, until it's resumed to pending again
	BaseTxStatusSuspended BaseTxStatus = "Suspended"
)

type PublicTX struct {
	ID              string          `json:"id"`
	Created         *fftypes.FFTime `json:"created"`
	Updated         *fftypes.FFTime `json:"updated"`
	Status          BaseTxStatus    `json:"status"`
	DeleteRequested *fftypes.FFTime `json:"deleteRequested,omitempty"`
	SequenceID      string          `json:"sequenceId,omitempty"`
	*ethsigner.Transaction
	TransactionHash string          `json:"transactionHash,omitempty"`
	FirstSubmit     *fftypes.FFTime `json:"firstSubmit,omitempty"`
	LastSubmit      *fftypes.FFTime `json:"lastSubmit,omitempty"`
	ErrorMessage    string          `json:"errorMessage,omitempty"`
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

// BaseTxSubStatus is an intermediate status a transaction may go through
type BaseTxSubStatus string

const (
	// BaseTxSubStatusReceived indicates the transaction has been received by the connector
	BaseTxSubStatusReceived BaseTxSubStatus = "Received"
	// BaseTxSubStatusStale indicates the transaction is now in stale
	BaseTxSubStatusStale BaseTxSubStatus = "Stale"
	// BaseTxSubStatusTracking indicates we are tracking progress of the transaction
	BaseTxSubStatusTracking BaseTxSubStatus = "Tracking"
	// BaseTxSubStatusConfirmed indicates we have confirmed that the transaction has been fully processed
	BaseTxSubStatusConfirmed BaseTxSubStatus = "Confirmed"
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
	Status               *BaseTxStatus        `json:"status"`
	DeleteRequested      *fftypes.FFTime      `json:"deleteRequested,omitempty"`
	From                 *string              `json:"from,omitempty"`
	To                   *string              `json:"to,omitempty"`
	Nonce                *ethtypes.HexInteger `json:"nonce,omitempty"`
	Value                *ethtypes.HexInteger `json:"value,omitempty"`
	GasPrice             *ethtypes.HexInteger `json:"gasPrice,omitempty"`
	MaxPriorityFeePerGas *ethtypes.HexInteger `json:"maxPriorityFeePerGas,omitempty"`
	MaxFeePerGas         *ethtypes.HexInteger `json:"maxFeePerGas,omitempty"`
	GasLimit             *ethtypes.HexInteger `json:"gas,omitempty"` // note this is required for some methods (eth_estimateGas)
	TransactionHash      *string              `json:"transactionHash,omitempty"`
	FirstSubmit          *fftypes.FFTime      `json:"firstSubmit,omitempty"`
	LastSubmit           *fftypes.FFTime      `json:"lastSubmit,omitempty"`
	ErrorMessage         *string              `json:"errorMessage,omitempty"`
	SubmittedHashes      []string             `json:"submittedHashes,omitempty"`
}

type NextNonceCallback func(ctx context.Context, signer string) (uint64, error)

type TransactionStore interface {
	GetTransactionByID(ctx context.Context, txID string) (*PublicTX, error)
	InsertTransactionWithNextNonce(ctx context.Context, tx *PublicTX, lookupNextNonce NextNonceCallback) error
	UpdateTransaction(ctx context.Context, txID string, updates *BaseTXUpdates) error
	DeleteTransaction(ctx context.Context, txID string) error

	GetConfirmedTransaction(ctx context.Context, txID string) (iTX *blockindexer.IndexedTransaction, err error)
	SetConfirmedTransaction(ctx context.Context, txID string, iTX *blockindexer.IndexedTransaction) error

	AddSubStatusAction(ctx context.Context, txID string, subStatus BaseTxSubStatus, action BaseTxAction, info *fftypes.JSONAny, err *fftypes.JSONAny, actionOccurred *fftypes.FFTime) error

	ListTransactions(ctx context.Context, filter ffapi.AndFilter) ([]*PublicTX, *ffapi.FilterResult, error)
	NewTransactionFilter(ctx context.Context) ffapi.FilterBuilder
}
type PublicTxEngine interface {
	// Lifecycle functions

	// Init - setting a set of initialized toolkit plugins in the constructed transaction handler object. Safe checks & initialization
	//        can take place inside this function as well. It also enables toolkit plugins to be able to embed a reference to its parent
	//        transaction handler instance.
	Init(ctx context.Context, ethClient ethclient.EthClient, keymgr ethclient.KeyManager, txStore TransactionStore, publicTXEventNotifier PublicTxEventNotifier, blockIndexer blockindexer.BlockIndexer)

	// Start - starting the transaction handler to handle inbound events.
	// It takes in a context, of which upon cancellation will stop the transaction handler.
	// It returns a read-only channel. When this channel gets closed, it indicates transaction handler has been stopped gracefully.
	// It returns an error when failed to start.
	Start(ctx context.Context) (done <-chan struct{}, err error)

	// Event handling functions
	// Instructional events:
	// HandleNewTransaction - handles event of adding new transactions onto blockchain
	HandleNewTransaction(ctx context.Context, reqOptions *RequestOptions, txPayload interface{}) (mtx *PublicTX, submissionRejected bool, err error)
	// HandleSuspendTransaction - handles event of suspending a managed transaction
	HandleSuspendTransaction(ctx context.Context, txID string) (mtx *PublicTX, err error)
	// HandleResumeTransaction - handles event of resuming a suspended managed transaction
	HandleResumeTransaction(ctx context.Context, txID string) (mtx *PublicTX, err error)

	// Functions for auto-fueling
	GetPendingFuelingTransaction(ctx context.Context, sourceAddress string, destinationAddress string) (tx *PublicTX, err error)
	CheckTransactionCompleted(ctx context.Context, tx *PublicTX) (completed bool)
}

type PublicTxManager interface {
	ManagerLifecycle
}
