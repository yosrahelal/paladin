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

package pldapi

import (
	"github.com/google/uuid"
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

type Transaction struct {
	ID             *uuid.UUID                    `docstruct:"Transaction" json:"id,omitempty"`             // server generated UUID for this transaction (query only)
	Created        tktypes.Timestamp             `docstruct:"Transaction" json:"created,omitempty"`        // server generated creation timestamp for this transaction (query only)
	IdempotencyKey string                        `docstruct:"Transaction" json:"idempotencyKey,omitempty"` // externally supplied unique identifier for this transaction. 409 Conflict will be returned on attempt to re-submit
	Type           tktypes.Enum[TransactionType] `docstruct:"Transaction" json:"type,omitempty"`           // public transactions go straight to a base ledger EVM smart contract. Private transactions use a Paladin domain to mask the on-chain data
	Domain         string                        `docstruct:"Transaction" json:"domain,omitempty"`         // name of a domain - only required on input for private deploy transactions (n/a for public, and inferred from "to" for invoke)
	Function       string                        `docstruct:"Transaction" json:"function,omitempty"`       // inferred from definition if not supplied. Resolved to full signature and stored. Required with abiReference on input if not constructor
	ABIReference   *tktypes.Bytes32              `docstruct:"Transaction" json:"abiReference,omitempty"`   // calculated if not supplied (ABI will be stored for you)
	From           string                        `docstruct:"Transaction" json:"from,omitempty"`           // locator for a local signing identity to use for submission of this transaction
	To             *tktypes.EthAddress           `docstruct:"Transaction" json:"to,omitempty"`             // the target contract, or null for a deploy
	Data           tktypes.RawJSON               `docstruct:"Transaction" json:"data,omitempty"`           // pre-encoded array with/without function selector, array, or object input
	PublicTxOptions
	// TODO: PrivateTransactions string list
	// TODO: PublicTransactions string list
}

// Additional optional fields on input not returned on output
type TransactionInput struct {
	Transaction
	DependsOn []uuid.UUID      `docstruct:"TransactionInput" json:"dependsOn,omitempty"` // these transactions must be mined on the blockchain successfully (or deleted) before this transaction submits. Failure of pre-reqs results in failure of this TX
	ABI       abi.ABI          `docstruct:"TransactionInput" json:"abi,omitempty"`       // required if abiReference not supplied
	Bytecode  tktypes.HexBytes `docstruct:"TransactionInput" json:"bytecode,omitempty"`  // for deploy this is prepended to the encoded data inputs
}

// Additional fields returned on output when "full" specified
type TransactionFull struct {
	*Transaction
	DependsOn []uuid.UUID             `docstruct:"TransactionFull" json:"dependsOn,omitempty"` // transactions registered as dependencies when the transaction was created
	Receipt   *TransactionReceiptData `docstruct:"TransactionFull" json:"receipt"`             // available if the transaction has reached a final state
	Public    []*PublicTx             `docstruct:"TransactionFull" json:"public"`              // list of public transactions associated
	// TODO: PrivateTransactions object list
}

type TransactionReceipt struct {
	ID uuid.UUID `docstruct:"TransactionReceipt" json:"id,omitempty"` // transaction ID
	TransactionReceiptData
}

type TransactionReceiptDataOnchain struct {
	TransactionHash  *tktypes.Bytes32 `docstruct:"TransactionReceiptDataOnchain" json:"transactionHash,omitempty"`
	BlockNumber      int64            `docstruct:"TransactionReceiptDataOnchain" json:"blockNumber,omitempty"`
	TransactionIndex int64            `docstruct:"TransactionReceiptDataOnchain" json:"transactionIndex,omitempty"`
}

type TransactionReceiptDataOnchainEvent struct {
	LogIndex int64              `docstruct:"TransactionReceiptDataOnchainEvent" json:"logIndex,omitempty"`
	Source   tktypes.EthAddress `docstruct:"TransactionReceiptDataOnchainEvent" json:"source,omitempty"`
}

type TransactionReceiptData struct {
	Success                             bool                `docstruct:"TransactionReceiptData" json:"success,omitempty"` // true for success (note "status" is reserved for future use)
	*TransactionReceiptDataOnchain      `json:",inline"`    // if the result was finalized by the blockchain (note quirk of omitempty that we can't put zero-valid int pointers on main struct)
	*TransactionReceiptDataOnchainEvent `json:",inline"`    // if the result was finalized by the blockchain by an event
	FailureMessage                      string              `docstruct:"TransactionReceiptData" json:"failureMessage,omitempty"`  // always set to a non-empty string if the transaction reverted, with as much detail as could be extracted
	RevertData                          tktypes.HexBytes    `docstruct:"TransactionReceiptData" json:"revertData,omitempty"`      // encoded revert data if available
	ContractAddress                     *tktypes.EthAddress `docstruct:"TransactionReceiptData" json:"contractAddress,omitempty"` // address of the new contract address, to be used in the `To` field for subsequent invoke transactions.  Nil if this transaction itself was an invoke
}

type TransactionActivityRecord struct {
	Time    tktypes.Timestamp `docstruct:"TransactionActivityRecord" json:"time"`    // time the record occurred
	Message string            `docstruct:"TransactionActivityRecord" json:"message"` // a message
}

type TransactionDependencies struct {
	DependsOn []uuid.UUID `docstruct:"TransactionDependencies" json:"dependsOn"`
	PrereqOf  []uuid.UUID `docstruct:"TransactionDependencies" json:"prereqOf"`
}
