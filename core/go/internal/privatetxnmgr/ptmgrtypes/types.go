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

/*
   This package defines interfaces that are used within the privatetxnmgr package
   They are defined in a separate package to avoid circular dependencies between the privatetxnmgr package mocks.
   All interfaces of privatetxnmgr intended to be consumed by other packages should be defined in components package
*/

import (
	"context"

	"github.com/google/uuid"
	"github.com/kaleido-io/paladin/core/internal/components"
	"github.com/kaleido-io/paladin/core/internal/statedistribution"
	"github.com/kaleido-io/paladin/toolkit/pkg/prototk"
)

type EndorsementRequest struct {
	TransactionID string
	InputStates   []string
}

type Transaction struct {
	ID              string
	AssemblerNodeID string
	OutputStates    []string
	InputStates     []string
}

type Publisher interface {
	//Service for sending messages and events within the local node
	PublishTransactionBlockedEvent(ctx context.Context, transactionId string)
	PublishTransactionDispatchedEvent(ctx context.Context, transactionId string, nonce uint64, signingAddress string)
	PublishTransactionAssembledEvent(ctx context.Context, transactionId string)
	PublishTransactionAssembleFailedEvent(ctx context.Context, transactionId string, errorMessage string)
	PublishTransactionSignedEvent(ctx context.Context, transactionId string, attestationResult *prototk.AttestationResult)
	PublishTransactionEndorsedEvent(ctx context.Context, transactionId string, attestationResult *prototk.AttestationResult, revertReason *string)
	PublishResolveVerifierResponseEvent(ctx context.Context, transactionId string, lookup, algorithm, verifier, verifierType string)
	PublishResolveVerifierErrorEvent(ctx context.Context, transactionId string, lookup, algorithm, errorMessage string)
	PublishTransactionFinalizedEvent(ctx context.Context, transactionId string)
	PublishTransactionFinalizeError(ctx context.Context, transactionId string, revertReason string, err error)
}

// Map of signing address to an ordered list of transaction IDs that are ready to be dispatched by that signing address
type DispatchableTransactions map[string][]string
type Dispatcher interface {
	// Dispatcher is the component that takes responsibility for submitting the transactions in the sequence to the base ledger in the correct order
	DispatchTransactions(context.Context, DispatchableTransactions) error
}

type EndorsementGatherer interface {
	// TODO: Consider if this is the right object to hold this
	DomainContext() components.DomainContext

	//integrate with local signer and domain manager to satisfy the given endorsement request
	// that may have came from a transaction assembled locally or from another node
	GatherEndorsement(
		ctx context.Context,
		transactionSpecification *prototk.TransactionSpecification,
		verifiers []*prototk.ResolvedVerifier,
		signatures []*prototk.AttestationResult,
		inputStates []*prototk.EndorsableState,
		readStates []*prototk.EndorsableState,
		outputStates []*prototk.EndorsableState,
		partyName string,
		endorsementRequest *prototk.AttestationRequest) (*prototk.AttestationResult, *string, error)
}

type ContentionResolver interface {
	Resolve(stateID, biddingContentionResolver1, biddingContentionResolver2 string) (string, error)
}

type TransportWriter interface {
	SendState(ctx context.Context, stateId string, schemaId string, stateDataJson string, party string) error
	SendDelegationRequest(ctx context.Context, delegationId string, delegateNodeId string, transaction *components.PrivateTransaction) error
}

type TxProcessorStatus int

const (
	TxProcessorActive TxProcessorStatus = iota
	TxProcessorSuspend
	TxProcessorResume
	TxProcessorRemove
)

type TxProcessor interface {
	GetTxStatus(ctx context.Context) (components.PrivateTxStatus, error)

	ApplyEvent(ctx context.Context, event PrivateTransactionEvent)
	Action(ctx context.Context)

	PrepareTransaction(ctx context.Context) (*components.PrivateTransaction, error)
	GetStateDistributions(ctx context.Context) []*statedistribution.StateDistribution
	CoordinatingLocally() bool
	IsComplete() bool
	ReadyForSequencing() bool
	Dispatched() bool
	ID() uuid.UUID
	IsEndorsed(ctx context.Context) bool
	InputStateIDs() []string
	OutputStateIDs() []string
	Signer() string
}
