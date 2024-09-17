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
	"context"
	"time"

	"github.com/kaleido-io/paladin/core/internal/components"
	"github.com/kaleido-io/paladin/core/internal/statestore"
	"github.com/kaleido-io/paladin/core/pkg/ethclient"
	pbSequence "github.com/kaleido-io/paladin/core/pkg/proto/sequence"
	"github.com/kaleido-io/paladin/toolkit/pkg/prototk"
)

type StageProcessNextStep int

const (
	NextStepWait StageProcessNextStep = iota
	NextStepNewStage
	NextStepNewAction
)

type StageEvent struct {
	ID              string      `json:"id"` // TODO: not sure how useful it is to have this ID as the process of event should be idempotent?
	Stage           string      `json:"stage"`
	ContractAddress string      `json:"contractAddress"`
	TxID            string      `json:"transactionId"`
	Data            interface{} `json:"data"` // schema decided by each stage
}

type StageChangeEvent struct {
	ID              string      `json:"id"`
	PreviousStage   string      `json:"previousStage"`
	NewStage        string      `json:"newStage"`
	ContractAddress string      `json:"contractAddress"`
	TxID            string      `json:"transactionId"`
	Data            interface{} `json:"data"` // schema decided by each stage
}

type TxProcessPreReq struct {
	TxIDs []string `json:"transactionIds,omitempty"`
}

type TxStatus struct {
	TxID   string `json:"transactionId"`
	Status string `json:"status"`
}

type MockIdentityResolver struct {
}

func (mti *MockIdentityResolver) IsCurrentNode(nodeID string) bool {
	return nodeID == "current-node"
}

func (mti *MockIdentityResolver) GetDispatchAddress(preferredAddresses []string) string {
	if len(preferredAddresses) > 0 {
		return preferredAddresses[0]
	}
	return ""
}

func (mti *MockIdentityResolver) ConnectToBaseLeger() error {
	return nil
}

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

type StageContext struct {
	Ctx            context.Context
	ID             string
	Stage          string
	StageEntryTime time.Time
}

type EventSubscriber func(event EngineEvent)

type EngineEvent interface {
}

type StageFoundationService interface {
	TransportManager() components.TransportManager
	DomainAPI() components.DomainSmartContract
	StateStore() statestore.StateStore // TODO: filter out to only getters so setters can be coordinated efficiently like transactions
	KeyManager() ethclient.KeyManager
}

type Sequencer interface {
	/*
		HandleTransactionAssembledEvent needs to be called whenever a transaction has been assembled by any node in the network, including the local node.
	*/
	HandleTransactionAssembledEvent(ctx context.Context, event *pbSequence.TransactionAssembledEvent) error

	/*
		HandleTransactionEndorsedEvent needs to be called whenever a the endorsement rules for the given domain have been satisfied for a given transaction.
	*/
	HandleTransactionEndorsedEvent(ctx context.Context, event *pbSequence.TransactionEndorsedEvent) error

	/*
		HandleTransactionDispatchResovedEvent needs to be called whenever a the signign address for a transaction has been resolved.
	*/
	HandleTransactionDispatchResolvedEvent(ctx context.Context, event *pbSequence.TransactionDispatchResolvedEvent) error

	/*
		HandleTransactionConfirmedEvent needs to be called whenever a transaction has been confirmed on the base ledger
		i.e. it has been included in a block with enough subsequent blocks to consider this final for that particular chain.
	*/
	HandleTransactionConfirmedEvent(ctx context.Context, event *pbSequence.TransactionConfirmedEvent) error

	/*
		OnTransationReverted needs to be called whenever a transaction has been rejected by any of the validation
		steps on any nodes or the base leddger contract. The transaction may or may not be reassembled after this
		hanlder is called.
	*/
	HandleTransactionRevertedEvent(ctx context.Context, event *pbSequence.TransactionRevertedEvent) error

	/*
		HandleTransactionDelegatedEvent needs to be called whenever a transaction has been delegated from one node to another
		this is an event that is broadcast to all nodes after the fact and should not be confused with the DelegateTransaction message which is
		an instruction to the delegate node.
	*/
	HandleTransactionDelegatedEvent(ctx context.Context, event *pbSequence.TransactionDelegatedEvent) error

	/*
		AssignTransaction is an instruction for the given transaction to be managed by this sequencer
	*/
	AssignTransaction(ctx context.Context, transactionID string) error

	/*
		ApproveEndorsement is a synchronous check of whether a given transaction could be endorsed by the local node. It asks the question:
		"given the information available to the local node at this point in time, does it appear that this transaction has no contention on input states".
	*/
	ApproveEndorsement(ctx context.Context, endorsementRequest EndorsementRequest) (bool, error)

	SetDispatcher(dispatcher Dispatcher)
}

type Publisher interface {
	//Service for sending messages and events within the local node
	PublishTransactionBlockedEvent(ctx context.Context, transactionId string) error
	PublishTransactionDispatchedEvent(ctx context.Context, transactionId string, nonce uint64, signingAddress string) error
	PublishTransactionSignedEvent(ctx context.Context, transactionId string, attestationResult *prototk.AttestationResult) error
	PublishTransactionEndorsedEvent(ctx context.Context, transactionId string, attestationResult *prototk.AttestationResult, revertReason *string) error
}

// Map of signing address to an ordered list of transaction IDs that are ready to be dispatched by that signing address
type DispatchableTransactions map[string][]string
type Dispatcher interface {
	// Dispatcher is the component that takes responsibility for submitting the transactions in the sequence to the base ledger in the correct order
	DispatchTransactions(context.Context, DispatchableTransactions) error
}

type EndorsementGatherer interface {
	//integrate with local signer and domain manager to satisfy the given endorsement request
	// that may have came from a transaction assembled locally or from another node
	GatherEndorsement(ctx context.Context, transactionSpecification *prototk.TransactionSpecification, verifiers []*prototk.ResolvedVerifier, signatures []*prototk.AttestationResult, inputStates []*prototk.EndorsableState, outputStates []*prototk.EndorsableState, partyName string, endorsementRequest *prototk.AttestationRequest) (*prototk.AttestationResult, *string, error)
}

type ContentionResolver interface {
	Resolve(stateID, biddingContentionResolver1, biddingContentionResolver2 string) (string, error)
}

type TransportWriter interface {
	// Provided to the sequencer to allow it to send messages to other nodes in the network
	SendDelegateTransactionMessage(ctx context.Context, transactionId string, delegateNodeId string) error
}

type TxProcessorStatus int

const (
	TxProcessorActive TxProcessorStatus = iota
	TxProcessorSuspend
	TxProcessorResume
	TxProcessorRemove
)

type TxProcessor interface {
	Init(ctx context.Context)
	GetTxStatus(ctx context.Context) (TxStatus, error)
	GetStatus(ctx context.Context) TxProcessorStatus

	HandleTransactionSubmittedEvent(ctx context.Context, event *TransactionSubmittedEvent)
	HandleTransactionAssembledEvent(ctx context.Context, event *TransactionAssembledEvent)
	HandleTransactionSignedEvent(ctx context.Context, event *TransactionSignedEvent)
	HandleTransactionEndorsedEvent(ctx context.Context, event *TransactionEndorsedEvent)
	HandleTransactionDispatchedEvent(ctx context.Context, event *TransactionDispatchedEvent)
	HandleTransactionConfirmedEvent(ctx context.Context, event *TransactionConfirmedEvent)
	HandleTransactionRevertedEvent(ctx context.Context, event *TransactionRevertedEvent)
	HandleTransactionDelegatedEvent(ctx context.Context, event *TransactionDelegatedEvent)

	PrepareTransaction(ctx context.Context) (*components.PrivateTransaction, error)
}
