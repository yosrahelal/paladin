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

package privatetxnmgr

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/kaleido-io/paladin/core/internal/components"
	"github.com/kaleido-io/paladin/core/internal/privatetxnmgr/ptmgrtypes"
	"github.com/kaleido-io/paladin/core/mocks/componentmocks"
	"github.com/kaleido-io/paladin/core/mocks/privatetxnmgrmocks"
	"github.com/kaleido-io/paladin/core/mocks/prvtxsyncpointsmocks"
	"github.com/kaleido-io/paladin/toolkit/pkg/algorithms"
	"github.com/kaleido-io/paladin/toolkit/pkg/prototk"
	"github.com/kaleido-io/paladin/toolkit/pkg/signpayloads"
	"github.com/kaleido-io/paladin/toolkit/pkg/tktypes"
	"github.com/kaleido-io/paladin/toolkit/pkg/verifiers"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

type transactionFlowDepencyMocks struct {
	allComponents       *componentmocks.AllComponents
	domainSmartContract *componentmocks.DomainSmartContract
	domainContext       *componentmocks.DomainContext
	domainMgr           *componentmocks.DomainManager
	transportManager    *componentmocks.TransportManager
	stateStore          *componentmocks.StateManager
	keyManager          *componentmocks.KeyManager
	endorsementGatherer *privatetxnmgrmocks.EndorsementGatherer
	publisher           *privatetxnmgrmocks.Publisher
	identityResolver    *componentmocks.IdentityResolver
	syncPoints          *prvtxsyncpointsmocks.SyncPoints
	transportWriter     *privatetxnmgrmocks.TransportWriter
	environment         *privatetxnmgrmocks.SequencerEnvironment
	coordinatorSelector *privatetxnmgrmocks.CoordinatorSelector
}

func newTransactionFlowForTesting(t *testing.T, ctx context.Context, transaction *components.PrivateTransaction, nodeName string) (*transactionFlow, *transactionFlowDepencyMocks) {

	mocks := &transactionFlowDepencyMocks{
		allComponents:       componentmocks.NewAllComponents(t),
		domainSmartContract: componentmocks.NewDomainSmartContract(t),
		domainContext:       componentmocks.NewDomainContext(t),
		domainMgr:           componentmocks.NewDomainManager(t),
		transportManager:    componentmocks.NewTransportManager(t),
		stateStore:          componentmocks.NewStateManager(t),
		keyManager:          componentmocks.NewKeyManager(t),
		endorsementGatherer: privatetxnmgrmocks.NewEndorsementGatherer(t),
		publisher:           privatetxnmgrmocks.NewPublisher(t),
		identityResolver:    componentmocks.NewIdentityResolver(t),
		syncPoints:          prvtxsyncpointsmocks.NewSyncPoints(t),
		transportWriter:     privatetxnmgrmocks.NewTransportWriter(t),
		environment:         privatetxnmgrmocks.NewSequencerEnvironment(t),
		coordinatorSelector: privatetxnmgrmocks.NewCoordinatorSelector(t),
	}
	contractAddress := tktypes.RandAddress()
	mocks.allComponents.On("StateManager").Return(mocks.stateStore).Maybe()
	mocks.allComponents.On("DomainManager").Return(mocks.domainMgr).Maybe()
	mocks.allComponents.On("TransportManager").Return(mocks.transportManager).Maybe()
	mocks.allComponents.On("KeyManager").Return(mocks.keyManager).Maybe()
	mocks.endorsementGatherer.On("DomainContext").Return(mocks.domainContext).Maybe()
	mocks.domainSmartContract.On("Address").Return(*contractAddress).Maybe()
	mocks.domainSmartContract.On("ContractConfig").Return(&prototk.ContractConfig{
		CoordinatorSelection: prototk.ContractConfig_COORDINATOR_ENDORSER,
	}).Maybe()

	domain := componentmocks.NewDomain(t)
	domain.On("Configuration").Return(&prototk.DomainConfig{}).Maybe()
	mocks.domainSmartContract.On("Domain").Return(domain).Maybe()

	assembleCoordinator := NewAssembleCoordinator(ctx, nodeName, 1, mocks.allComponents, mocks.domainSmartContract, mocks.domainContext)
	tp := NewTransactionFlow(ctx, transaction, nodeName, mocks.allComponents, mocks.domainSmartContract, mocks.publisher, mocks.endorsementGatherer, mocks.identityResolver, mocks.syncPoints, mocks.transportWriter, 1*time.Minute, mocks.coordinatorSelector, assembleCoordinator, mocks.environment)

	return tp.(*transactionFlow), mocks
}

func TestHasOutstandingEndorsementRequestsMultipleRequestsIncomplete(t *testing.T) {
	// When there is an attestation plan with multiple AttestationRequest
	// but not enough AttestationResult
	// then returns true
	ctx := context.Background()
	newTxID := uuid.New()
	aliceIdentityLocator := "alice@node1"
	aliceVerifier := tktypes.RandAddress().String()
	bobIdentityLocator := "bob@node2"
	bobVerifier := tktypes.RandAddress().String()
	carolIdentityLocator := "carol@node2"
	carolVerifier := tktypes.RandAddress().String()

	testTx := &components.PrivateTransaction{
		ID: newTxID,
		PreAssembly: &components.TransactionPreAssembly{
			Verifiers: []*prototk.ResolvedVerifier{
				{
					Lookup:       aliceIdentityLocator,
					Algorithm:    algorithms.ECDSA_SECP256K1,
					VerifierType: verifiers.ETH_ADDRESS,
					Verifier:     aliceVerifier,
				},
				{
					Lookup:       bobIdentityLocator,
					Algorithm:    algorithms.ECDSA_SECP256K1,
					VerifierType: verifiers.ETH_ADDRESS,
					Verifier:     bobVerifier,
				},
				{
					Lookup:       carolIdentityLocator,
					Algorithm:    algorithms.ECDSA_SECP256K1,
					VerifierType: verifiers.ETH_ADDRESS,
					Verifier:     carolVerifier,
				},
			},
		},
		PostAssembly: &components.TransactionPostAssembly{
			AttestationPlan: []*prototk.AttestationRequest{
				{
					Name:            "foo",
					AttestationType: prototk.AttestationType_ENDORSE,
					Algorithm:       algorithms.ECDSA_SECP256K1,
					VerifierType:    verifiers.ETH_ADDRESS,
					PayloadType:     signpayloads.OPAQUE_TO_RSV,
					Parties: []string{
						aliceIdentityLocator,
					},
				},
				{
					Name:            "bar",
					AttestationType: prototk.AttestationType_ENDORSE,
					Algorithm:       algorithms.ECDSA_SECP256K1,
					VerifierType:    verifiers.ETH_ADDRESS,
					PayloadType:     signpayloads.OPAQUE_TO_RSV,
					Parties: []string{
						bobIdentityLocator,
					},
				},
				{
					Name:            "quz",
					AttestationType: prototk.AttestationType_ENDORSE,
					Algorithm:       algorithms.ECDSA_SECP256K1,
					VerifierType:    verifiers.ETH_ADDRESS,
					PayloadType:     signpayloads.OPAQUE_TO_RSV,
					Parties: []string{
						carolIdentityLocator,
					},
				},
			},
			Endorsements: []*prototk.AttestationResult{
				{
					Name:            "foo",
					AttestationType: prototk.AttestationType_ENDORSE,
					Verifier: &prototk.ResolvedVerifier{
						Lookup:       aliceIdentityLocator,
						Algorithm:    algorithms.ECDSA_SECP256K1,
						Verifier:     tktypes.RandAddress().String(),
						VerifierType: verifiers.ETH_ADDRESS,
					},
					Payload: tktypes.RandBytes(32),
				},
			},
		},
	}

	tp, _ := newTransactionFlowForTesting(t, ctx, testTx, "node1")
	result := tp.hasOutstandingEndorsementRequests(ctx)
	assert.True(t, result)

}

func TestHasOutstandingEndorsementRequestsMultipleRequestsComplete(t *testing.T) {
	// When there is an attestation plan with multiple AttestationRequest
	// and we have an AttestationResult matching each one
	// then returns false
	ctx := context.Background()
	newTxID := uuid.New()
	aliceIdentityLocator := "alice@node1"
	aliceVerifier := tktypes.RandAddress().String()
	bobIdentityLocator := "bob@node2"
	bobVerifier := tktypes.RandAddress().String()
	carolIdentityLocator := "carol@node2"
	carolVerifier := tktypes.RandAddress().String()
	testTx := &components.PrivateTransaction{
		ID: newTxID,
		PreAssembly: &components.TransactionPreAssembly{
			Verifiers: []*prototk.ResolvedVerifier{
				{
					Lookup:       aliceIdentityLocator,
					Algorithm:    algorithms.ECDSA_SECP256K1,
					VerifierType: verifiers.ETH_ADDRESS,
					Verifier:     aliceVerifier,
				},
				{
					Lookup:       bobIdentityLocator,
					Algorithm:    algorithms.ECDSA_SECP256K1,
					VerifierType: verifiers.ETH_ADDRESS,
					Verifier:     bobVerifier,
				},
				{
					Lookup:       carolIdentityLocator,
					Algorithm:    algorithms.ECDSA_SECP256K1,
					VerifierType: verifiers.ETH_ADDRESS,
					Verifier:     carolVerifier,
				},
			},
		},
		PostAssembly: &components.TransactionPostAssembly{
			AttestationPlan: []*prototk.AttestationRequest{
				{
					Name:            "foo",
					AttestationType: prototk.AttestationType_ENDORSE,
					Algorithm:       algorithms.ECDSA_SECP256K1,
					VerifierType:    verifiers.ETH_ADDRESS,
					PayloadType:     signpayloads.OPAQUE_TO_RSV,
					Parties: []string{
						aliceIdentityLocator,
					},
				},
				{
					Name:            "bar",
					AttestationType: prototk.AttestationType_ENDORSE,
					Algorithm:       algorithms.ECDSA_SECP256K1,
					VerifierType:    verifiers.ETH_ADDRESS,
					PayloadType:     signpayloads.OPAQUE_TO_RSV,
					Parties: []string{
						bobIdentityLocator,
					},
				},
				{
					Name:            "quz",
					AttestationType: prototk.AttestationType_ENDORSE,
					Algorithm:       algorithms.ECDSA_SECP256K1,
					VerifierType:    verifiers.ETH_ADDRESS,
					PayloadType:     signpayloads.OPAQUE_TO_RSV,
					Parties: []string{
						carolIdentityLocator,
					},
				},
			},
			Endorsements: []*prototk.AttestationResult{
				{
					Name:            "foo",
					AttestationType: prototk.AttestationType_ENDORSE,
					Verifier: &prototk.ResolvedVerifier{
						Lookup:       aliceIdentityLocator,
						Algorithm:    algorithms.ECDSA_SECP256K1,
						Verifier:     aliceVerifier,
						VerifierType: verifiers.ETH_ADDRESS,
					},
					Payload: tktypes.RandBytes(32),
				},
				{
					Name:            "bar",
					AttestationType: prototk.AttestationType_ENDORSE,
					Verifier: &prototk.ResolvedVerifier{
						Lookup:       bobIdentityLocator,
						Algorithm:    algorithms.ECDSA_SECP256K1,
						Verifier:     bobVerifier,
						VerifierType: verifiers.ETH_ADDRESS,
					},
					Payload: tktypes.RandBytes(32),
				},
				{
					Name:            "quz",
					AttestationType: prototk.AttestationType_ENDORSE,
					Verifier: &prototk.ResolvedVerifier{
						Lookup:       carolIdentityLocator,
						Algorithm:    algorithms.ECDSA_SECP256K1,
						Verifier:     carolVerifier,
						VerifierType: verifiers.ETH_ADDRESS,
					},
					Payload: tktypes.RandBytes(32),
				},
			},
		},
	}

	tp, _ := newTransactionFlowForTesting(t, ctx, testTx, "node1")
	result := tp.hasOutstandingEndorsementRequests(ctx)
	assert.False(t, result)

}

func TestHasOutstandingEndorsementRequestSingleRequestMultiplePartiesIncomplete(t *testing.T) {
	// When there is an attestation plan with a single AttestationRequest listing multiple parties
	// and we dont have all of the matching AttestationResults
	// then returns true

	ctx := context.Background()
	newTxID := uuid.New()
	aliceIdentityLocator := "alice@node1"
	aliceVerifier := tktypes.RandAddress().String()
	bobIdentityLocator := "bob@node2"
	bobVerifier := tktypes.RandAddress().String()
	carolIdentityLocator := "carol@node2"
	carolVerifier := tktypes.RandAddress().String()
	testTx := &components.PrivateTransaction{
		ID: newTxID,
		PreAssembly: &components.TransactionPreAssembly{
			Verifiers: []*prototk.ResolvedVerifier{
				{
					Lookup:       aliceIdentityLocator,
					Algorithm:    algorithms.ECDSA_SECP256K1,
					VerifierType: verifiers.ETH_ADDRESS,
					Verifier:     aliceVerifier,
				},
				{
					Lookup:       bobIdentityLocator,
					Algorithm:    algorithms.ECDSA_SECP256K1,
					VerifierType: verifiers.ETH_ADDRESS,
					Verifier:     bobVerifier,
				},
				{
					Lookup:       carolIdentityLocator,
					Algorithm:    algorithms.ECDSA_SECP256K1,
					VerifierType: verifiers.ETH_ADDRESS,
					Verifier:     carolVerifier,
				},
			},
		},
		PostAssembly: &components.TransactionPostAssembly{
			AttestationPlan: []*prototk.AttestationRequest{
				{
					Name:            "foo",
					AttestationType: prototk.AttestationType_ENDORSE,
					Algorithm:       algorithms.ECDSA_SECP256K1,
					VerifierType:    verifiers.ETH_ADDRESS,
					PayloadType:     signpayloads.OPAQUE_TO_RSV,
					Parties: []string{
						aliceIdentityLocator,
						bobIdentityLocator,
						carolIdentityLocator,
					},
				},
			},
			Endorsements: []*prototk.AttestationResult{
				{
					Name:            "foo",
					AttestationType: prototk.AttestationType_ENDORSE,
					Verifier: &prototk.ResolvedVerifier{
						Lookup:       aliceIdentityLocator,
						Algorithm:    algorithms.ECDSA_SECP256K1,
						Verifier:     aliceVerifier,
						VerifierType: verifiers.ETH_ADDRESS,
					},
					Payload: tktypes.RandBytes(32),
				},
			},
		},
	}

	tp, _ := newTransactionFlowForTesting(t, ctx, testTx, "node1")
	result := tp.hasOutstandingEndorsementRequests(ctx)
	assert.True(t, result)

}

func TestHasOutstandingEndorsementRequestSingleRequestMultiplePartiesComplete(t *testing.T) {
	// When there is an attestation plan with a single AttestationRequest listing multiple parties
	// and we have an AttestationResult matching each one
	// then returns false
	ctx := context.Background()
	newTxID := uuid.New()
	aliceIdentityLocator := "alice@node1"
	aliceVerifier := tktypes.RandAddress().String()
	bobIdentityLocator := "bob@node2"
	bobVerifier := tktypes.RandAddress().String()
	carolIdentityLocator := "carol@node2"
	carolVerifier := tktypes.RandAddress().String()
	testTx := &components.PrivateTransaction{
		ID: newTxID,
		PreAssembly: &components.TransactionPreAssembly{
			Verifiers: []*prototk.ResolvedVerifier{
				{
					Lookup:       aliceIdentityLocator,
					Algorithm:    algorithms.ECDSA_SECP256K1,
					VerifierType: verifiers.ETH_ADDRESS,
					Verifier:     aliceVerifier,
				},
				{
					Lookup:       bobIdentityLocator,
					Algorithm:    algorithms.ECDSA_SECP256K1,
					VerifierType: verifiers.ETH_ADDRESS,
					Verifier:     bobVerifier,
				},
				{
					Lookup:       carolIdentityLocator,
					Algorithm:    algorithms.ECDSA_SECP256K1,
					VerifierType: verifiers.ETH_ADDRESS,
					Verifier:     carolVerifier,
				},
			},
		},
		PostAssembly: &components.TransactionPostAssembly{
			AttestationPlan: []*prototk.AttestationRequest{
				{
					Name:            "foo",
					AttestationType: prototk.AttestationType_ENDORSE,
					Algorithm:       algorithms.ECDSA_SECP256K1,
					VerifierType:    verifiers.ETH_ADDRESS,
					PayloadType:     signpayloads.OPAQUE_TO_RSV,
					Parties: []string{
						aliceIdentityLocator,
						bobIdentityLocator,
						carolIdentityLocator,
					},
				},
			},
			Endorsements: []*prototk.AttestationResult{
				{
					Name:            "foo",
					AttestationType: prototk.AttestationType_ENDORSE,
					Verifier: &prototk.ResolvedVerifier{
						Lookup:       aliceIdentityLocator,
						Algorithm:    algorithms.ECDSA_SECP256K1,
						Verifier:     aliceVerifier,
						VerifierType: verifiers.ETH_ADDRESS,
					},
					Payload: tktypes.RandBytes(32),
				},
				{
					Name:            "foo",
					AttestationType: prototk.AttestationType_ENDORSE,
					Verifier: &prototk.ResolvedVerifier{
						Lookup:       bobIdentityLocator,
						Algorithm:    algorithms.ECDSA_SECP256K1,
						Verifier:     bobVerifier,
						VerifierType: verifiers.ETH_ADDRESS,
					},
					Payload: tktypes.RandBytes(32),
				},
				{
					Name:            "foo",
					AttestationType: prototk.AttestationType_ENDORSE,
					Verifier: &prototk.ResolvedVerifier{
						Lookup:       carolIdentityLocator,
						Algorithm:    algorithms.ECDSA_SECP256K1,
						Verifier:     carolVerifier,
						VerifierType: verifiers.ETH_ADDRESS,
					},
					Payload: tktypes.RandBytes(32),
				},
			},
		},
	}

	tp, _ := newTransactionFlowForTesting(t, ctx, testTx, "node1")
	result := tp.hasOutstandingEndorsementRequests(ctx)
	assert.False(t, result)

}

func TestHasOutstandingEndorsementRequestSingleRequestMultiplePartiesDuplicate(t *testing.T) {
	// when we have the right number of endorsements but they are all for the same party that counts as incomplete
	ctx := context.Background()
	newTxID := uuid.New()
	aliceIdentityLocator := "alice@node1"
	aliceVerifier := tktypes.RandAddress().String()
	bobIdentityLocator := "bob@node2"
	bobVerifier := tktypes.RandAddress().String()
	carolIdentityLocator := "carol@node2"
	carolVerifier := tktypes.RandAddress().String()
	testTx := &components.PrivateTransaction{
		ID: newTxID,
		PreAssembly: &components.TransactionPreAssembly{
			Verifiers: []*prototk.ResolvedVerifier{
				{
					Lookup:       aliceIdentityLocator,
					Algorithm:    algorithms.ECDSA_SECP256K1,
					VerifierType: verifiers.ETH_ADDRESS,
					Verifier:     aliceVerifier,
				},
				{
					Lookup:       bobIdentityLocator,
					Algorithm:    algorithms.ECDSA_SECP256K1,
					VerifierType: verifiers.ETH_ADDRESS,
					Verifier:     bobVerifier,
				},
				{
					Lookup:       carolIdentityLocator,
					Algorithm:    algorithms.ECDSA_SECP256K1,
					VerifierType: verifiers.ETH_ADDRESS,
					Verifier:     carolVerifier,
				},
			},
		},
		PostAssembly: &components.TransactionPostAssembly{
			AttestationPlan: []*prototk.AttestationRequest{
				{
					Name:            "foo",
					AttestationType: prototk.AttestationType_ENDORSE,
					Algorithm:       algorithms.ECDSA_SECP256K1,
					VerifierType:    verifiers.ETH_ADDRESS,
					PayloadType:     signpayloads.OPAQUE_TO_RSV,
					Parties: []string{
						aliceIdentityLocator,
						bobIdentityLocator,
						carolIdentityLocator,
					},
				},
			},
			Endorsements: []*prototk.AttestationResult{
				{
					Name:            "foo",
					AttestationType: prototk.AttestationType_ENDORSE,
					Verifier: &prototk.ResolvedVerifier{
						Lookup:       aliceIdentityLocator,
						Algorithm:    algorithms.ECDSA_SECP256K1,
						Verifier:     aliceVerifier,
						VerifierType: verifiers.ETH_ADDRESS,
					},
					Payload: tktypes.RandBytes(32),
				},
				{
					Name:            "foo",
					AttestationType: prototk.AttestationType_ENDORSE,
					Verifier: &prototk.ResolvedVerifier{
						Lookup:       aliceIdentityLocator,
						Algorithm:    algorithms.ECDSA_SECP256K1,
						Verifier:     aliceVerifier,
						VerifierType: verifiers.ETH_ADDRESS,
					},
					Payload: tktypes.RandBytes(32),
				},
				{
					Name:            "foo",
					AttestationType: prototk.AttestationType_ENDORSE,
					Verifier: &prototk.ResolvedVerifier{
						Lookup:       aliceIdentityLocator,
						Algorithm:    algorithms.ECDSA_SECP256K1,
						Verifier:     aliceVerifier,
						VerifierType: verifiers.ETH_ADDRESS,
					},
					Payload: tktypes.RandBytes(32),
				},
			},
		},
	}

	tp, _ := newTransactionFlowForTesting(t, ctx, testTx, "node1")
	result := tp.hasOutstandingEndorsementRequests(ctx)
	assert.True(t, result)

}

func TestHasOutstandingEndorsementRequestSingleRequestMultiplePartiesCompleteMixedOrder(t *testing.T) {
	// order of responses does not need to match order of requests
	ctx := context.Background()
	newTxID := uuid.New()
	aliceIdentityLocator := "alice@node1"
	aliceVerifier := tktypes.RandAddress().String()
	bobIdentityLocator := "bob@node2"
	bobVerifier := tktypes.RandAddress().String()
	carolIdentityLocator := "carol@node2"
	carolVerifier := tktypes.RandAddress().String()
	testTx := &components.PrivateTransaction{
		ID: newTxID,
		PreAssembly: &components.TransactionPreAssembly{
			Verifiers: []*prototk.ResolvedVerifier{
				{
					Lookup:       aliceIdentityLocator,
					Algorithm:    algorithms.ECDSA_SECP256K1,
					VerifierType: verifiers.ETH_ADDRESS,
					Verifier:     aliceVerifier,
				},
				{
					Lookup:       bobIdentityLocator,
					Algorithm:    algorithms.ECDSA_SECP256K1,
					VerifierType: verifiers.ETH_ADDRESS,
					Verifier:     bobVerifier,
				},
				{
					Lookup:       carolIdentityLocator,
					Algorithm:    algorithms.ECDSA_SECP256K1,
					VerifierType: verifiers.ETH_ADDRESS,
					Verifier:     carolVerifier,
				},
			},
		},
		PostAssembly: &components.TransactionPostAssembly{
			AttestationPlan: []*prototk.AttestationRequest{
				{
					Name:            "foo",
					AttestationType: prototk.AttestationType_ENDORSE,
					Algorithm:       algorithms.ECDSA_SECP256K1,
					VerifierType:    verifiers.ETH_ADDRESS,
					PayloadType:     signpayloads.OPAQUE_TO_RSV,
					Parties: []string{
						aliceIdentityLocator,
						bobIdentityLocator,
						carolIdentityLocator,
					},
				},
			},
			Endorsements: []*prototk.AttestationResult{
				{
					Name:            "foo",
					AttestationType: prototk.AttestationType_ENDORSE,
					Verifier: &prototk.ResolvedVerifier{
						Lookup:       carolIdentityLocator,
						Algorithm:    algorithms.ECDSA_SECP256K1,
						Verifier:     carolVerifier,
						VerifierType: verifiers.ETH_ADDRESS,
					},
					Payload: tktypes.RandBytes(32),
				},
				{
					Name:            "foo",
					AttestationType: prototk.AttestationType_ENDORSE,
					Verifier: &prototk.ResolvedVerifier{
						Lookup:       aliceIdentityLocator,
						Algorithm:    algorithms.ECDSA_SECP256K1,
						Verifier:     aliceVerifier,
						VerifierType: verifiers.ETH_ADDRESS,
					},
					Payload: tktypes.RandBytes(32),
				},
				{
					Name:            "foo",
					AttestationType: prototk.AttestationType_ENDORSE,
					Verifier: &prototk.ResolvedVerifier{
						Lookup:       bobIdentityLocator,
						Algorithm:    algorithms.ECDSA_SECP256K1,
						Verifier:     bobVerifier,
						VerifierType: verifiers.ETH_ADDRESS,
					},
					Payload: tktypes.RandBytes(32),
				},
			},
		},
	}

	tp, _ := newTransactionFlowForTesting(t, ctx, testTx, "node1")
	result := tp.hasOutstandingEndorsementRequests(ctx)
	assert.False(t, result)
}

func TestRequestRemoteEndorsements(t *testing.T) {
	ctx := context.Background()
	newTxID := uuid.New()

	aliceIdentityLocator := "alice@node1"
	aliceVerifier := tktypes.RandAddress().String()
	bobIdentityLocator := "bob@node2"
	bobVerifier := tktypes.RandAddress().String()
	carolIdentityLocator := "carol@node2"
	carolVerifier := tktypes.RandAddress().String()

	testContractAddress := *tktypes.RandAddress()
	// create a transaction as if we have already
	// - resolved the verifiers
	// - assembled it
	// - signed it
	// so next step is to request endorsements
	testTx := &components.PrivateTransaction{
		ID: newTxID,
		Inputs: &components.TransactionInputs{
			To:   testContractAddress,
			From: aliceIdentityLocator,
		},
		PreAssembly: &components.TransactionPreAssembly{
			TransactionSpecification: &prototk.TransactionSpecification{
				From:          aliceIdentityLocator,
				TransactionId: newTxID.String(),
			},
			Verifiers: []*prototk.ResolvedVerifier{
				{
					Lookup:       aliceIdentityLocator,
					Algorithm:    algorithms.ECDSA_SECP256K1,
					VerifierType: verifiers.ETH_ADDRESS,
					Verifier:     aliceVerifier,
				},
				{
					Lookup:       bobIdentityLocator,
					Algorithm:    algorithms.ECDSA_SECP256K1,
					VerifierType: verifiers.ETH_ADDRESS,
					Verifier:     bobVerifier,
				},
				{
					Lookup:       carolIdentityLocator,
					Algorithm:    algorithms.ECDSA_SECP256K1,
					VerifierType: verifiers.ETH_ADDRESS,
					Verifier:     carolVerifier,
				},
			},
		},
		PostAssembly: &components.TransactionPostAssembly{
			AttestationPlan: []*prototk.AttestationRequest{
				{
					Name:            "foo",
					AttestationType: prototk.AttestationType_ENDORSE,
					Algorithm:       algorithms.ECDSA_SECP256K1,
					VerifierType:    verifiers.ETH_ADDRESS,
					PayloadType:     signpayloads.OPAQUE_TO_RSV,
					Parties: []string{
						aliceIdentityLocator,
						bobIdentityLocator,
						carolIdentityLocator,
					},
				},
			},
		},
	}

	sendingNodeName := "sendingNode"

	tp, mocks := newTransactionFlowForTesting(t, ctx, testTx, sendingNodeName)
	mocks.coordinatorSelector.On("SelectCoordinatorNode", mock.Anything, mock.Anything, mock.Anything).Return(sendingNodeName, nil)
	mocks.transportWriter.On("SendEndorsementRequest",
		mock.Anything,
		"alice@node1",
		"node1",
		testContractAddress.String(),
		newTxID.String(),
		mock.Anything, //attRequest
		mock.Anything, //TransactionSpecification,
		mock.Anything, //Verifiers,
		mock.Anything, //Signatures,
		mock.Anything, //InputStates,
		mock.Anything, //OutputStates,
	).Return(nil).Once()
	mocks.transportWriter.On("SendEndorsementRequest",
		mock.Anything,
		"bob@node2",
		"node2",
		testContractAddress.String(),
		newTxID.String(),
		mock.Anything, //attRequest
		mock.Anything, //TransactionSpecification,
		mock.Anything, //Verifiers,
		mock.Anything, //Signatures,
		mock.Anything, //InputStates,
		mock.Anything, //OutputStates,
	).Return(nil).Once()
	mocks.transportWriter.On("SendEndorsementRequest",
		mock.Anything,
		"carol@node2",
		"node2",
		testContractAddress.String(),
		newTxID.String(),
		mock.Anything, //attRequest
		mock.Anything, //TransactionSpecification,
		mock.Anything, //Verifiers,
		mock.Anything, //Signatures,
		mock.Anything, //InputStates,
		mock.Anything, //OutputStates,
	).Return(nil).Once()
	tp.Action(ctx)

	mocks.transportWriter.AssertExpectations(t)

	//Check that we don't send the same requests again (we specified Once in the mocks above)
	tp.Action(ctx)

}

func TestRequestLocalEndorsements(t *testing.T) {
	ctx := context.Background()
	newTxID := uuid.New()
	//endorsers are on the same node as the sender
	sendingNodeName := "sendingNode"

	aliceIdentityLocator := "alice@" + sendingNodeName
	aliceVerifier := tktypes.RandAddress().String()
	bobIdentityLocator := "bob@" + sendingNodeName
	bobVerifier := tktypes.RandAddress().String()
	carolIdentityLocator := "carol@" + sendingNodeName
	carolVerifier := tktypes.RandAddress().String()

	testContractAddress := *tktypes.RandAddress()
	// create a transaction as if we have already
	// - resolved the verifiers
	// - assembled it
	// - signed it
	// so next step is to request endorsements
	testTx := &components.PrivateTransaction{
		ID: newTxID,
		Inputs: &components.TransactionInputs{
			To:   testContractAddress,
			From: aliceIdentityLocator,
		},
		PreAssembly: &components.TransactionPreAssembly{
			TransactionSpecification: &prototk.TransactionSpecification{
				From:          aliceIdentityLocator,
				TransactionId: newTxID.String(),
			},
			Verifiers: []*prototk.ResolvedVerifier{
				{
					Lookup:       aliceIdentityLocator,
					Algorithm:    algorithms.ECDSA_SECP256K1,
					VerifierType: verifiers.ETH_ADDRESS,
					Verifier:     aliceVerifier,
				},
				{
					Lookup:       bobIdentityLocator,
					Algorithm:    algorithms.ECDSA_SECP256K1,
					VerifierType: verifiers.ETH_ADDRESS,
					Verifier:     bobVerifier,
				},
				{
					Lookup:       carolIdentityLocator,
					Algorithm:    algorithms.ECDSA_SECP256K1,
					VerifierType: verifiers.ETH_ADDRESS,
					Verifier:     carolVerifier,
				},
			},
		},
		PostAssembly: &components.TransactionPostAssembly{
			AttestationPlan: []*prototk.AttestationRequest{
				{
					Name:            "foo",
					AttestationType: prototk.AttestationType_ENDORSE,
					Algorithm:       algorithms.ECDSA_SECP256K1,
					VerifierType:    verifiers.ETH_ADDRESS,
					PayloadType:     signpayloads.OPAQUE_TO_RSV,
					Parties: []string{
						aliceIdentityLocator,
						bobIdentityLocator,
						carolIdentityLocator,
					},
				},
			},
		},
	}

	tp, mocks := newTransactionFlowForTesting(t, ctx, testTx, sendingNodeName)
	mocks.coordinatorSelector.On("SelectCoordinatorNode", mock.Anything, mock.Anything, mock.Anything).Return(sendingNodeName, nil)
	mocks.endorsementGatherer.On("GatherEndorsement",
		mock.Anything, // context
		mock.Anything, //TransactionSpecification,
		mock.Anything, //Verifiers,
		mock.Anything, //Signatures,
		mock.Anything, //InputStates,
		mock.Anything, //ReadStates,
		mock.Anything, //OutputStates,
		"alice@"+sendingNodeName,
		mock.Anything, //attRequest
	).Return(
		&prototk.AttestationResult{
			Name: "foo",
			Verifier: &prototk.ResolvedVerifier{
				Lookup:       aliceIdentityLocator,
				Algorithm:    algorithms.ECDSA_SECP256K1,
				Verifier:     aliceVerifier,
				VerifierType: verifiers.ETH_ADDRESS,
			},
		},
		nil,
		nil,
	).Once()
	mocks.endorsementGatherer.On("GatherEndorsement",
		mock.Anything, // context
		mock.Anything, //TransactionSpecification,
		mock.Anything, //Verifiers,
		mock.Anything, //Signatures,
		mock.Anything, //InputStates,
		mock.Anything, //ReadStates,
		mock.Anything, //OutputStates,
		"bob@"+sendingNodeName,
		mock.Anything, //attRequest
	).Return(
		&prototk.AttestationResult{
			Name: "foo",
			Verifier: &prototk.ResolvedVerifier{
				Lookup:       aliceIdentityLocator,
				Algorithm:    algorithms.ECDSA_SECP256K1,
				Verifier:     aliceVerifier,
				VerifierType: verifiers.ETH_ADDRESS,
			},
		},
		nil,
		nil,
	).Once()
	mocks.endorsementGatherer.On("GatherEndorsement",
		mock.Anything, // context
		mock.Anything, //TransactionSpecification,
		mock.Anything, //Verifiers,
		mock.Anything, //Signatures,
		mock.Anything, //InputStates,
		mock.Anything, //ReadStates,
		mock.Anything, //OutputStates,
		"carol@"+sendingNodeName,
		mock.Anything, //attRequest
	).Return(
		&prototk.AttestationResult{
			Name: "foo",
			Verifier: &prototk.ResolvedVerifier{
				Lookup:       aliceIdentityLocator,
				Algorithm:    algorithms.ECDSA_SECP256K1,
				Verifier:     aliceVerifier,
				VerifierType: verifiers.ETH_ADDRESS,
			},
		},
		nil,
		nil,
	).Once()

	mocks.publisher.On("PublishTransactionEndorsedEvent", mock.Anything, newTxID.String(), mock.Anything, mock.Anything).Return().Times(3)
	tp.Action(ctx)

	mocks.transportWriter.AssertExpectations(t)

	//Check that we don't send the same requests again (we specified Once in the mocks above)
	tp.Action(ctx)

}

func TestTimedOutEndorsementRequest(t *testing.T) {
	// This can happen if the remote node is slow to respond
	//or the network is unreliable and the request or the response has been lost
	// we don't necessarily know which of those is the case so we just treat it as a timeout
	// this could / should be tested as part of an E2E reliability test but
	// we like to get confidence at a white box level because there is no guarantee
	// that the E2E test will be able to reproduce the conditions that cause the timeout

	ctx := context.Background()
	newTxID := uuid.New()

	aliceIdentityLocator := "alice@node1"
	aliceVerifier := tktypes.RandAddress().String()
	bobIdentityLocator := "bob@node2"
	bobVerifier := tktypes.RandAddress().String()
	carolIdentityLocator := "carol@node2"
	carolVerifier := tktypes.RandAddress().String()

	testContractAddress := *tktypes.RandAddress()
	// create a transaction as if we have already
	// - resolved the verifiers
	// - assembled it
	// - signed it
	// so next step is to request endorsements
	testTx := &components.PrivateTransaction{
		ID: newTxID,
		Inputs: &components.TransactionInputs{
			To:   testContractAddress,
			From: aliceIdentityLocator,
		},
		PreAssembly: &components.TransactionPreAssembly{
			TransactionSpecification: &prototk.TransactionSpecification{
				From:          aliceIdentityLocator,
				TransactionId: newTxID.String(),
			},
			Verifiers: []*prototk.ResolvedVerifier{
				{
					Lookup:       aliceIdentityLocator,
					Algorithm:    algorithms.ECDSA_SECP256K1,
					VerifierType: verifiers.ETH_ADDRESS,
					Verifier:     aliceVerifier,
				},
				{
					Lookup:       bobIdentityLocator,
					Algorithm:    algorithms.ECDSA_SECP256K1,
					VerifierType: verifiers.ETH_ADDRESS,
					Verifier:     bobVerifier,
				},
				{
					Lookup:       carolIdentityLocator,
					Algorithm:    algorithms.ECDSA_SECP256K1,
					VerifierType: verifiers.ETH_ADDRESS,
					Verifier:     carolVerifier,
				},
			},
		},
		PostAssembly: &components.TransactionPostAssembly{
			AttestationPlan: []*prototk.AttestationRequest{
				{
					Name:            "foo",
					AttestationType: prototk.AttestationType_ENDORSE,
					Algorithm:       algorithms.ECDSA_SECP256K1,
					VerifierType:    verifiers.ETH_ADDRESS,
					PayloadType:     signpayloads.OPAQUE_TO_RSV,
					Parties: []string{
						bobIdentityLocator,
						carolIdentityLocator,
					},
				},
			},
		},
	}

	tp, mocks := newTransactionFlowForTesting(t, ctx, testTx, "node1")
	mocks.coordinatorSelector.On("SelectCoordinatorNode", mock.Anything, mock.Anything, mock.Anything).Return("node1", nil)

	fakeClock := &fakeClock{timePassed: 0}
	tp.clock = fakeClock

	expectEndorsementRequest := func(party, node string) {
		mocks.transportWriter.On("SendEndorsementRequest",
			mock.Anything,
			party,
			node,
			testContractAddress.String(),
			newTxID.String(),
			mock.Anything, //attRequest
			mock.Anything, //TransactionSpecification,
			mock.Anything, //Verifiers,
			mock.Anything, //Signatures,
			mock.Anything, //InputStates,
			mock.Anything, //OutputStates,
		).Return(nil).Once()
	}

	expectEndorsementRequest("bob@node2", "node2")
	expectEndorsementRequest("carol@node2", "node2")
	tp.Action(ctx)
	mocks.transportWriter.AssertExpectations(t)

	//Check that we don't send the same requests again because it hasn't timeout out yet
	tp.Action(ctx)

	//simulate the passing of time
	fakeClock.timePassed = 1*time.Minute + 1*time.Second
	expectEndorsementRequest("bob@node2", "node2")
	expectEndorsementRequest("carol@node2", "node2")
	tp.Action(ctx)
	mocks.transportWriter.AssertExpectations(t)

	//Check that we don't send the same requests again because it hasn't timeout out yet
	tp.Action(ctx)

	//Receive response from bob
	tp.applyTransactionEndorsedEvent(ctx, &ptmgrtypes.TransactionEndorsedEvent{
		PrivateTransactionEventBase: ptmgrtypes.PrivateTransactionEventBase{
			TransactionID:   newTxID.String(),
			ContractAddress: testContractAddress.String(),
		},
		Endorsement: &prototk.AttestationResult{
			Name: "foo",
			Verifier: &prototk.ResolvedVerifier{
				Lookup:       bobIdentityLocator,
				Algorithm:    algorithms.ECDSA_SECP256K1,
				Verifier:     bobVerifier,
				VerifierType: verifiers.ETH_ADDRESS,
			},
		},
	})

	//simulate the passing of time
	fakeClock.timePassed = fakeClock.timePassed + 1*time.Minute + 1*time.Second
	expectEndorsementRequest("carol@node2", "node2")
	tp.Action(ctx)
}

func TestEndorsementRequestAfterReassemble(t *testing.T) {
	// when we have re-assembled the transaction after sending an endorsement request
	// we should resend the request and should ignore any responses that eventually come back for the
	// original request

	//TODO skip for now while we think about his.
	// the main reason for re-assembly would be a rejected endorsement because we are trying to spend a state that has ( unbeknown to us) been spent already
	// in that situation ( most likely in pente) we actually want to trigger a delegation handover
	// however, after delegation re-assembly is likely
	t.Skip()

}

func TestDuplicateEndorsementResponse(t *testing.T) {
	// we effectively have an at least once delivery guarantee on the endorsement requests and responses
	// so we need to be able to handle duplicate responses
	ctx := context.Background()
	newTxID := uuid.New()

	senderNodeName := "senderNode"
	senderIdentityLocator := "sender@" + senderNodeName
	aliceIdentityLocator := "alice@node1"
	aliceVerifier := tktypes.RandAddress().String()
	bobIdentityLocator := "bob@node2"
	bobVerifier := tktypes.RandAddress().String()
	carolIdentityLocator := "carol@node2"
	carolVerifier := tktypes.RandAddress().String()

	testContractAddress := *tktypes.RandAddress()
	// create a transaction as if we have already:
	// - resolved the verifiers
	// - assembled it
	// - signed it
	// so next step is to request endorsements
	testTx := &components.PrivateTransaction{
		ID: newTxID,
		Inputs: &components.TransactionInputs{
			To:   testContractAddress,
			From: senderIdentityLocator,
		},
		PreAssembly: &components.TransactionPreAssembly{
			TransactionSpecification: &prototk.TransactionSpecification{
				From:          senderIdentityLocator,
				TransactionId: newTxID.String(),
			},
			Verifiers: []*prototk.ResolvedVerifier{
				{
					Lookup:       senderIdentityLocator,
					Algorithm:    algorithms.ECDSA_SECP256K1,
					VerifierType: verifiers.ETH_ADDRESS,
					Verifier:     aliceVerifier,
				},
				{
					Lookup:       aliceIdentityLocator,
					Algorithm:    algorithms.ECDSA_SECP256K1,
					VerifierType: verifiers.ETH_ADDRESS,
					Verifier:     aliceVerifier,
				},
				{
					Lookup:       bobIdentityLocator,
					Algorithm:    algorithms.ECDSA_SECP256K1,
					VerifierType: verifiers.ETH_ADDRESS,
					Verifier:     bobVerifier,
				},
				{
					Lookup:       carolIdentityLocator,
					Algorithm:    algorithms.ECDSA_SECP256K1,
					VerifierType: verifiers.ETH_ADDRESS,
					Verifier:     carolVerifier,
				},
			},
		},
		PostAssembly: &components.TransactionPostAssembly{
			AttestationPlan: []*prototk.AttestationRequest{
				{
					Name:            "foo",
					AttestationType: prototk.AttestationType_ENDORSE,
					Algorithm:       algorithms.ECDSA_SECP256K1,
					VerifierType:    verifiers.ETH_ADDRESS,
					PayloadType:     signpayloads.OPAQUE_TO_RSV,
					Parties: []string{
						aliceIdentityLocator,
						bobIdentityLocator,
						carolIdentityLocator,
					},
				},
			},
		},
	}

	tp, mocks := newTransactionFlowForTesting(t, ctx, testTx, senderNodeName)
	mocks.coordinatorSelector.On("SelectCoordinatorNode", mock.Anything, mock.Anything, mock.Anything).Return(senderNodeName, nil)

	fakeClock := &fakeClock{timePassed: 0}
	tp.clock = fakeClock

	expectEndorsementRequest := func(party, node string) {
		mocks.transportWriter.On("SendEndorsementRequest",
			mock.Anything,
			party,
			node,
			testContractAddress.String(),
			newTxID.String(),
			mock.Anything, //attRequest
			mock.Anything, //TransactionSpecification,
			mock.Anything, //Verifiers,
			mock.Anything, //Signatures,
			mock.Anything, //InputStates,
			mock.Anything, //OutputStates,
		).Return(nil).Once()
	}

	expectEndorsementRequest("alice@node1", "node1")
	expectEndorsementRequest("bob@node2", "node2")
	expectEndorsementRequest("carol@node2", "node2")
	tp.Action(ctx)
	mocks.transportWriter.AssertExpectations(t)

	//Receive response from alice
	tp.applyTransactionEndorsedEvent(ctx, &ptmgrtypes.TransactionEndorsedEvent{
		PrivateTransactionEventBase: ptmgrtypes.PrivateTransactionEventBase{
			TransactionID:   newTxID.String(),
			ContractAddress: testContractAddress.String(),
		},
		Endorsement: &prototk.AttestationResult{
			Name: "foo",
			Verifier: &prototk.ResolvedVerifier{
				Lookup:       aliceIdentityLocator,
				Algorithm:    algorithms.ECDSA_SECP256K1,
				Verifier:     aliceVerifier,
				VerifierType: verifiers.ETH_ADDRESS,
			},
		},
	})

	//simulate the passing of time
	fakeClock.timePassed = 1*time.Minute + 1*time.Second
	expectEndorsementRequest("bob@node2", "node2")
	expectEndorsementRequest("carol@node2", "node2")
	tp.Action(ctx)
	mocks.transportWriter.AssertExpectations(t)

	//Receive both responses from carol
	tp.applyTransactionEndorsedEvent(ctx, &ptmgrtypes.TransactionEndorsedEvent{
		PrivateTransactionEventBase: ptmgrtypes.PrivateTransactionEventBase{
			TransactionID:   newTxID.String(),
			ContractAddress: testContractAddress.String(),
		},
		Endorsement: &prototk.AttestationResult{
			Name: "foo",
			Verifier: &prototk.ResolvedVerifier{
				Lookup:       carolIdentityLocator,
				Algorithm:    algorithms.ECDSA_SECP256K1,
				Verifier:     carolVerifier,
				VerifierType: verifiers.ETH_ADDRESS,
			},
		},
	})
	tp.applyTransactionEndorsedEvent(ctx, &ptmgrtypes.TransactionEndorsedEvent{
		PrivateTransactionEventBase: ptmgrtypes.PrivateTransactionEventBase{
			TransactionID:   newTxID.String(),
			ContractAddress: testContractAddress.String(),
		},
		Endorsement: &prototk.AttestationResult{
			Name: "foo",
			Verifier: &prototk.ResolvedVerifier{
				Lookup:       carolIdentityLocator,
				Algorithm:    algorithms.ECDSA_SECP256K1,
				Verifier:     carolVerifier,
				VerifierType: verifiers.ETH_ADDRESS,
			},
		},
	})

	// no further action because we are still waiting for a response from bob
	//even though we have received 3 responses, we are not ready for dispatch because 2 of them are duplicates
	tp.Action(ctx)
}

type fakeClock struct {
	timePassed time.Duration
}

func (f *fakeClock) Now() time.Time {
	return time.Now().Add(f.timePassed)
}
