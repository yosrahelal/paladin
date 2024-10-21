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
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/hyperledger/firefly-common/pkg/i18n"
	"github.com/kaleido-io/paladin/core/internal/components"
	"github.com/kaleido-io/paladin/core/internal/msgs"
	"github.com/kaleido-io/paladin/core/internal/privatetxnmgr/ptmgrtypes"
	"github.com/kaleido-io/paladin/core/internal/privatetxnmgr/syncpoints"
	"github.com/kaleido-io/paladin/core/internal/statedistribution"

	"github.com/kaleido-io/paladin/toolkit/pkg/log"
	"github.com/kaleido-io/paladin/toolkit/pkg/pldapi"
	"github.com/kaleido-io/paladin/toolkit/pkg/prototk"
	"github.com/kaleido-io/paladin/toolkit/pkg/tktypes"
)

func NewPaladinTransactionProcessor(ctx context.Context, transaction *components.PrivateTransaction, nodeID string, components components.AllComponents, domainAPI components.DomainSmartContract /*sequencer ptmgrtypes.Sequencer,*/, publisher ptmgrtypes.Publisher, endorsementGatherer ptmgrtypes.EndorsementGatherer, identityResolver components.IdentityResolver, syncPoints syncpoints.SyncPoints, transportWriter ptmgrtypes.TransportWriter) ptmgrtypes.TxProcessor {
	return &PaladinTxProcessor{
		stageErrorRetry:             10 * time.Second,
		domainAPI:                   domainAPI,
		nodeID:                      nodeID,
		components:                  components,
		publisher:                   publisher,
		endorsementGatherer:         endorsementGatherer,
		transaction:                 transaction,
		status:                      "new",
		identityResolver:            identityResolver,
		syncPoints:                  syncPoints,
		transportWriter:             transportWriter,
		finalizeRequired:            false,
		finalizePending:             false,
		requestedVerifierResolution: false,
		requestedSignatures:         false,
		requestedEndorsement:        false,
		complete:                    false,
		localCoordinator:            true,
		readyForSequencing:          false,
		dispatched:                  false,
	}
}

type PaladinTxProcessor struct {
	stageErrorRetry             time.Duration
	components                  components.AllComponents
	nodeID                      string
	domainAPI                   components.DomainSmartContract
	transaction                 *components.PrivateTransaction
	publisher                   ptmgrtypes.Publisher
	endorsementGatherer         ptmgrtypes.EndorsementGatherer
	status                      string
	latestEvent                 string
	latestError                 string
	identityResolver            components.IdentityResolver
	syncPoints                  syncpoints.SyncPoints
	transportWriter             ptmgrtypes.TransportWriter
	finalizeReason              string
	finalizeRequired            bool
	finalizePending             bool
	complete                    bool
	requestedVerifierResolution bool
	requestedSignatures         bool
	requestedEndorsement        bool
	localCoordinator            bool
	readyForSequencing          bool
	dispatched                  bool
}

func (ts *PaladinTxProcessor) GetTxStatus(ctx context.Context) (components.PrivateTxStatus, error) {
	return components.PrivateTxStatus{
		TxID:        ts.transaction.ID.String(),
		Status:      ts.status,
		LatestEvent: ts.latestEvent,
		LatestError: ts.latestError,
	}, nil
}

func (ts *PaladinTxProcessor) ApplyEvent(ctx context.Context, event ptmgrtypes.PrivateTransactionEvent) {

	//First we update our in memory record of the transaction with the data from the event
	switch event := event.(type) {
	case *ptmgrtypes.TransactionSubmittedEvent:
		ts.applyTransactionSubmittedEvent(ctx, event)
	case *ptmgrtypes.TransactionSwappedInEvent:
		ts.applyTransactionSwappedInEvent(ctx, event)
	case *ptmgrtypes.TransactionSignedEvent:
		ts.applyTransactionSignedEvent(ctx, event)
	case *ptmgrtypes.TransactionEndorsedEvent:
		ts.applyTransactionEndorsedEvent(ctx, event)
	case *ptmgrtypes.TransactionAssembledEvent:
		ts.applyTransactionAssembledEvent(ctx, event)
	case *ptmgrtypes.TransactionAssembleFailedEvent:
		ts.applyTransactionAssembleFailedEvent(ctx, event)
	case *ptmgrtypes.TransactionDispatchedEvent:
		ts.applyTransactionDispatchedEvent(ctx, event)
	case *ptmgrtypes.TransactionConfirmedEvent:
		ts.applyTransactionConfirmedEvent(ctx, event)
	case *ptmgrtypes.TransactionRevertedEvent:
		ts.applyTransactionRevertedEvent(ctx, event)
	case *ptmgrtypes.TransactionDelegatedEvent:
		ts.applyTransactionDelegatedEvent(ctx, event)
	case *ptmgrtypes.ResolveVerifierResponseEvent:
		ts.applyResolveVerifierResponseEvent(ctx, event)
	case *ptmgrtypes.ResolveVerifierErrorEvent:
		ts.applyResolveVerifierErrorEvent(ctx, event)
	case *ptmgrtypes.TransactionFinalizedEvent:
		ts.applyTransactionFinalizedEvent(ctx, event)
	case *ptmgrtypes.TransactionFinalizeError:
		ts.applyTransactionFinalizeError(ctx, event)

	default:
		log.L(ctx).Warnf("Unknown event type: %T", event)
	}
}

func (ts *PaladinTxProcessor) IsComplete() bool {
	return ts.complete
}

func (ts *PaladinTxProcessor) ReadyForSequencing() bool {
	return ts.readyForSequencing
}

func (ts *PaladinTxProcessor) Dispatched() bool {
	return ts.dispatched
}

func (ts *PaladinTxProcessor) IsEndorsed(ctx context.Context) bool {
	return !ts.hasOutstandingEndorsementRequests(ctx)
}

func (ts *PaladinTxProcessor) CoordinatingLocally() bool {
	return ts.localCoordinator
}

func (ts *PaladinTxProcessor) applyTransactionSubmittedEvent(ctx context.Context, _ *ptmgrtypes.TransactionSubmittedEvent) {
	log.L(ctx).Debug("PaladinTxProcessor:applyTransactionSubmittedEvent")

	ts.latestEvent = "TransactionSubmittedEvent"

}

func (ts *PaladinTxProcessor) applyTransactionSwappedInEvent(ctx context.Context, _ *ptmgrtypes.TransactionSwappedInEvent) {
	log.L(ctx).Debug("PaladinTxProcessor:applyTransactionSwappedInEvent")

	ts.latestEvent = "TransactionSwappedInEvent"

}

func (ts *PaladinTxProcessor) Action(ctx context.Context) {
	log.L(ctx).Debug("PaladinTxProcessor:Action")
	if ts.complete {
		log.L(ctx).Infof("Transaction %s is complete", ts.transaction.ID.String())
		return
	}

	if ts.dispatched {
		log.L(ctx).Infof("Transaction %s is dispatched", ts.transaction.ID.String())
		return
	}

	// Lets get the nasty stuff out of the way first
	// if the event handler has marked the transaction as failed, then we initiate the finalize sync point
	if ts.finalizeRequired {
		if ts.finalizePending {
			log.L(ctx).Infof("Transaction %s finalize already pending", ts.transaction.ID.String())
			return
		}
		//we know we need to finalize but we are not currently waiting for a finalize to complete
		// most likely a previous attempt to finalize has failed
		ts.finalize(ctx)
	}

	if ts.transaction.PreAssembly == nil {
		panic("PreAssembly is nil.")
		//This should never happen unless there is a serious programming error or the memory has been corrupted
		// PreAssembly is checked for nil after InitTransaction which is during the synchronous transaction request
		// and before it is added to the transaction processor / dispatched to the event loop
	}

	if ts.transaction.PostAssembly == nil {
		log.L(ctx).Debug("not assembled yet - or was assembled and reverted")

		//if we have not sent a request, or if the request has timed out or been invalided by a re-assembly, then send the request
		ts.requestVerifierResolution(ctx)
		if ts.hasOutstandingVerifierRequests(ctx) {
			log.L(ctx).Infof("Transaction %s not ready to assemble. Waiting for verifiers to be resolved", ts.transaction.ID.String())
			return
		}

		ts.requestAssemble(ctx)
		if ts.transaction.PostAssembly == nil {
			log.L(ctx).Infof("Transaction %s not assembled. Waiting for assembler to return", ts.transaction.ID.String())
			return
		}
	}

	ts.delegateIfRequired(ctx)
	if ts.status == "delegating" {
		log.L(ctx).Infof("Transaction %s is delegating", ts.transaction.ID.String())
		return
	}

	if ts.status == "delegated" {
		// probably should not get here because the orchestrator should have removed the transaction processor
		log.L(ctx).Infof("Transaction %s has been delegated", ts.transaction.ID.String())
		return
	}

	if ts.transaction.PostAssembly.OutputStatesPotential != nil && ts.transaction.PostAssembly.OutputStates == nil {
		// We need to write the potential states to the domain before we can sign or endorse the transaction
		// but there is no point in doing that until we are sure that the transaction is going to be coordinated locally
		// so this is the earliest, and latest, point in the flow that we can do this
		err := ts.domainAPI.WritePotentialStates(ts.endorsementGatherer.DomainContext(), ts.transaction)
		if err != nil {
			//Any error from WritePotentialStates is likely to be caused by an invalid init or assemble of the transaction
			// which ist most likely a programming error in the domain or the domain manager or privateTxManager
			// not much we can do other than revert the transaction with an internal error
			errorMessage := fmt.Sprintf("Failed to write potential states: %s", err)
			log.L(ctx).Error(errorMessage)
			//TODO publish an event that will cause the transaction to be reverted
			//ts.revertTransaction(ctx, i18n.ExpandWithCode(ctx, i18n.MessageKey(msgs.MsgPrivateTxManagerInternalError), errorMessage))
			return
		}
	}
	ts.readyForSequencing = true

	//If we get here, we have an assembled transaction and have no intention of delegating it
	// so we are responsible for coordinating the endorsement flow

	// either because it was submitted locally and we decided not to delegate or because it was delegated to us
	// start with fulfilling any outstanding signature requests
	ts.requestSignatures(ctx)
	if ts.hasOutstandingSignatureRequests() {
		return
	}
	ts.status = "signed"

	ts.requestEndorsements(ctx)
	if ts.hasOutstandingEndorsementRequests(ctx) {
		return
	}
	ts.status = "endorsed"

	// TODO is this too late to be resolving the dispatch key?
	// Can we do it any earlier or do we need to wait until we have all endorsements ( i.e. so that the endorser can declare ENDORSER_MUST_SUBMIT)
	// We would need to do it earlier if we want to avoid transactions for different dispatch keys ending up in the same dependency graph
	if ts.transaction.Signer == "" {
		err := ts.domainAPI.ResolveDispatch(ctx, ts.transaction)
		if err != nil {

			log.L(ctx).Errorf("Failed to resolve dispatch for transaction %s: %s", ts.transaction.ID.String(), err)
			ts.latestError = i18n.ExpandWithCode(ctx, i18n.MessageKey(msgs.MsgPrivateTxManagerResolveDispatchError), err.Error())

			//TODO as it stands, we will just enter a retry loop of trying to resolve the dispatcher next time the event loop triggers an action
			// if we are lucky, that will be triggered by an event that somehow changes the in memory state in a way that the dispatcher can be
			// resolved but that is unlikely
			// would it be more appropriate to re-assemble ( or even revert ) the transaction here?
			return
		}
	}
}

func (ts *PaladinTxProcessor) hasOutstandingVerifierRequests(ctx context.Context) bool {
	log.L(ctx).Debug("PaladinTxProcessor:hasOutstandingVerifierRequests")

	// assume they are all resolved until we find one in RequiredVerifiers that is not in Verifiers
	verifiersResolved := true
	for _, v := range ts.transaction.PreAssembly.RequiredVerifiers {
		thisVerifierIsResolved := false
		for _, rv := range ts.transaction.PreAssembly.Verifiers {
			if rv.Lookup == v.Lookup {
				thisVerifierIsResolved = true
				break
			}
		}
		if !thisVerifierIsResolved {
			verifiersResolved = false
		}
	}
	if verifiersResolved {
		return false
	} else {
		log.L(ctx).Infof("Waiting for verifiers to be resolved for transaction %s", ts.transaction.ID.String())
		return true
	}

}

func (ts *PaladinTxProcessor) revertTransaction(ctx context.Context, revertReason string) {
	log.L(ctx).Errorf("Reverting transaction %s: %s", ts.transaction.ID.String(), revertReason)
	//trigger a finalize and update the transaction state so that finalize can be retried if it fails
	ts.finalizeRequired = true
	ts.finalizePending = true
	ts.finalizeReason = revertReason
	ts.finalize(ctx)

}

func (ts *PaladinTxProcessor) finalize(ctx context.Context) {
	log.L(ctx).Errorf("finalize transaction %s: %s", ts.transaction.ID.String(), ts.finalizeReason)
	//flush that to the txmgr database
	// so that the user can see that it is reverted and so that we stop retrying to assemble and endorse it

	ts.syncPoints.QueueTransactionFinalize(
		ctx,
		ts.domainAPI.Address(),
		ts.transaction.ID,
		ts.finalizeReason,
		func(ctx context.Context) {
			//we are not on the main event loop thread so can't update in memory state here.
			// need to go back into the event loop
			log.L(ctx).Infof("Transaction %s finalize committed", ts.transaction.ID.String())
			go ts.publisher.PublishTransactionFinalizedEvent(ctx, ts.transaction.ID.String())
		},
		func(ctx context.Context, rollbackErr error) {
			//we are not on the main event loop thread so can't update in memory state here.
			// need to go back into the event loop
			log.L(ctx).Errorf("Transaction %s finalize rolled back: %s", ts.transaction.ID.String(), rollbackErr)
			go ts.publisher.PublishTransactionFinalizeError(ctx, ts.transaction.ID.String(), ts.finalizeReason, rollbackErr)
		},
	)
}

func (ts *PaladinTxProcessor) applyTransactionAssembledEvent(ctx context.Context, _ *ptmgrtypes.TransactionAssembledEvent) {
	ts.latestEvent = "TransactionAssembledEvent"
	if ts.transaction.PostAssembly.AssemblyResult == prototk.AssembleTransactionResponse_REVERT {
		// Not sure if any domains actually use this but it is a valid response to indicate failure
		log.L(ctx).Errorf("AssemblyResult is AssembleTransactionResponse_REVERT")
		ts.revertTransaction(ctx, i18n.ExpandWithCode(ctx, i18n.MessageKey(msgs.MsgPrivateTxManagerAssembleRevert)))
		return
	}
	ts.status = "assembled"

}

func (ts *PaladinTxProcessor) applyTransactionAssembleFailedEvent(ctx context.Context, event *ptmgrtypes.TransactionAssembleFailedEvent) {
	log.L(ctx).Debugf("PaladinTxProcessor:applyTransactionAssembleFailedEvent: %s", event.Error)
	ts.latestEvent = "TransactionAssembleFailedEvent"
	ts.latestError = event.Error
	ts.finalizeRequired = true
	ts.finalizeReason = event.Error
}

func (ts *PaladinTxProcessor) delegateIfRequired(ctx context.Context) {
	log.L(ctx).Debug("PaladinTxProcessor:delegateIfRequired")
	if ts.transaction.PostAssembly.AttestationPlan != nil {
		numEndorsers := 0
		endorser := "" // will only be used if there is only one
		for _, attRequest := range ts.transaction.PostAssembly.AttestationPlan {
			if attRequest.AttestationType == prototk.AttestationType_ENDORSE {
				numEndorsers = numEndorsers + len(attRequest.Parties)
				endorser = attRequest.Parties[0]
			}
		}
		//in the special case of a single endorsers in a domain with a submit mode of ENDORSER_SUBMISSION we delegate to that endorser
		// It is most likely that this means we are in the noto domain and
		// that single endorser is the notary and all transactions will be delegated there for endorsement
		// and dispatch to base ledger so we might as well delegate the coordination to it so that
		// it can maximize the optimistic spending of pending states

		if ts.domainAPI.Domain().Configuration().GetBaseLedgerSubmitConfig().GetSubmitMode() == prototk.BaseLedgerSubmitConfig_ENDORSER_SUBMISSION && numEndorsers == 1 {
			endorserNode, err := tktypes.PrivateIdentityLocator(endorser).Node(ctx, true)
			if err != nil {
				log.L(ctx).Errorf("Failed to get node name from locator %s: %s", ts.transaction.PostAssembly.AttestationPlan[0].Parties[0], err)
				ts.latestError = i18n.ExpandWithCode(ctx, i18n.MessageKey(msgs.MsgPrivateTxManagerInternalError), err.Error())
				return
			}
			if endorserNode != ts.nodeID && endorserNode != "" {
				ts.localCoordinator = false
				// TODO persist the delegation and send the request on the callback
				ts.status = "delegating"
				// TODO update to "delegated" once the ack has been received
				err := ts.transportWriter.SendDelegationRequest(
					ctx,
					uuid.New().String(),
					endorserNode,
					ts.transaction,
				)
				if err != nil {
					ts.latestError = i18n.ExpandWithCode(ctx, i18n.MessageKey(msgs.MsgPrivateTxManagerInternalError), err.Error())
				}
				return
			}
		}
	}
}

func (ts *PaladinTxProcessor) requestAssemble(ctx context.Context) {
	//Assemble may require a call to another node ( in the case we have been delegated to coordinate transaction for other nodes)
	//Usually, they will get sent to us already assembled but there may be cases where we need to re-assemble
	// so this needs to be an async step
	// however, there must be only one assemble in progress at a time or else there is a risk that 2 transactions could chose to spend the same state
	//   (TODO - maybe in future, we could further optimise this and allow multiple assembles to be in progress if we can assert that they are not presented with the same available states)
	//   However, before we do that, we really need to sort out the separation of concerns between the domain manager, state store and private transaction manager and where the responsibility to single thread the assembly stream(s) lies

	log.L(ctx).Debug("PaladinTxProcessor:requestAssemble")

	if ts.transaction.PostAssembly != nil {
		log.L(ctx).Debug("already assembled")
		return
	}

	assemblingNode, err := tktypes.PrivateIdentityLocator(ts.transaction.Inputs.From).Node(ctx, true)
	if err != nil {

		log.L(ctx).Errorf("Failed to get node name from locator %s: %s", ts.transaction.Inputs.From, err)
		ts.publisher.PublishTransactionAssembleFailedEvent(
			ctx,
			ts.transaction.ID.String(),
			i18n.ExpandWithCode(ctx, i18n.MessageKey(msgs.MsgPrivateTxManagerInternalError), "Failed to get node name from locator"),
		)
		return
	}

	if assemblingNode == ts.nodeID || assemblingNode == "" {
		//we are the node that is responsible for assembling this transaction
		err = ts.domainAPI.AssembleTransaction(ts.endorsementGatherer.DomainContext(), ts.transaction)
		if err != nil {
			log.L(ctx).Errorf("AssembleTransaction failed: %s", err)
			ts.publisher.PublishTransactionAssembleFailedEvent(ctx,
				ts.transaction.ID.String(),
				i18n.ExpandWithCode(ctx, i18n.MessageKey(msgs.MsgPrivateTxManagerAssembleError), err.Error()),
			)
			return
		}
		if ts.transaction.PostAssembly == nil {
			// This is most likely a programming error in the domain
			log.L(ctx).Errorf("PostAssembly is nil.")
			ts.publisher.PublishTransactionAssembleFailedEvent(
				ctx,
				ts.transaction.ID.String(),
				i18n.ExpandWithCode(ctx, i18n.MessageKey(msgs.MsgPrivateTxManagerInternalError), "AssembleTransaction returned nil PostAssembly"),
			)
			return
		}

		//TODO should probably include the assemble output in the event
		// for now that is not necessary because this is a local assemble and the domain manager updates the transaction that we passed by reference
		// need to decide if we want to continue with that style of interface to the domain manager and if so,
		// we need to do something different when the assembling node is remote
		ts.publisher.PublishTransactionAssembledEvent(ctx,
			ts.transaction.ID.String(),
		)
		return

	} else {
		log.L(ctx).Debugf("Assembling transaction %s on node %s", ts.transaction.ID.String(), assemblingNode)
		//TODO send a request to the node that is responsible for assembling this transaction
	}
}

func (ts *PaladinTxProcessor) applyTransactionSignedEvent(ctx context.Context, event *ptmgrtypes.TransactionSignedEvent) {
	ts.latestEvent = "TransactionSignedEvent"
	log.L(ctx).Debugf("Adding signature to transaction %s", ts.transaction.ID.String())
	ts.transaction.PostAssembly.Signatures = append(ts.transaction.PostAssembly.Signatures, event.AttestationResult)

}

func (ts *PaladinTxProcessor) applyTransactionEndorsedEvent(ctx context.Context, event *ptmgrtypes.TransactionEndorsedEvent) {
	ts.latestEvent = "TransactionEndorsedEvent"
	if event.RevertReason != nil {
		log.L(ctx).Infof("Endorsement for transaction %s was rejected: %s", ts.transaction.ID.String(), *event.RevertReason)
		// endorsement errors trigger a re-assemble
		// if the reason for the endorsement error is a change of state of the universe since the transaction was assembled, then the re-assemble may fail and cause the transaction to be reverted
		// on the other hand, the re-assemble may result in an endorsable version of the transaction.
		// either way, we trigger the re-assembly and hope for the best
		//TODO - there may be other endorsements that are en route, based on the previous assembly.  Need to make sure that
		// we discard them when they do return.
		//only apply at this stage, action will be taken later
		ts.transaction.PostAssembly = nil

	} else {
		log.L(ctx).Infof("Adding endorsement to transaction %s", ts.transaction.ID.String())
		ts.transaction.PostAssembly.Endorsements = append(ts.transaction.PostAssembly.Endorsements, event.Endorsement)

	}
}

func (ts *PaladinTxProcessor) applyTransactionDispatchedEvent(ctx context.Context, event *ptmgrtypes.TransactionDispatchedEvent) {
	log.L(ctx).Debugf("PaladinTxProcessor:applyTransactionDispatchedEvent transactionID:%s nonce:%d signingAddress:%s", ts.transaction.ID.String(), event.Nonce, event.SigningAddress)
	ts.latestEvent = "TransactionDispatchedEvent"
	ts.status = "dispatched"
	ts.dispatched = true
}

func (ts *PaladinTxProcessor) applyTransactionConfirmedEvent(ctx context.Context, event *ptmgrtypes.TransactionConfirmedEvent) {
	log.L(ctx).Debugf("PaladinTxProcessor:applyTransactionConfirmedEvent transactionID:%s contractAddress: %s", ts.transaction.ID.String(), event.ContractAddress)
	ts.latestEvent = "TransactionConfirmedEvent"
	ts.status = "confirmed"
	ts.complete = true
}

func (ts *PaladinTxProcessor) applyTransactionRevertedEvent(ctx context.Context, _ *ptmgrtypes.TransactionRevertedEvent) {
	log.L(ctx).Debugf("PaladinTxProcessor:applyTransactionRevertedEvent transactionID:%s", ts.transaction.ID.String())
	ts.latestEvent = "TransactionRevertedEvent"
	ts.status = "reverted"
}

func (ts *PaladinTxProcessor) applyTransactionDelegatedEvent(ctx context.Context, _ *ptmgrtypes.TransactionDelegatedEvent) {
	log.L(ctx).Debugf("PaladinTxProcessor:applyTransactionDelegatedEvent transactionID:%s", ts.transaction.ID.String())
	ts.latestEvent = "TransactionDelegatedEvent"
	ts.status = "delegated"
}

func (ts *PaladinTxProcessor) applyResolveVerifierResponseEvent(ctx context.Context, event *ptmgrtypes.ResolveVerifierResponseEvent) {
	log.L(ctx).Debug("applyResolveVerifierResponseEvent")
	ts.latestEvent = "ResolveVerifierResponseEvent"

	if ts.transaction.PreAssembly.Verifiers == nil {
		ts.transaction.PreAssembly.Verifiers = make([]*prototk.ResolvedVerifier, 0, len(ts.transaction.PreAssembly.RequiredVerifiers))
	}
	// assuming that the order of resolved verifiers in .PreAssembly.Verifiers does not need to match the order of .PreAssembly.RequiredVerifiers
	ts.transaction.PreAssembly.Verifiers = append(ts.transaction.PreAssembly.Verifiers, &prototk.ResolvedVerifier{
		Lookup:       *event.Lookup,
		Algorithm:    *event.Algorithm,
		Verifier:     *event.Verifier,
		VerifierType: *event.VerifierType,
	})

}

func (ts *PaladinTxProcessor) applyResolveVerifierErrorEvent(ctx context.Context, event *ptmgrtypes.ResolveVerifierErrorEvent) {
	ts.latestEvent = "ResolveVerifierErrorEvent"
	log.L(ctx).Errorf("Failed to resolve verifier %s: %s", *event.Lookup, *event.ErrorMessage)
	//it is possible that this identity was valid when the transaction was assembled but is no longer valid
	// all we can do it try to re-assemble the transaction
	// TODO we might have other resolver verifieres in progress.  Need to make sure that when they are received, we only apply them if they
	// happen to match the requirements new assembled transaction and if that is still nil, then discard them
	ts.transaction.PostAssembly = nil
}

func (ts *PaladinTxProcessor) applyTransactionFinalizedEvent(ctx context.Context, _ *ptmgrtypes.TransactionFinalizedEvent) {
	log.L(ctx).Debugf("PaladinTxProcessor:applyTransactionFinalizedEvent transactionID:%s", ts.transaction.ID.String())
	ts.latestEvent = "TransactionFinalizedEvent"
	ts.complete = true
	log.L(ctx).Debug("HandleTransactionFinalizedEvent")
}

func (ts *PaladinTxProcessor) applyTransactionFinalizeError(ctx context.Context, event *ptmgrtypes.TransactionFinalizeError) {
	log.L(ctx).Errorf("applyTransactionFinalizeError transaction %s: %s", ts.transaction.ID, event.ErrorMessage)

	ts.latestEvent = "TransactionFinalizeError"
	ts.finalizeRequired = true
	ts.finalizePending = false
}

func (ts *PaladinTxProcessor) requestSignature(ctx context.Context, attRequest *prototk.AttestationRequest, partyName string) {

	keyMgr := ts.components.KeyManager()
	unqualifiedLookup, err := tktypes.PrivateIdentityLocator(partyName).Identity(ctx)
	var resolvedKey *pldapi.KeyMappingAndVerifier
	if err == nil {
		resolvedKey, err = keyMgr.ResolveKeyNewDatabaseTX(ctx, unqualifiedLookup, attRequest.Algorithm, attRequest.VerifierType)
	}
	if err != nil {
		log.L(ctx).Errorf("Failed to resolve local signer for %s (algorithm=%s): %s", partyName, attRequest.Algorithm, err)
		ts.latestError = i18n.ExpandWithCode(ctx, i18n.MessageKey(msgs.MsgPrivateTxManagerResolveError), partyName, attRequest.Algorithm, err.Error())
		return
	}
	// TODO this could be calling out to a remote signer, should we be doing these in parallel?
	signaturePayload, err := keyMgr.Sign(ctx, resolvedKey, attRequest.PayloadType, attRequest.Payload)
	if err != nil {
		log.L(ctx).Errorf("failed to sign for party %s (verifier=%s,algorithm=%s): %s", partyName, resolvedKey.Verifier.Verifier, attRequest.Algorithm, err)
		ts.latestError = i18n.ExpandWithCode(ctx, i18n.MessageKey(msgs.MsgPrivateTxManagerSignError), partyName, resolvedKey.Verifier.Verifier, attRequest.Algorithm, err.Error())
		return
	}
	log.L(ctx).Debugf("payload: %x signed %x by %s (%s)", attRequest.Payload, signaturePayload, partyName, resolvedKey.Verifier.Verifier)

	ts.publisher.PublishTransactionSignedEvent(ctx,
		ts.transaction.ID.String(),
		&prototk.AttestationResult{
			Name:            attRequest.Name,
			AttestationType: attRequest.AttestationType,
			Verifier: &prototk.ResolvedVerifier{
				Lookup:       partyName,
				Algorithm:    attRequest.Algorithm,
				Verifier:     resolvedKey.Verifier.Verifier,
				VerifierType: attRequest.VerifierType,
			},
			Payload:     signaturePayload,
			PayloadType: &attRequest.PayloadType,
		},
	)
}

func (ts *PaladinTxProcessor) requestSignatures(ctx context.Context) {

	if ts.requestedSignatures {
		return
	}
	if ts.transaction.PostAssembly.Signatures == nil {
		ts.transaction.PostAssembly.Signatures = make([]*prototk.AttestationResult, 0)
	}
	attPlan := ts.transaction.PostAssembly.AttestationPlan
	attResults := ts.transaction.PostAssembly.Endorsements

	for _, attRequest := range attPlan {
		switch attRequest.AttestationType {
		case prototk.AttestationType_SIGN:
			toBeComplete := true
			for _, ar := range attResults {
				if ar.GetAttestationType().Type() == attRequest.GetAttestationType().Type() {
					toBeComplete = false
					break
				}
			}
			if toBeComplete {

				for _, partyName := range attRequest.Parties {
					go ts.requestSignature(ctx, attRequest, partyName)
				}
			}
		}
	}
	ts.requestedSignatures = true
}

func (ts *PaladinTxProcessor) requestEndorsement(ctx context.Context, party string, attRequest *prototk.AttestationRequest) {

	partyLocator := tktypes.PrivateIdentityLocator(party)
	partyNode, err := partyLocator.Node(ctx, true)
	if err != nil {
		log.L(ctx).Errorf("Failed to get node name from locator %s: %s", party, err)
		//TODO return nil, i18n.WrapError(ctx, err, msgs.MsgPrivateTxManagerInternalError)
	}

	//TODO the following errors are only really possible if the memory has been corrupted or there is a serious programming error
	// so we should probably panic here
	if ts.transaction == nil {
		log.L(ctx).Error("Transaction  is nil")
		return
	}
	if ts.transaction.PreAssembly == nil {
		log.L(ctx).Error("PreAssembly is nil")
		return
	}
	if ts.transaction.PostAssembly == nil {
		log.L(ctx).Error("PostAssembly is nil")
		return
	}
	if partyNode == ts.nodeID || partyNode == "" {
		// This is a local party, so we can endorse it directly
		endorsement, revertReason, err := ts.endorsementGatherer.GatherEndorsement(
			ctx,
			ts.transaction.PreAssembly.TransactionSpecification,
			ts.transaction.PreAssembly.Verifiers,
			ts.transaction.PostAssembly.Signatures,
			toEndorsableList(ts.transaction.PostAssembly.InputStates),
			toEndorsableList(ts.transaction.PostAssembly.ReadStates),
			toEndorsableList(ts.transaction.PostAssembly.OutputStates),
			party,
			attRequest)
		if err != nil {
			log.L(ctx).Errorf("Failed to gather endorsement for party %s: %s", party, err)
			return
			//TODO specific error message
			//TODO return nil, i18n.WrapError(ctx, err, msgs.MsgPrivateTxManagerInternalError)
		}
		ts.publisher.PublishTransactionEndorsedEvent(ctx,
			ts.transaction.ID.String(),
			endorsement,
			revertReason,
		)

	} else {
		// This is a remote party, so we need to send an endorsement request to the remote node

		err = ts.transportWriter.SendEndorsementRequest(
			ctx,
			party,
			partyNode,
			ts.transaction.Inputs.To.String(),
			ts.transaction.ID.String(),
			attRequest,
			ts.transaction.PreAssembly.TransactionSpecification,
			ts.transaction.PreAssembly.Verifiers,
			ts.transaction.PostAssembly.Signatures,
			ts.transaction.PostAssembly.InputStates,
			ts.transaction.PostAssembly.OutputStates,
		)
		if err != nil {
			log.L(ctx).Errorf("Failed to send endorsement request to party %s: %s", party, err)
			ts.latestError = i18n.ExpandWithCode(ctx, i18n.MessageKey(msgs.MsgPrivateTxManagerEndorsementRequestError), party, err.Error())
		}
	}
}

func (ts *PaladinTxProcessor) requestEndorsements(ctx context.Context) {
	if ts.requestedEndorsement {
		log.L(ctx).Infof("Transaction %s endorsement already requested", ts.transaction.ID.String())
		return
	}
	attPlan := ts.transaction.PostAssembly.AttestationPlan
	attResults := ts.transaction.PostAssembly.Endorsements
	for _, attRequest := range attPlan {
		switch attRequest.AttestationType {
		case prototk.AttestationType_SIGN:
			// no op. Signatures are gathered in the GatherSignaturesStage
		case prototk.AttestationType_ENDORSE:
			//TODO not sure this is the best way to check toBeComplete - take a closer look and think about this
			toBeComplete := true
			for _, ar := range attResults {
				if ar.GetAttestationType().Type() == attRequest.GetAttestationType().Type() {
					toBeComplete = false
					break
				}
			}
			if toBeComplete {

				for _, party := range attRequest.GetParties() {
					ts.requestEndorsement(ctx, party, attRequest)
				}

			}
		case prototk.AttestationType_GENERATE_PROOF:
			errorMessage := "AttestationType_GENERATE_PROOF is not implemented yet"
			log.L(ctx).Error(errorMessage)
			ts.latestError = i18n.ExpandWithCode(ctx, i18n.MessageKey(msgs.MsgPrivateTxManagerInternalError), errorMessage)
		default:
			errorMessage := fmt.Sprintf("Unsupported attestation type: %s", attRequest.AttestationType)
			log.L(ctx).Error(errorMessage)
			ts.latestError = i18n.ExpandWithCode(ctx, i18n.MessageKey(msgs.MsgPrivateTxManagerInternalError), errorMessage)
		}

	}
	ts.requestedEndorsement = true
}

func (ts *PaladinTxProcessor) hasOutstandingSignatureRequests() bool {
	outstandingSignatureRequests := false
out:
	for _, attRequest := range ts.transaction.PostAssembly.AttestationPlan {
		if attRequest.AttestationType == prototk.AttestationType_SIGN {
			found := false
			for _, signatures := range ts.transaction.PostAssembly.Signatures {
				if signatures.Name == attRequest.Name {
					found = true
					break
				}
			}
			if !found {
				outstandingSignatureRequests = true
				// no point checking any further, we have at least one outstanding signature request
				break out
			}
		}
	}
	return outstandingSignatureRequests
}

func (ts *PaladinTxProcessor) hasOutstandingEndorsementRequests(_ context.Context) bool {
	outstandingEndorsementRequests := false
out:
	for _, attRequest := range ts.transaction.PostAssembly.AttestationPlan {
		if attRequest.AttestationType == prototk.AttestationType_ENDORSE {
			for _, party := range attRequest.Parties {
				var verifier string
				for _, v := range ts.transaction.PreAssembly.Verifiers {
					if v.Lookup == party {
						verifier = v.Verifier
						break
					}
				}

				found := false
				for _, endorsement := range ts.transaction.PostAssembly.Endorsements {
					if endorsement.Name == attRequest.Name && endorsement.Verifier.Verifier == verifier {
						found = true
						break
					}
				}
				if !found {
					outstandingEndorsementRequests = true
					// no point checking any further, we have at least one outstanding endorsement request
					break out
				}
			}
		}
	}
	return outstandingEndorsementRequests
}

func (ts *PaladinTxProcessor) PrepareTransaction(ctx context.Context) (*components.PrivateTransaction, error) {

	prepError := ts.domainAPI.PrepareTransaction(ts.endorsementGatherer.DomainContext(), ts.transaction)
	if prepError != nil {
		log.L(ctx).Errorf("Error preparing transaction: %s", prepError)
		ts.latestError = i18n.ExpandWithCode(ctx, i18n.MessageKey(msgs.MsgPrivateTxManagerPrepareError), prepError.Error())
		return nil, prepError
	}
	return ts.transaction, nil
}

func toEndorsableList(states []*components.FullState) []*prototk.EndorsableState {
	endorsableList := make([]*prototk.EndorsableState, len(states))
	for i, input := range states {
		endorsableList[i] = &prototk.EndorsableState{
			Id:            input.ID.String(),
			SchemaId:      input.Schema.String(),
			StateDataJson: string(input.Data),
		}
	}
	return endorsableList
}

func (ts *PaladinTxProcessor) requestVerifierResolution(ctx context.Context) {

	if ts.requestedVerifierResolution {
		log.L(ctx).Infof("Transaction %s verifier resolution already requested", ts.transaction.ID.String())
		return
	}

	//TODO keep track of previous requests and send out new requests if previous ones have timed out
	if ts.transaction.PreAssembly.Verifiers == nil {
		ts.transaction.PreAssembly.Verifiers = make([]*prototk.ResolvedVerifier, 0, len(ts.transaction.PreAssembly.RequiredVerifiers))
	}
	for _, v := range ts.transaction.PreAssembly.RequiredVerifiers {
		ts.identityResolver.ResolveVerifierAsync(
			ctx,
			v.Lookup,
			v.Algorithm,
			v.VerifierType,
			func(ctx context.Context, verifier string) {
				//response event needs to be handled by the orchestrator so that the dispatch to a handling thread is done in fairness to all other in flight transactions
				ts.publisher.PublishResolveVerifierResponseEvent(ctx, ts.transaction.ID.String(), v.Lookup, v.Algorithm, verifier, v.VerifierType)
			},
			func(ctx context.Context, err error) {
				ts.publisher.PublishResolveVerifierErrorEvent(ctx, ts.transaction.ID.String(), v.Lookup, v.Algorithm, err.Error())
			},
		)
	}
	//TODO this needs to be more precise (like which verifiers have been sent / pending / stale  etc)
	ts.requestedVerifierResolution = true
}

func (ts *PaladinTxProcessor) GetStateDistributions(ctx context.Context) []*statedistribution.StateDistribution {
	log.L(ctx).Debug("PaladinTxProcessor:GetStateDistributions")

	stateDistributions := make([]*statedistribution.StateDistribution, 0)
	if ts.transaction.PostAssembly == nil {
		log.L(ctx).Error("PostAssembly is nil")
		return stateDistributions
	}
	if ts.transaction.PostAssembly.OutputStates == nil {
		log.L(ctx).Debug("OutputStates is nil")
		return stateDistributions
	}
	for stateIndex, outputState := range ts.transaction.PostAssembly.OutputStates {
		//need the output state for the state ID and need the outputStatePotential for the distribution list
		outputStatePotential := ts.transaction.PostAssembly.OutputStatesPotential[stateIndex]

		for _, party := range outputStatePotential.DistributionList {
			stateDistributions = append(stateDistributions, &statedistribution.StateDistribution{
				ID:              uuid.New().String(),
				StateID:         outputState.ID.String(),
				IdentityLocator: party,
				Domain:          ts.domainAPI.Domain().Name(),
				ContractAddress: ts.transaction.Inputs.To.String(),
				SchemaID:        outputState.Schema.String(),
				StateDataJson:   string(outputState.Data), // the state data json is available on both but we take it
				// from the outputState to make sure it is the same json that was used to generate the hash
			})
		}
	}
	return stateDistributions
}

func (ts *PaladinTxProcessor) InputStateIDs() []string {

	inputStateIDs := make([]string, len(ts.transaction.PostAssembly.InputStates))
	for i, inputState := range ts.transaction.PostAssembly.InputStates {
		inputStateIDs[i] = inputState.ID.String()
	}
	return inputStateIDs
}

func (ts *PaladinTxProcessor) OutputStateIDs() []string {

	//We use the output states here not the OutputStatesPotential because it is not possible for another transaction
	// to spend a state unless it has been written to the state store and at that point we have the state ID
	outputStateIDs := make([]string, len(ts.transaction.PostAssembly.OutputStates))
	for i, outputState := range ts.transaction.PostAssembly.OutputStates {
		outputStateIDs[i] = outputState.ID.String()
	}
	return outputStateIDs
}

func (ts *PaladinTxProcessor) Signer() string {

	return ts.transaction.Signer
}

func (ts *PaladinTxProcessor) ID() uuid.UUID {

	return ts.transaction.ID
}
