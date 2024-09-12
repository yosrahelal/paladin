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
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/kaleido-io/paladin/core/internal/components"
	"github.com/kaleido-io/paladin/core/internal/privatetxnmgr/ptmgrtypes"
	"github.com/kaleido-io/paladin/core/internal/transactionstore"
	coreProto "github.com/kaleido-io/paladin/core/pkg/proto"
	engineProto "github.com/kaleido-io/paladin/core/pkg/proto/engine"

	"github.com/kaleido-io/paladin/core/pkg/proto/sequence"
	"github.com/kaleido-io/paladin/toolkit/pkg/log"
	"github.com/kaleido-io/paladin/toolkit/pkg/prototk"
	"github.com/kaleido-io/paladin/toolkit/pkg/tktypes"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"
)

type stageContextAction int

const (
	resumeStage = iota
	initStage
	switchStage
)

type TxProcessor interface {
	GetStageContext(ctx context.Context) *ptmgrtypes.StageContext
	GetStageTriggerError(ctx context.Context) error

	// stage outputs management
	AddStageEvent(ctx context.Context, stageEvent *ptmgrtypes.StageEvent)
	Init(ctx context.Context)
	GetTxStatus(ctx context.Context) (ptmgrtypes.TxStatus, error)

	handleTransactionSubmittedEvent(ctx context.Context, event *TransactionSubmittedEvent)
	handleTransactionAssembledEvent(ctx context.Context, event *TransactionAssembledEvent)
	handleTransactionSignedEvent(ctx context.Context, event *TransactionSignedEvent)
	handleTransactionEndorsedEvent(ctx context.Context, event *TransactionEndorsedEvent)
	handleTransactionDispatchedEvent(ctx context.Context, event *TransactionDispatchedEvent)
	handleTransactionConfirmedEvent(ctx context.Context, event *TransactionConfirmedEvent)
	handleTransactionRevertedEvent(ctx context.Context, event *TransactionRevertedEvent)
	handleTransactionDelegatedEvent(ctx context.Context, event *TransactionDelegatedEvent)
}

func NewPaladinTransactionProcessor(ctx context.Context, transaction *components.PrivateTransaction, nodeID string, components components.PreInitComponentsAndManagers, domainAPI components.DomainSmartContract, sequencer ptmgrtypes.Sequencer, publisher ptmgrtypes.Publisher, endorsementGatherer ptmgrtypes.EndorsementGatherer) TxProcessor {
	return &PaladinTxProcessor{
		stageErrorRetry:     10 * time.Second,
		sequencer:           sequencer,
		domainAPI:           domainAPI,
		nodeID:              nodeID,
		components:          components,
		publisher:           publisher,
		endorsementGatherer: endorsementGatherer,
		transaction:         transaction,
		status:              "new",
	}
}

type PaladinTxProcessor struct {
	stageContextMutex sync.Mutex
	stageContext      *ptmgrtypes.StageContext
	stageTriggerError error
	stageErrorRetry   time.Duration
	tsm               transactionstore.TxStateManager

	stageController StageController

	bufferedStageEventsMapMutex sync.Mutex
	bufferedStageEvents         []*ptmgrtypes.StageEvent
	contractAddress             string // the contract address managed by the current orchestrator

	components components.PreInitComponentsAndManagers

	nodeID              string
	domainAPI           components.DomainSmartContract
	sequencer           ptmgrtypes.Sequencer
	transaction         *components.PrivateTransaction
	publisher           ptmgrtypes.Publisher
	endorsementGatherer ptmgrtypes.EndorsementGatherer
	status              string
}

func (ts *PaladinTxProcessor) Init(ctx context.Context) {
}

func (ts *PaladinTxProcessor) createStageContext(ctx context.Context, action stageContextAction) {
	ts.stageContextMutex.Lock()
	defer ts.stageContextMutex.Unlock()
	if action != switchStage && ts.stageContext != nil { // we only override existing stage context when switching stage
		// stage context already initialized, skip
		log.L(ctx).Tracef("Transaction with ID %s, on stage %s, no need for new stage context", ts.tsm.GetTxID(ctx), ts.stageContext.Stage)
		return
	}
	nowTime := time.Now() // pin the now time
	stage := ts.stageController.CalculateStage(ctx, ts.tsm)
	nextStepContext := &ptmgrtypes.StageContext{
		Stage:          stage,
		ID:             uuid.NewString(),
		StageEntryTime: nowTime,
		Ctx:            log.WithLogField(ctx, "stage", string(stage)),
	}
	if ts.stageContext != nil {
		if ts.stageContext.Stage == nextStepContext.Stage { // switching to existing stage ---> this is a retry
			// redoing the current stage
			log.L(ctx).Warnf("Transaction with ID %s retrying action, already on stage %s for %s", ts.tsm.GetTxID(ctx), stage, time.Since(ts.stageContext.StageEntryTime))
			nextStepContext.StageEntryTime = ts.stageContext.StageEntryTime
		} else {
			log.L(ctx).Tracef("Transaction with ID %s, switching from %s to %s after %s", ts.tsm.GetTxID(ctx), ts.stageContext.Stage, nextStepContext.Stage, time.Since(ts.stageContext.StageEntryTime))
		}
	} else {
		// init succeeded
		log.L(ctx).Tracef("Transaction with ID %s, initiated on stage %s", ts.tsm.GetTxID(ctx), nextStepContext.Stage)
	}
	ts.stageContext = nextStepContext
	ts.stageTriggerError = nil
	if action != resumeStage { // if we are resuming a stage when received its action event, don't perf the action again
		ts.PerformActionForStageAsync(ctx)
	} else {
		log.L(ctx).Tracef("Transaction with ID %s, resuming for %s stage", ts.tsm.GetTxID(ctx), stage)
	}
}

func (ts *PaladinTxProcessor) PerformActionForStageAsync(ctx context.Context) {
	stageContext := ts.stageContext
	if stageContext == nil {
		panic("stage context not set")
	}
	log.L(ctx).Tracef("Transaction with ID %s, triggering action for %s stage", ts.tsm.GetTxID(ctx), stageContext.Stage)
	ts.executeAsync(func() {
		synchronousActionOutput, err := ts.stageController.PerformActionForStage(ctx, string(stageContext.Stage), ts.tsm)
		ts.stageTriggerError = err
		if synchronousActionOutput != nil {
			ts.AddStageEvent(ts.stageContext.Ctx, &ptmgrtypes.StageEvent{
				ID:    stageContext.ID,
				TxID:  ts.tsm.GetTxID(ctx),
				Stage: stageContext.Stage,
				Data:  synchronousActionOutput,
			})
		}
		if err != nil {
			// if errored, clean stage context
			ts.stageContextMutex.Lock()
			ts.stageContext = nil
			ts.stageContextMutex.Unlock()
			// retry after the timeout
			time.Sleep(ts.stageErrorRetry)
			ts.createStageContext(ctx, initStage)
		}
	}, ctx)
}

func (ts *PaladinTxProcessor) addPanicOutput(ctx context.Context, sc ptmgrtypes.StageContext) {
	start := time.Now()
	// unexpected error, set an empty input for the stage
	// so that the stage handler will handle this as unexpected error
	ts.AddStageEvent(ctx, &ptmgrtypes.StageEvent{
		Stage: sc.Stage,
		ID:    sc.ID,
		TxID:  ts.tsm.GetTxID(ctx),
	})
	log.L(ctx).Debugf("%s addPanicOutput took %s to write the result", ts.tsm.GetTxID(ctx), time.Since(start))
}

func (ts *PaladinTxProcessor) executeAsync(funcToExecute func(), ctx context.Context) {
	sc := *ts.stageContext
	go func() {
		defer func() {
			if err := recover(); err != nil {
				// if the function panicked, catch it and write a panic error to the output queue
				log.L(ctx).Errorf("Panic error detected for transaction %s, when executing: %s, error: %+v", ts.tsm.GetTxID(ctx), sc.Stage, err)
				ts.addPanicOutput(ctx, sc)
			}
		}()
		funcToExecute() // in non-panic scenarios, this function will add output to the output queue
	}()
}

func (ts *PaladinTxProcessor) GetStageContext(ctx context.Context) *ptmgrtypes.StageContext {
	return ts.stageContext
}

func (ts *PaladinTxProcessor) GetStageTriggerError(ctx context.Context) error {
	return ts.stageTriggerError
}

func (ts *PaladinTxProcessor) AddStageEvent(ctx context.Context, stageEvent *ptmgrtypes.StageEvent) {
	ts.bufferedStageEventsMapMutex.Lock()
	defer ts.bufferedStageEventsMapMutex.Unlock()
	ts.bufferedStageEvents = append(ts.bufferedStageEvents, stageEvent)

	ts.createStageContext(ctx, resumeStage)

	unProcessedBufferedStageEvents, txUpdates, nextStep := ts.stageController.ProcessEventsForStage(ctx, string(ts.stageContext.Stage), ts.tsm, ts.bufferedStageEvents)

	if unProcessedBufferedStageEvents != nil {
		ts.bufferedStageEvents = unProcessedBufferedStageEvents
	}
	if txUpdates != nil {
		// persistence is synchronous, so it must NOT run on the main go routine to avoid blocking
		ts.tsm.ApplyTxUpdates(ctx, txUpdates)
	}
	if nextStep == ptmgrtypes.NextStepNewStage {
		ts.createStageContext(ctx, switchStage)
	} else if nextStep == ptmgrtypes.NextStepNewAction {
		ts.PerformActionForStageAsync(ctx)
	}
	// other wise, the stage told the processor to wait for async events
}

func (ts *PaladinTxProcessor) GetTxStatus(ctx context.Context) (ptmgrtypes.TxStatus, error) {
	return ptmgrtypes.TxStatus{
		TxID:   ts.transaction.ID.String(),
		Status: ts.status,
	}, nil
}

func (ts *PaladinTxProcessor) handleTransactionSubmittedEvent(ctx context.Context, event *TransactionSubmittedEvent) {
	//syncronously assemble the transaction then inform the local sequencer and remote nodes for any parties in the
	// privacy group that need to know about the transaction
	// this could be other parties that have potential to attempt to spend the same state(s) as this transaction is assembled to spend
	// or parties that could potentially spend the output states of this transaction
	// or parties that will be needed to endorse or notarize this transaction
	err := ts.domainAPI.AssembleTransaction(ctx, ts.transaction)
	if err != nil {
		log.L(ctx).Errorf("AssembleTransaction failed: %s", err)
		// TODO assembly failed, need to revert the transaction
	}
	ts.status = "assembled"
	// inform the sequencer that the transaction has been assembled
	err = ts.sequencer.HandleTransactionAssembledEvent(ctx, &sequence.TransactionAssembledEvent{
		TransactionId: ts.transaction.ID.String(),
		NodeId:        ts.nodeID,
		InputStateId:  stateIDs(ts.transaction.PostAssembly.InputStates),
		OutputStateId: stateIDs(ts.transaction.PostAssembly.OutputStates),
	})
	if err != nil {
		log.L(ctx).Errorf("HandleTransactionAssembledEvent failed: %s", err)
		panic("todo")
	}

	if ts.transaction.PostAssembly == nil {
		log.L(ctx).Errorf("PostAssembly is nil. Should never have reached this stage without a PostAssembly")
		//return nil, i18n.NewError(ctx, msgs.MsgEngineInternalError, "")
	}

	if ts.transaction.PostAssembly.OutputStatesPotential != nil && ts.transaction.PostAssembly.OutputStates == nil {
		//TODO - a bit of a chicken and egg situation here.
		// We need to write the potential states to the domain before we can sign or endorse the transaction
		// however, this is something that we would prefer to defer until we are confident that this transaction will be
		// added to a sequence.
		// Currently, the sequencer waits for endorsement before giving us that confidence so we are forced to write the potential states here.

		err := ts.domainAPI.WritePotentialStates(ctx, ts.transaction)
		if err != nil {
			//TODO better error message
			errorMessage := fmt.Sprintf("Failed to write potential states: %s", err)
			log.L(ctx).Error(errorMessage)
			//return nil, i18n.WrapError(ctx, err, msgs.MsgEngineInternalError, errorMessage)
		}
	}

	err = ts.sequencer.AssignTransaction(ctx, ts.transaction.ID.String())
	if err != nil {
		log.L(ctx).Errorf("Failed to assign transaction to sequencer: %s", err)
		//TODO return nil, i18n.WrapError(ctx, err, msgs.MsgEngineInternalError)
	}

	//start an async process to gather signatures
	// this will emit a TransactionSignedEvent for each signature collected
	if ts.hasOutstandingSignatureRequests(ctx) {
		ts.requestSignatures(ctx)
	} else {
		ts.requestEndorsements(ctx)
	}
}

func (ts *PaladinTxProcessor) handleTransactionAssembledEvent(ctx context.Context, event *TransactionAssembledEvent) {
	//TODO inform the sequencer about a transaction assembled by another node
}

func (ts *PaladinTxProcessor) handleTransactionSignedEvent(ctx context.Context, event *TransactionSignedEvent) {
	log.L(ctx).Debugf("Adding signature to transaction %s", ts.transaction.ID.String())
	ts.transaction.PostAssembly.Signatures = append(ts.transaction.PostAssembly.Signatures, event.attestationResult)
	if !ts.hasOutstandingSignatureRequests(ctx) {
		ts.status = "signed"
		ts.requestEndorsements(ctx)
	}
}

func (ts *PaladinTxProcessor) handleTransactionEndorsedEvent(ctx context.Context, event *TransactionEndorsedEvent) {
	if event.revertReason != nil {
		log.L(ctx).Infof("Endorsement for transaction %s was rejected: %s", ts.transaction.ID.String(), *event.revertReason)
		//TODO
	} else {
		log.L(ctx).Infof("Adding endorsement to transaction %s", ts.transaction.ID.String())
		ts.transaction.PostAssembly.Endorsements = append(ts.transaction.PostAssembly.Endorsements, event.endorsement)
		if event.endorsement.Constraints != nil {
			for _, constraint := range event.endorsement.Constraints {
				switch constraint {
				case prototk.AttestationResult_ENDORSER_MUST_SUBMIT:
					//TODO endorser must submit?
					//TODO other constraints

				default:
					log.L(ctx).Errorf("Unsupported constraint: %s", constraint)
				}
			}
		}
		if !ts.hasOutstandingEndorsementRequests(ctx) {
			ts.status = "endorsed"

			//TODO should really call out to the engine to publish this event because it needs
			// to go to other nodes too?

			//Tell the sequencer that this transaction has been endorsed and wait until it publishes a TransactionDispatched event before moving to the next stage
			err := ts.sequencer.HandleTransactionEndorsedEvent(ctx, &sequence.TransactionEndorsedEvent{
				TransactionId: ts.transaction.ID.String(),
			})
			if err != nil {
				//TODO need better error handling here.  Should we retry? Should we fail the transaction? Should we try sending the other requests?
				log.L(ctx).Errorf("Failed to publish transaction endorsed event: %s", err)
			}
		}
	}
}

func (ts *PaladinTxProcessor) handleTransactionDispatchedEvent(ctx context.Context, event *TransactionDispatchedEvent) {
	ts.status = "dispatched"
}

func (ts *PaladinTxProcessor) handleTransactionConfirmedEvent(ctx context.Context, event *TransactionConfirmedEvent) {
}
func (ts *PaladinTxProcessor) handleTransactionRevertedEvent(ctx context.Context, event *TransactionRevertedEvent) {
}
func (ts *PaladinTxProcessor) handleTransactionDelegatedEvent(ctx context.Context, event *TransactionDelegatedEvent) {
}

func (ts *PaladinTxProcessor) requestSignature(ctx context.Context, attRequest *prototk.AttestationRequest, partyName string) {
	keyHandle, verifier, err := ts.components.KeyManager().ResolveKey(ctx, partyName, attRequest.Algorithm)
	if err != nil {
		log.L(ctx).Errorf("Failed to resolve local signer for %s (algorithm=%s): %s", partyName, attRequest.Algorithm, err)

		//TODO return nil, err
	}
	// TODO this could be calling out to a remote signer, should we be doing these in parallel?
	signaturePayload, err := ts.components.KeyManager().Sign(ctx, &coreProto.SignRequest{
		KeyHandle: keyHandle,
		Algorithm: attRequest.Algorithm,
		Payload:   attRequest.Payload,
	})
	if err != nil {
		log.L(ctx).Errorf("failed to sign for party %s (verifier=%s,algorithm=%s): %s", partyName, verifier, attRequest.Algorithm, err)
		//TODO return nil, err
	}

	ts.publisher.PublishTransactionSignedEvent(ctx,
		ts.transaction.ID.String(),
		&prototk.AttestationResult{
			Name:            attRequest.Name,
			AttestationType: attRequest.AttestationType,
			Verifier: &prototk.ResolvedVerifier{
				Lookup:    partyName,
				Algorithm: attRequest.Algorithm,
				Verifier:  verifier,
			},
			Payload: signaturePayload.Payload,
		},
	)
}

func (ts *PaladinTxProcessor) requestSignatures(ctx context.Context) {

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
}
func (ts *PaladinTxProcessor) requestEndorsement(ctx context.Context, party string, attRequest *prototk.AttestationRequest) {

	partyLocator := tktypes.PrivateIdentityLocator(party)
	partyNode, err := partyLocator.Node(ctx, true)
	if err != nil {
		log.L(ctx).Errorf("Failed to get node name from locator %s: %s", party, err)
		//TODO return nil, i18n.WrapError(ctx, err, msgs.MsgEngineInternalError)
	}

	if partyNode == ts.nodeID || partyNode == "" {
		// This is a local party, so we can endorse it directly
		endorsement, revertReason, err := ts.endorsementGatherer.GatherEndorsement(ctx,
			ts.transaction.PreAssembly.TransactionSpecification,
			ts.transaction.PreAssembly.Verifiers,
			ts.transaction.PostAssembly.Signatures,
			toEndorsableList(ts.transaction.PostAssembly.InputStates),
			toEndorsableList(ts.transaction.PostAssembly.OutputStates), party, attRequest)
		if err != nil {
			log.L(ctx).Errorf("Failed to gather endorsement for party %s: %s", party, err)
			//TODO specific error message
			//TODO return nil, i18n.WrapError(ctx, err, msgs.MsgEngineInternalError)
		}
		ts.publisher.PublishTransactionEndorsedEvent(ctx,
			ts.transaction.ID.String(),
			endorsement,
			revertReason,
		)

	} else {
		// This is a remote party, so we need to send an endorsement request to the remote node

		attRequstAny, err := anypb.New(attRequest)
		if err != nil {
			log.L(ctx).Error("Error marshalling attestation request", err)
			//TODO return nil, err
		}

		transactionSpecificationAny, err := anypb.New(ts.transaction.PreAssembly.TransactionSpecification)
		if err != nil {
			log.L(ctx).Error("Error marshalling transaction specification", err)
			//TODO return nil, err
		}
		verifiers := make([]*anypb.Any, len(ts.transaction.PreAssembly.Verifiers))
		for i, verifier := range ts.transaction.PreAssembly.Verifiers {
			verifierAny, err := anypb.New(verifier)
			if err != nil {
				log.L(ctx).Error("Error marshalling verifier", err)
				//TODO return nil, err
			}
			verifiers[i] = verifierAny
		}
		signatures := make([]*anypb.Any, len(ts.transaction.PostAssembly.Signatures))
		for i, signature := range ts.transaction.PostAssembly.Signatures {
			signatureAny, err := anypb.New(signature)
			if err != nil {
				log.L(ctx).Error("Error marshalling signature", err)
				//TODO return nil, err
			}
			signatures[i] = signatureAny
		}

		inputStates := make([]*anypb.Any, len(ts.transaction.PostAssembly.InputStates))
		endorseableInputStates := toEndorsableList(ts.transaction.PostAssembly.InputStates)
		for i, inputState := range endorseableInputStates {
			inputStateAny, err := anypb.New(inputState)
			if err != nil {
				log.L(ctx).Error("Error marshalling input state", err)
				//TODO return nil, err
			}
			inputStates[i] = inputStateAny
		}

		outputStates := make([]*anypb.Any, len(ts.transaction.PostAssembly.OutputStates))
		endorseableOutputStates := toEndorsableList(ts.transaction.PostAssembly.OutputStates)
		for i, outputState := range endorseableOutputStates {
			outputStateAny, err := anypb.New(outputState)
			if err != nil {
				log.L(ctx).Error("Error marshalling output state", err)
				//TODO return nil, err
			}
			outputStates[i] = outputStateAny
		}

		endorsementRequest := &engineProto.EndorsementRequest{
			ContractAddress:          ts.transaction.Inputs.To.String(),
			TransactionId:            ts.transaction.ID.String(),
			AttestationRequest:       attRequstAny,
			Party:                    party,
			TransactionSpecification: transactionSpecificationAny,
			Verifiers:                verifiers,
			Signatures:               signatures,
			InputStates:              inputStates,
			OutputStates:             outputStates,
		}

		endorsementRequestBytes, err := proto.Marshal(endorsementRequest)
		if err != nil {
			log.L(ctx).Error("Error marshalling endorsement request", err)
			//TODO return nil, err
		}
		err = ts.components.TransportManager().Send(ctx, &components.TransportMessage{
			MessageType: "EndorsementRequest",
			Destination: tktypes.PrivateIdentityLocator(party),
			Payload:     endorsementRequestBytes,
		})
		if err != nil {
			//TODO need better error handling here.  Should we retry? Should we fail the transaction? Should we try sending the other requests?
			log.L(ctx).Errorf("Failed to send endorsement request to party %s: %s", party, err)
			//TODO return nil, i18n.WrapError(ctx, err, msgs.MsgEngineInternalError)
		}
	}
}

func (ts *PaladinTxProcessor) requestEndorsements(ctx context.Context) {
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
					go ts.requestEndorsement(ctx, party, attRequest)
				}

			}
		case prototk.AttestationType_GENERATE_PROOF:
			errorMessage := "AttestationType_GENERATE_PROOF is not implemented yet"
			log.L(ctx).Error(errorMessage)
			//TODO return nil, i18n.NewError(ctx, msgs.MsgEngineInternalError, errorMessage)
		default:
			errorMessage := fmt.Sprintf("Unsupported attestation type: %s", attRequest.AttestationType)
			log.L(ctx).Error(errorMessage)
			//TODO return nil, i18n.NewError(ctx, msgs.MsgEngineInternalError, errorMessage)
		}

	}
}

func (ts *PaladinTxProcessor) hasOutstandingSignatureRequests(ctx context.Context) bool {
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

func (ts *PaladinTxProcessor) hasOutstandingEndorsementRequests(ctx context.Context) bool {
	outstandingEndorsementRequests := false
out:
	for _, attRequest := range ts.transaction.PostAssembly.AttestationPlan {
		if attRequest.AttestationType == prototk.AttestationType_ENDORSE {
			found := false
			for _, endorsement := range ts.transaction.PostAssembly.Endorsements {
				if endorsement.Name == attRequest.Name {
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
	return outstandingEndorsementRequests
}
