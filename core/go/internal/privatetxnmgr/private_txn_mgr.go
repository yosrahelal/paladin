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
	"encoding/json"
	"fmt"
	"sync"

	"github.com/hyperledger/firefly-common/pkg/i18n"
	"github.com/kaleido-io/paladin/core/internal/components"
	"github.com/kaleido-io/paladin/core/internal/privatetxnmgr/ptmgrtypes"
	"github.com/kaleido-io/paladin/core/internal/privatetxnmgr/syncpoints"
	"github.com/kaleido-io/paladin/core/internal/statedistribution"
	"gorm.io/gorm"

	"github.com/kaleido-io/paladin/core/internal/msgs"

	pbEngine "github.com/kaleido-io/paladin/core/pkg/proto/engine"

	"github.com/kaleido-io/paladin/config/pkg/confutil"
	"github.com/kaleido-io/paladin/config/pkg/pldconf"
	"github.com/kaleido-io/paladin/toolkit/pkg/pldapi"
	"github.com/kaleido-io/paladin/toolkit/pkg/tktypes"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"

	"github.com/kaleido-io/paladin/toolkit/pkg/log"
	"github.com/kaleido-io/paladin/toolkit/pkg/prototk"
)

type privateTxManager struct {
	ctx                  context.Context
	ctxCancel            func()
	config               *pldconf.PrivateTxManagerConfig
	sequencers           map[string]*Sequencer
	sequencersLock       sync.RWMutex
	endorsementGatherers map[string]ptmgrtypes.EndorsementGatherer
	components           components.AllComponents
	nodeName             string
	subscribers          []components.PrivateTxEventSubscriber
	subscribersLock      sync.Mutex
	syncPoints           syncpoints.SyncPoints
	stateDistributer     statedistribution.StateDistributer
}

// Init implements Engine.
func (p *privateTxManager) PreInit(c components.PreInitComponents) (*components.ManagerInitResult, error) {
	return &components.ManagerInitResult{}, nil
}

func (p *privateTxManager) PostInit(c components.AllComponents) error {
	p.components = c
	p.nodeName = p.components.TransportManager().LocalNodeName()
	p.syncPoints = syncpoints.NewSyncPoints(p.ctx, &p.config.Writer, c.Persistence(), c.TxManager())
	p.stateDistributer = statedistribution.NewStateDistributer(
		p.ctx,
		p.nodeName,
		p.components.TransportManager(),
		p.components.StateManager(),
		p.components.Persistence(),
		&p.config.StateDistributer)
	err := p.stateDistributer.Start(p.ctx)
	if err != nil {
		return err
	}
	return p.components.TransportManager().RegisterClient(p.ctx, p)
}

func (p *privateTxManager) Start() error {
	p.syncPoints.Start()
	return nil
}

func (p *privateTxManager) Stop() {
	p.stateDistributer.Stop(p.ctx)

}

func NewPrivateTransactionMgr(ctx context.Context, config *pldconf.PrivateTxManagerConfig) components.PrivateTxManager {
	p := &privateTxManager{
		config:               config,
		sequencers:           make(map[string]*Sequencer),
		endorsementGatherers: make(map[string]ptmgrtypes.EndorsementGatherer),
		subscribers:          make([]components.PrivateTxEventSubscriber, 0),
	}
	p.ctx, p.ctxCancel = context.WithCancel(ctx)
	return p
}

func (p *privateTxManager) getSequencerForContract(ctx context.Context, contractAddr tktypes.EthAddress, domainAPI components.DomainSmartContract) (oc *Sequencer, err error) {

	readlock := true
	p.sequencersLock.RLock()
	defer func() {
		if readlock {
			p.sequencersLock.RUnlock()
		}
	}()
	if p.sequencers[contractAddr.String()] == nil {
		//swap the read lock for a write lock
		p.sequencersLock.RUnlock()
		readlock = false
		p.sequencersLock.Lock()
		defer p.sequencersLock.Unlock()
		//double check in case another goroutine has created the sequencer while we were waiting for the write lock
		if p.sequencers[contractAddr.String()] == nil {
			transportWriter := NewTransportWriter(domainAPI.Domain().Name(), &contractAddr, p.nodeName, p.components.TransportManager())
			publisher := NewPublisher(p, contractAddr.String())

			endorsementGatherer, err := p.getEndorsementGathererForContract(ctx, contractAddr)
			if err != nil {
				log.L(ctx).Errorf("Failed to get endorsement gatherer for contract %s: %s", contractAddr.String(), err)
				return nil, err
			}

			p.sequencers[contractAddr.String()] =
				NewSequencer(
					p.ctx, p.nodeName,
					contractAddr,
					&p.config.Sequencer,
					p.components,
					domainAPI,
					endorsementGatherer,
					publisher,
					p.syncPoints,
					p.components.IdentityResolver(),
					p.stateDistributer,
					transportWriter,
					confutil.DurationMin(p.config.RequestTimeout, 0, *pldconf.PrivateTxManagerDefaults.RequestTimeout),
				)
			sequencerDone, err := p.sequencers[contractAddr.String()].Start(ctx)
			if err != nil {
				log.L(ctx).Errorf("Failed to start sequencer for contract %s: %s", contractAddr.String(), err)
				return nil, err
			}

			go func() {

				<-sequencerDone
				log.L(ctx).Infof("Sequencer for contract %s has stopped", contractAddr.String())
				p.sequencersLock.Lock()
				defer p.sequencersLock.Unlock()
				delete(p.sequencers, contractAddr.String())
			}()
		}
	}
	return p.sequencers[contractAddr.String()], nil
}

func (p *privateTxManager) getEndorsementGathererForContract(ctx context.Context, contractAddr tktypes.EthAddress) (ptmgrtypes.EndorsementGatherer, error) {

	domainSmartContract, err := p.components.DomainManager().GetSmartContractByAddress(ctx, contractAddr)
	if err != nil {
		return nil, err
	}
	if p.endorsementGatherers[contractAddr.String()] == nil {
		// TODO: Consider scope of state in privateTxManager threading model
		dCtx := p.components.StateManager().NewDomainContext(p.ctx /* background context */, domainSmartContract.Domain(), contractAddr)
		endorsementGatherer := NewEndorsementGatherer(p.components.Persistence(), domainSmartContract, dCtx, p.components.KeyManager())
		p.endorsementGatherers[contractAddr.String()] = endorsementGatherer
	}
	return p.endorsementGatherers[contractAddr.String()], nil
}

// HandleNewTx synchronously receives a new transaction submission
// TODO this should really be a 2 (or 3?) phase handshake with
//   - Pre submit phase to validate the inputs
//   - Submit phase to persist the record of the submission as part of a database transaction that is coordinated by the caller
//   - Post submit phase to clean up any locks / resources that were held during the submission after the database transaction has been committed ( given that we cannot be sure on completeion of phase 2 that the transaction will be committed)
//
// We are currently proving out this pattern on the boundary of the private transaction manager and the public transaction manager and once that has settled, we will implement the same pattern here.
// In the meantime, we a single function to submit a transaction and there is currently no persistence of the submission record.  It is all held in memory only
func (p *privateTxManager) HandleNewTx(ctx context.Context, tx *components.PrivateTransaction) error {
	log.L(ctx).Debugf("Handling new transaction: %v", tx)
	if tx.Inputs == nil || tx.Inputs.Domain == "" {
		return i18n.NewError(ctx, msgs.MsgDomainNotProvided)
	}

	emptyAddress := tktypes.EthAddress{}
	if tx.Inputs.To == emptyAddress {
		return i18n.NewError(ctx, msgs.MsgContractAddressNotProvided)
	}

	contractAddr := tx.Inputs.To
	domainAPI, err := p.components.DomainManager().GetSmartContractByAddress(ctx, contractAddr)
	if err != nil {
		return err
	}
	err = domainAPI.InitTransaction(ctx, tx)
	if err != nil {
		return err
	}

	if tx.PreAssembly == nil {
		return i18n.NewError(ctx, msgs.MsgPrivateTxManagerInternalError, "PreAssembly is nil")
	}

	oc, err := p.getSequencerForContract(ctx, contractAddr, domainAPI)
	if err != nil {
		return err
	}
	queued := oc.ProcessNewTransaction(ctx, tx)
	if queued {
		log.L(ctx).Debugf("Transaction with ID %s queued in database", tx.ID)
	}
	return nil
}

func (p *privateTxManager) validateDelegatedTransaction(ctx context.Context, tx *components.PrivateTransaction) error {
	log.L(ctx).Debugf("Validating delegated transaction: %v", tx)
	if tx.Inputs == nil || tx.Inputs.Domain == "" {
		return i18n.NewError(ctx, msgs.MsgDomainNotProvided)
	}

	emptyAddress := tktypes.EthAddress{}
	if tx.Inputs.To == emptyAddress {
		return i18n.NewError(ctx, msgs.MsgContractAddressNotProvided)
	}

	if tx.PreAssembly == nil {
		return i18n.NewError(ctx, msgs.MsgPrivateTxManagerInternalError, "PreAssembly is nil")
	}
	return nil

}

func (p *privateTxManager) handleDelegatedTransaction(ctx context.Context, tx *components.PrivateTransaction) error {
	log.L(ctx).Debugf("Handling delegated transaction: %v", tx)

	contractAddr := tx.Inputs.To
	domainAPI, err := p.components.DomainManager().GetSmartContractByAddress(ctx, contractAddr)
	if err != nil {
		return err
	}
	oc, err := p.getSequencerForContract(ctx, contractAddr, domainAPI)
	if err != nil {
		return err
	}
	queued := oc.ProcessInFlightTransaction(ctx, tx)
	if queued {
		log.L(ctx).Debugf("Delegated Transaction with ID %s queued in database", tx.ID)
	}
	return nil
}

// Synchronous function to submit a deployment request which is asynchronously processed
// Private transaction manager will receive a notification when the public transaction is confirmed
// (same as for invokes)
func (p *privateTxManager) HandleDeployTx(ctx context.Context, tx *components.PrivateContractDeploy) error {
	log.L(ctx).Debugf("Handling new private contract deploy transaction: %v", tx)
	if tx.Domain == "" {
		return i18n.NewError(ctx, msgs.MsgDomainNotProvided)
	}

	domain, err := p.components.DomainManager().GetDomainByName(ctx, tx.Domain)
	if err != nil {
		return i18n.WrapError(ctx, err, msgs.MsgDomainNotFound, tx.Domain)
	}

	err = domain.InitDeploy(ctx, tx)
	if err != nil {
		return i18n.WrapError(ctx, err, msgs.MsgDeployInitFailed)
	}

	// NOTE unlike private transactions, we assume that all verifiers are resolved locally

	//Resolve keys synchronously so that we can return an error if any key resolution fails
	tx.Verifiers = make([]*prototk.ResolvedVerifier, len(tx.RequiredVerifiers))
	for i, v := range tx.RequiredVerifiers {
		// TODO: This is a synchronous cross-node exchange, done sequentially for each verifier.
		// Potentially needs to move to an event-driven model like on invocation.
		verifier, err := p.components.IdentityResolver().ResolveVerifier(ctx, v.Lookup, v.Algorithm, v.VerifierType)
		if err != nil {
			return i18n.WrapError(ctx, err, msgs.MsgKeyResolutionFailed, v.Lookup, v.Algorithm, v.VerifierType)
		}
		tx.Verifiers[i] = &prototk.ResolvedVerifier{
			Lookup:       v.Lookup,
			Algorithm:    v.Algorithm,
			Verifier:     verifier,
			VerifierType: v.VerifierType,
		}
	}

	// this is a transaction that will confirm just like invoke transactions
	// unlike invoke transactions, we don't yet have the sequencer thread to dispatch to so we start a new go routine for each deployment
	// TODO - should have a pool of deployment threads? Maybe size of pool should be one? Or at least one per domain?
	go p.deploymentLoop(log.WithLogField(p.ctx, "role", "deploy-loop"), domain, tx)

	return nil
}
func (p *privateTxManager) deploymentLoop(ctx context.Context, domain components.Domain, tx *components.PrivateContractDeploy) {
	log.L(ctx).Info("Starting deployment loop")
	err := p.evaluateDeployment(ctx, domain, tx)
	if err != nil {
		log.L(ctx).Errorf("Error evaluating deployment: %s", err)
		return
	}
	log.L(ctx).Info("Deployment completed successfully. ")
}

func (p *privateTxManager) revertDeploy(ctx context.Context, tx *components.PrivateContractDeploy, err error) error {
	deployError := i18n.WrapError(ctx, err, msgs.MsgPrivateTxManagerDeployError)

	var tryFinalize func()
	tryFinalize = func() {
		p.syncPoints.QueueTransactionFinalize(ctx, tktypes.EthAddress{}, tx.ID, deployError.Error(),
			func(ctx context.Context) {
				log.L(ctx).Debugf("Finalized deployment transaction: %s", tx.ID)
			},
			func(ctx context.Context, err error) {
				log.L(ctx).Errorf("Error finalizing deployment: %s", err)
				tryFinalize()
			})
	}
	tryFinalize()
	return deployError

}

func (p *privateTxManager) evaluateDeployment(ctx context.Context, domain components.Domain, tx *components.PrivateContractDeploy) error {

	// TODO there is a lot of common code between this and the Dispatch function in the sequencer. should really move some of it into a common place
	// and use that as an opportunity to refactor to be more readable

	err := domain.PrepareDeploy(ctx, tx)
	if err != nil {
		return p.revertDeploy(ctx, tx, err)
	}

	publicTransactionEngine := p.components.PublicTxManager()

	// The signer needs to be in our local node or it's an error
	identifier, node, err := tktypes.PrivateIdentityLocator(tx.Signer).Validate(ctx, p.nodeName, true)
	if err != nil {
		return err
	}
	if node != p.nodeName {
		return i18n.NewError(ctx, msgs.MsgPrivateTxManagerNonLocalSigningAddr, tx.Signer)
	}

	keyMgr := p.components.KeyManager()
	resolvedAddrs, err := keyMgr.ResolveEthAddressBatchNewDatabaseTX(ctx, []string{identifier})
	if err != nil {
		return p.revertDeploy(ctx, tx, err)
	}

	publicTXs := []*components.PublicTxSubmission{
		{
			Bindings: []*components.PaladinTXReference{{TransactionID: tx.ID, TransactionType: pldapi.TransactionTypePrivate.Enum()}},
			PublicTxInput: pldapi.PublicTxInput{
				From:            resolvedAddrs[0],
				PublicTxOptions: pldapi.PublicTxOptions{}, // TODO: Consider propagation from paladin transaction input
			},
		},
	}

	if tx.InvokeTransaction != nil {
		log.L(ctx).Debug("Deploying by invoking a base ledger contract")

		data, err := tx.InvokeTransaction.FunctionABI.EncodeCallDataCtx(ctx, tx.InvokeTransaction.Inputs)
		if err != nil {
			return p.revertDeploy(ctx, tx, i18n.WrapError(ctx, err, msgs.MsgPrivateTxMgrEncodeCallDataFailed))
		}
		publicTXs[0].Data = tktypes.HexBytes(data)
		publicTXs[0].To = &tx.InvokeTransaction.To

	} else if tx.DeployTransaction != nil {
		//TODO
		return p.revertDeploy(ctx, tx, i18n.NewError(ctx, msgs.MsgPrivateTxManagerInternalError, "DeployTransaction not implemented"))
	} else {
		return p.revertDeploy(ctx, tx, i18n.NewError(ctx, msgs.MsgPrivateTxManagerInternalError, "Neither InvokeTransaction nor DeployTransaction set"))
	}

	pubBatch, err := publicTransactionEngine.PrepareSubmissionBatch(ctx, publicTXs)
	if err != nil {
		return p.revertDeploy(ctx, tx, i18n.WrapError(ctx, err, msgs.MsgPrivateTxManagerInternalError, "PrepareSubmissionBatch failed"))
	}

	// Must make sure from this point we return the nonces
	completed := false // and include whether we committed the DB transaction or not
	defer func() {
		pubBatch.Completed(ctx, completed)
	}()
	if len(pubBatch.Rejected()) > 0 {
		// We do not handle partial success - roll everything back
		return p.revertDeploy(ctx, tx, i18n.WrapError(ctx, pubBatch.Rejected()[0].RejectedError(), msgs.MsgPrivateTxManagerInternalError, "Submission batch rejected "))
	}

	//transactions are always dispatched as a sequence, even if only a sequence of one
	sequence := &syncpoints.DispatchSequence{
		PrivateTransactionDispatches: []*syncpoints.DispatchPersisted{
			{
				PrivateTransactionID: tx.ID.String(),
			},
		},
	}
	sequence.PublicTxBatch = pubBatch
	dispatchBatch := &syncpoints.DispatchBatch{
		DispatchSequences: []*syncpoints.DispatchSequence{
			sequence,
		},
	}

	// as this is a deploy we specify the null address
	err = p.syncPoints.PersistDeployDispatchBatch(ctx, dispatchBatch)
	if err != nil {
		log.L(ctx).Errorf("Error persisting batch: %s", err)
		return p.revertDeploy(ctx, tx, err)
	}

	completed = true

	p.publishToSubscribers(ctx, &components.TransactionDispatchedEvent{
		TransactionID:  tx.ID.String(),
		Nonce:          uint64(0), /*TODO*/
		SigningAddress: tx.Signer,
	})

	return nil

}

func (p *privateTxManager) GetTxStatus(ctx context.Context, domainAddress string, txID string) (status components.PrivateTxStatus, err error) {
	// this returns status that we happen to have in memory at the moment and might be useful for debugging

	p.sequencersLock.RLock()
	defer p.sequencersLock.RUnlock()
	targetSequencer := p.sequencers[domainAddress]
	if targetSequencer == nil {
		//TODO should be valid to query the status of a transaction that belongs to a domain instance that is not currently active
		errorMessage := fmt.Sprintf("Sequencer not found for domain address %s", domainAddress)
		return components.PrivateTxStatus{}, i18n.NewError(ctx, msgs.MsgPrivateTxManagerInternalError, errorMessage)
	} else {
		return targetSequencer.GetTxStatus(ctx, txID)
	}

}

func (p *privateTxManager) HandleNewEvent(ctx context.Context, event ptmgrtypes.PrivateTransactionEvent) {
	p.sequencersLock.RLock()
	defer p.sequencersLock.RUnlock()
	targetSequencer := p.sequencers[event.GetContractAddress()]
	if targetSequencer == nil { // this is an event that belongs to a contract that's not in flight, throw it away and rely on the engine to trigger the action again when the sequencer is wake up. (an enhanced version is to add weight on queueing an sequencer)
		log.L(ctx).Warnf("Ignored %T event for domain contract %s and transaction %s . If this happens a lot, check the sequencer idle timeout is set to a reasonable number", event, event.GetContractAddress(), event.GetTransactionID())
	} else {
		targetSequencer.HandleEvent(ctx, event)
	}
}

func (p *privateTxManager) handleEndorsementRequest(ctx context.Context, messagePayload []byte, replyTo string) {
	endorsementRequest := &pbEngine.EndorsementRequest{}
	err := proto.Unmarshal(messagePayload, endorsementRequest)
	if err != nil {
		log.L(ctx).Errorf("Failed to unmarshal endorsement request: %s", err)
		return
	}
	contractAddressString := endorsementRequest.ContractAddress
	contractAddress, err := tktypes.ParseEthAddress(contractAddressString)
	if err != nil {
		log.L(ctx).Errorf("Failed to parse contract address %s: %s", contractAddressString, err)
		return
	}

	endorsementGatherer, err := p.getEndorsementGathererForContract(ctx, *contractAddress)
	if err != nil {
		log.L(ctx).Errorf("Failed to get endorsement gatherer for contract address %s: %s", contractAddressString, err)
		return
	}

	//TODO the following is temporary code to unmarshal the fields of the endorsement request
	// what we really should be doing is importing the tkproto messages but need to figure out the build
	// magic to make that work

	transactionSpecificationAny := endorsementRequest.GetTransactionSpecification()
	transactionSpecification := &prototk.TransactionSpecification{}
	err = transactionSpecificationAny.UnmarshalTo(transactionSpecification)
	if err != nil {
		log.L(ctx).Errorf("Failed to unmarshal transaction specification: %s", err)
		return
	}

	attestationRequestAny := endorsementRequest.GetAttestationRequest()
	attestationRequest := &prototk.AttestationRequest{}
	err = attestationRequestAny.UnmarshalTo(attestationRequest)
	if err != nil {
		log.L(ctx).Errorf("Failed to unmarshal attestation request: %s", err)
		return
	}

	verifiersAny := endorsementRequest.GetVerifiers()
	verifiers := make([]*prototk.ResolvedVerifier, len(verifiersAny))
	for i, v := range verifiersAny {
		verifiers[i] = &prototk.ResolvedVerifier{}
		err = v.UnmarshalTo(verifiers[i])
		if err != nil {
			log.L(ctx).Errorf("Failed to unmarshal attestation request: %s", err)
			return
		}
	}

	signatures := make([]*prototk.AttestationResult, len(endorsementRequest.GetSignatures()))
	for i, s := range endorsementRequest.GetSignatures() {
		signatures[i] = &prototk.AttestationResult{}
		err = s.UnmarshalTo(signatures[i])
		if err != nil {
			log.L(ctx).Errorf("Failed to unmarshal attestation request: %s", err)
			return
		}
	}

	inputStates := make([]*prototk.EndorsableState, len(endorsementRequest.GetInputStates()))
	for i, s := range endorsementRequest.GetInputStates() {
		inputStates[i] = &prototk.EndorsableState{}
		err = s.UnmarshalTo(inputStates[i])
		if err != nil {
			log.L(ctx).Errorf("Failed to unmarshal attestation request: %s", err)
			return
		}
	}

	readStates := make([]*prototk.EndorsableState, len(endorsementRequest.GetReadStates()))
	for i, s := range endorsementRequest.GetReadStates() {
		readStates[i] = &prototk.EndorsableState{}
		err = s.UnmarshalTo(readStates[i])
		if err != nil {
			log.L(ctx).Errorf("Failed to unmarshal attestation request: %s", err)
			return
		}
	}

	outputStates := make([]*prototk.EndorsableState, len(endorsementRequest.GetOutputStates()))
	for i, s := range endorsementRequest.GetOutputStates() {
		outputStates[i] = &prototk.EndorsableState{}
		err = s.UnmarshalTo(outputStates[i])
		if err != nil {
			log.L(ctx).Errorf("Failed to unmarshal attestation request: %s", err)
			return
		}
	}

	endorsement, revertReason, err := endorsementGatherer.GatherEndorsement(ctx,
		transactionSpecification,
		verifiers,
		signatures,
		inputStates,
		readStates,
		outputStates,
		endorsementRequest.GetParty(),
		attestationRequest)
	if err != nil {
		log.L(ctx).Errorf("Failed to gather endorsement: %s", err)
		return
	}

	endorsementAny, err := anypb.New(endorsement)
	if err != nil {
		log.L(ctx).Errorf("Failed marshal endorsement: %s", err)
		return
	}

	endorsementResponse := &pbEngine.EndorsementResponse{
		ContractAddress: contractAddressString,
		TransactionId:   endorsementRequest.TransactionId,
		Endorsement:     endorsementAny,
		RevertReason:    revertReason,
	}
	endorsementResponseBytes, err := proto.Marshal(endorsementResponse)
	if err != nil {
		log.L(ctx).Errorf("Failed to marshal endorsement response: %s", err)
		return
	}

	err = p.components.TransportManager().Send(ctx, &components.TransportMessage{
		MessageType: "EndorsementResponse",
		ReplyTo:     p.nodeName,
		Payload:     endorsementResponseBytes,
		Node:        replyTo,
		Component:   PRIVATE_TX_MANAGER_DESTINATION,
	})
	if err != nil {
		log.L(ctx).Errorf("Failed to send endorsement response: %s", err)
		return
	}
}

func (p *privateTxManager) handleDelegationRequest(ctx context.Context, messagePayload []byte) {
	delegationRequest := &pbEngine.DelegationRequest{}
	err := proto.Unmarshal(messagePayload, delegationRequest)
	if err != nil {
		log.L(ctx).Errorf("Failed to unmarshal delegation request: %s", err)
		return
	}

	transaction := new(components.PrivateTransaction)
	err = json.Unmarshal(delegationRequest.PrivateTransaction, &transaction)

	//before persisting the transaction, we validate it and send a rejection message if it is invalid
	if err == nil {
		err = p.validateDelegatedTransaction(ctx, transaction)
	}
	if err != nil {
		log.L(ctx).Errorf("Failed to validate delegated transaction: %s", err)
		//TODO send a negative acknowledgement
		return
	}

	//TODO persist the delegated transaction and only continue once it has been persisted

	err = p.handleDelegatedTransaction(ctx, transaction)
	if err != nil {
		log.L(ctx).Errorf("Failed to handle delegated transaction: %s", err)
		// do not send an ack and let the sender retry
		return
	}

	//TODO send an ack
}

func (p *privateTxManager) handleEndorsementResponse(ctx context.Context, messagePayload []byte) {

	endorsementResponse := &pbEngine.EndorsementResponse{}
	err := proto.Unmarshal(messagePayload, endorsementResponse)
	if err != nil {
		log.L(ctx).Errorf("Failed to unmarshal endorsementResponse: %s", err)
		return
	}
	contractAddressString := endorsementResponse.ContractAddress

	var revertReason *string
	if endorsementResponse.GetRevertReason() != "" {
		revertReason = confutil.P(endorsementResponse.GetRevertReason())
	}
	endorsement := &prototk.AttestationResult{}
	err = endorsementResponse.GetEndorsement().UnmarshalTo(endorsement)
	if err != nil {
		// TODO this is only temporary until we stop using anypb in EndorsementResponse
		log.L(ctx).Errorf("Wrong type received in EndorsementResponse")
		return
	}

	p.HandleNewEvent(ctx, &ptmgrtypes.TransactionEndorsedEvent{
		PrivateTransactionEventBase: ptmgrtypes.PrivateTransactionEventBase{
			TransactionID:   endorsementResponse.TransactionId,
			ContractAddress: contractAddressString,
		},
		RevertReason: revertReason,
		Endorsement:  endorsement,
	})

}

// For now, this is here to help with testing but it seems like it could be useful thing to have
// in the future if we want to have an eventing interface but at such time we would need to put more effort
// into the reliability of the event delivery or maybe there is only a consumer of the event and it is responsible
// for managing multiple subscribers and durability etc...
func (p *privateTxManager) Subscribe(ctx context.Context, subscriber components.PrivateTxEventSubscriber) {
	p.subscribersLock.Lock()
	defer p.subscribersLock.Unlock()
	//TODO implement this
	p.subscribers = append(p.subscribers, subscriber)
}

func (p *privateTxManager) publishToSubscribers(ctx context.Context, event components.PrivateTxEvent) {
	log.L(ctx).Debugf("Publishing event to subscribers")
	p.subscribersLock.Lock()
	defer p.subscribersLock.Unlock()
	for _, subscriber := range p.subscribers {
		subscriber(event)
	}
}

func (p *privateTxManager) NotifyFailedPublicTx(ctx context.Context, dbTX *gorm.DB, failures []*components.PublicTxMatch) error {
	// TODO: We have processing we need to do here to resubmit
	// For now, we directly raise a failure receipt for them back with the main transaction manager
	privateFailureReceipts := make([]*components.ReceiptInput, len(failures))
	for i, tx := range failures {
		privateFailureReceipts[i] = &components.ReceiptInput{
			ReceiptType:   components.RT_FailedOnChainWithRevertData,
			TransactionID: tx.TransactionID,
			OnChain: tktypes.OnChainLocation{
				Type:             tktypes.OnChainTransaction,
				TransactionHash:  tx.Hash,
				BlockNumber:      tx.BlockNumber,
				TransactionIndex: tx.BlockNumber,
			},
			RevertData: tx.RevertReason,
		}
	}
	return p.components.TxManager().FinalizeTransactions(ctx, dbTX, privateFailureReceipts)
}

// We get called post-commit by the indexer in the domain when transaction confirmations have been recorded,
// at which point it is important for us to remove transactions from our Domain Context in-memory buffer.
// This might also unblock significant extra processing for more transactions.
func (p *privateTxManager) PrivateTransactionConfirmed(ctx context.Context, receipt *components.TxCompletion) {
	log.L(ctx).Infof("private TX manager notified of transaction confirmation %s deploy=%t",
		receipt.TransactionID, receipt.PSC == nil)
	if receipt.PSC != nil {
		seq, err := p.getSequencerForContract(ctx, receipt.PSC.Address(), receipt.PSC)
		if err != nil {
			log.L(ctx).Errorf("failed to obtain sequence to process receipts on contract %s: %s", receipt.PSC.Address(), err)
			return
		}
		seq.publisher.PublishTransactionConfirmedEvent(ctx, receipt.TransactionID.String())
	}
}
