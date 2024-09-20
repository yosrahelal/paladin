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

	"github.com/hyperledger/firefly-common/pkg/i18n"
	"github.com/hyperledger/firefly-signer/pkg/ethtypes"
	"github.com/kaleido-io/paladin/core/internal/components"
	"github.com/kaleido-io/paladin/core/internal/privatetxnmgr/ptmgrtypes"

	"github.com/kaleido-io/paladin/core/internal/msgs"
	"github.com/kaleido-io/paladin/core/pkg/ethclient"
	pbEngine "github.com/kaleido-io/paladin/core/pkg/proto/engine"

	"github.com/kaleido-io/paladin/toolkit/pkg/confutil"
	"github.com/kaleido-io/paladin/toolkit/pkg/tktypes"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"

	"github.com/kaleido-io/paladin/toolkit/pkg/log"
	"github.com/kaleido-io/paladin/toolkit/pkg/prototk"
)

type privateTxManager struct {
	ctx                  context.Context
	ctxCancel            func()
	orchestrators        map[string]*Orchestrator
	endorsementGatherers map[string]ptmgrtypes.EndorsementGatherer
	components           components.AllComponents
	nodeID               string
	subscribers          []components.PrivateTxEventSubscriber
	subscribersLock      sync.Mutex
}

// Init implements Engine.
func (p *privateTxManager) PreInit(c components.PreInitComponents) (*components.ManagerInitResult, error) {
	return &components.ManagerInitResult{}, nil
}

func (p *privateTxManager) PostInit(c components.AllComponents) error {
	p.components = c
	return nil
}

func (p *privateTxManager) Start() error {
	p.ctx, p.ctxCancel = context.WithCancel(context.Background())
	return nil
}

func (p *privateTxManager) Stop() {
}

func NewPrivateTransactionMgr(ctx context.Context, nodeID string, config *Config) components.PrivateTxManager {
	return &privateTxManager{
		orchestrators:        make(map[string]*Orchestrator),
		endorsementGatherers: make(map[string]ptmgrtypes.EndorsementGatherer),
		nodeID:               nodeID,
		subscribers:          make([]components.PrivateTxEventSubscriber, 0),
	}
}

func (p *privateTxManager) getOrchestratorForContract(ctx context.Context, contractAddr tktypes.EthAddress, domainAPI components.DomainSmartContract) (oc *Orchestrator, err error) {

	if p.orchestrators[contractAddr.String()] == nil {
		publisher := NewPublisher(p, contractAddr.String())
		seq := NewSequencer(
			p.nodeID,
			publisher,
			NewTransportWriter(p.nodeID, p.components.TransportManager()),
		)
		endorsementGatherer, err := p.getEndorsementGathererForContract(ctx, contractAddr)
		if err != nil {
			log.L(ctx).Errorf("Failed to get endorsement gatherer for contract %s: %s", contractAddr.String(), err)
			return nil, err
		}

		p.orchestrators[contractAddr.String()] =
			NewOrchestrator(
				ctx, p.nodeID,
				contractAddr.String(), /** TODO: fill in the real plug-ins*/
				&OrchestratorConfig{},
				p.components,
				domainAPI,
				seq,
				endorsementGatherer,
				publisher,
			)
		orchestratorDone, err := p.orchestrators[contractAddr.String()].Start(ctx)
		if err != nil {
			log.L(ctx).Errorf("Failed to start orchestrator for contract %s: %s", contractAddr.String(), err)
			return nil, err
		}

		go func() {
			<-orchestratorDone
			log.L(ctx).Infof("Orchestrator for contract %s has stopped", contractAddr.String())
		}()
	}
	return p.orchestrators[contractAddr.String()], nil
}

func (p *privateTxManager) getEndorsementGathererForContract(ctx context.Context, contractAddr tktypes.EthAddress) (ptmgrtypes.EndorsementGatherer, error) {

	domainAPI, err := p.components.DomainManager().GetSmartContractByAddress(ctx, contractAddr)
	if err != nil {
		return nil, err
	}
	if p.endorsementGatherers[contractAddr.String()] == nil {
		endorsementGatherer := NewEndorsementGatherer(domainAPI, p.components.KeyManager())
		p.endorsementGatherers[contractAddr.String()] = endorsementGatherer
	}
	return p.endorsementGatherers[contractAddr.String()], nil
}

// HandleNewTx synchronously receives a new transaction submission
// TODO this should really be a 2 (or 3?) phase handshake with
//   - Pre submit phase to validate the inputs
//   - Submit phase to persist the record of the submissino as part of a database transaction that is co-ordinated by the caller
//   - Post submit phase to clean up any locks / resources that were held during the submission after the database transaction has been committed ( given that we cannot be sure on completeion of phase 2 that the transaction will be committed)
//
// We are currently proving out this pattern on the boundary of the private transaction manager and the public transaction manager and once that has settled, we will implement the same pattern here.
// In the meantime, we a single function to submit a transaction and there is currently no persistence of the submission record.  It is all held in memory only
func (p *privateTxManager) HandleNewTx(ctx context.Context, tx *components.PrivateTransaction) (txID string, err error) {
	log.L(ctx).Debugf("Handling new transaction: %v", tx)
	if tx.Inputs == nil || tx.Inputs.Domain == "" {
		return "", i18n.NewError(ctx, msgs.MsgDomainNotProvided)
	}

	emptyAddress := tktypes.EthAddress{}
	if tx.Inputs.To == emptyAddress {
		return "", i18n.NewError(ctx, msgs.MsgContractAddressNotProvided)
	}

	contractAddr := tx.Inputs.To
	domainAPI, err := p.components.DomainManager().GetSmartContractByAddress(ctx, contractAddr)
	if err != nil {
		return "", err
	}
	err = domainAPI.InitTransaction(ctx, tx)
	if err != nil {
		return "", err
	}

	//Resolve keys synchronously so that we can return an error if any key resolution fails
	keyMgr := p.components.KeyManager()
	if tx.PreAssembly == nil {
		return "", i18n.NewError(ctx, msgs.MsgPrivateTxManagerInternalError, "PreAssembly is nil")
	}
	tx.PreAssembly.Verifiers = make([]*prototk.ResolvedVerifier, len(tx.PreAssembly.RequiredVerifiers))
	for i, v := range tx.PreAssembly.RequiredVerifiers {
		_, verifier, err := keyMgr.ResolveKey(ctx, v.Lookup, v.Algorithm)
		if err != nil {
			return "", i18n.WrapError(ctx, err, msgs.MsgKeyResolutionFailed, v.Lookup, v.Algorithm)
		}
		tx.PreAssembly.Verifiers[i] = &prototk.ResolvedVerifier{
			Lookup:    v.Lookup,
			Algorithm: v.Algorithm,
			Verifier:  verifier,
		}
	}

	oc, err := p.getOrchestratorForContract(ctx, contractAddr, domainAPI)
	if err != nil {
		return "", err
	}
	queued := oc.ProcessNewTransaction(ctx, tx)
	if queued {
		log.L(ctx).Debugf("Transaction with ID %s queued in database", tx.ID)
	}
	return tx.ID.String(), nil
}

// Synchronous function to deploy a domain smart contract
// TODO should this be async?  If async, do we have a chicken and egg problem given that all async event handling relies on a threading model of one thread per contract instance?  What thread would be responsible for deploying a new contract instance?
func (p *privateTxManager) HandleDeployTx(ctx context.Context, tx *components.PrivateContractDeploy) (txID string, contractAddress string, err error) {
	log.L(ctx).Debugf("Handling new private contract deploy transaction: %v", tx)
	if tx.Domain == "" {
		return "", "", i18n.NewError(ctx, msgs.MsgDomainNotProvided)
	}

	domain, err := p.components.DomainManager().GetDomainByName(ctx, tx.Domain)
	if err != nil {
		return "", "", i18n.WrapError(ctx, err, msgs.MsgDomainNotFound, tx.Domain)
	}

	err = domain.InitDeploy(ctx, tx)
	if err != nil {
		return "", "", i18n.WrapError(ctx, err, msgs.MsgDeployInitFailed)
	}

	//Resolve keys synchronously (rather than having an orchestrator stage for it) so that we can return an error if any key resolution fails
	keyMgr := p.components.KeyManager()
	tx.Verifiers = make([]*prototk.ResolvedVerifier, len(tx.RequiredVerifiers))
	for i, v := range tx.RequiredVerifiers {
		_, verifier, err := keyMgr.ResolveKey(ctx, v.Lookup, v.Algorithm)
		if err != nil {
			return "", "", i18n.WrapError(ctx, err, msgs.MsgKeyResolutionFailed, v.Lookup, v.Algorithm)
		}
		tx.Verifiers[i] = &prototk.ResolvedVerifier{
			Lookup:    v.Lookup,
			Algorithm: v.Algorithm,
			Verifier:  verifier,
		}
	}

	//TODO should the following be done asyncronously?

	err = domain.PrepareDeploy(ctx, tx)
	if err != nil {
		return "", "", i18n.WrapError(ctx, err, msgs.MsgDeployPrepareFailed)
	}

	//Placeholder for integration with public transaction manager
	if tx.DeployTransaction != nil && tx.InvokeTransaction == nil {
		err = p.execBaseLedgerDeployTransaction(ctx, tx.Signer, tx.DeployTransaction)
	} else if tx.InvokeTransaction != nil && tx.DeployTransaction == nil {
		err = p.execBaseLedgerTransaction(ctx, tx.Signer, tx.InvokeTransaction)
	} else {
		return "", "", i18n.NewError(ctx, msgs.MsgDeployPrepareIncomplete)
	}
	if err != nil {
		return "", "", i18n.WrapError(ctx, err, msgs.MsgBaseLedgerTransactionFailed)
	}

	psc, err := p.components.DomainManager().WaitForDeploy(ctx, tx.ID)
	if err != nil {
		return "", "", i18n.WrapError(ctx, err, msgs.MsgBaseLedgerTransactionFailed)
	}
	addr := psc.Address()

	return tx.ID.String(), addr.String(), nil

}

// TODO this is a temporary function to execute a base ledger transaction.  It should be replaced with a call to the public transaction manager
func (p *privateTxManager) execBaseLedgerDeployTransaction(ctx context.Context, signer string, txInstruction *components.EthDeployTransaction) error {

	var abiFunc ethclient.ABIFunctionClient
	ec := p.components.EthClientFactory().HTTPClient()
	abiFunc, err := ec.ABIConstructor(ctx, txInstruction.ConstructorABI, tktypes.HexBytes(txInstruction.Bytecode))
	if err != nil {
		return err
	}

	// Send the transaction
	txHash, err := abiFunc.R(ctx).
		Signer(signer).
		Input(txInstruction.Inputs).
		SignAndSend()
	if err == nil {
		_, err = p.components.BlockIndexer().WaitForTransactionSuccess(ctx, *txHash, nil)
	}
	if err != nil {
		return fmt.Errorf("failed to send base deploy ledger transaction: %s", err)
	}
	return nil
}

// TODO this is a temporary function to execute a base ledger transaction.  It should be replaced with a call to the public transaction manager
func (p *privateTxManager) execBaseLedgerTransaction(ctx context.Context, signer string, txInstruction *components.EthTransaction) error {

	var abiFunc ethclient.ABIFunctionClient
	ec := p.components.EthClientFactory().HTTPClient()
	abiFunc, err := ec.ABIFunction(ctx, txInstruction.FunctionABI)
	if err != nil {
		return err
	}

	// Send the transaction
	addr := ethtypes.Address0xHex(txInstruction.To)
	txHash, err := abiFunc.R(ctx).
		Signer(signer).
		To(&addr).
		Input(txInstruction.Inputs).
		SignAndSend()
	if err == nil {
		_, err = p.components.BlockIndexer().WaitForTransactionSuccess(ctx, *txHash, nil)
	}
	if err != nil {
		return fmt.Errorf("failed to send base ledger transaction: %s", err)
	}
	return nil
}

func (p *privateTxManager) GetTxStatus(ctx context.Context, domainAddress string, txID string) (status components.PrivateTxStatus, err error) {
	//TODO This is primarily here to help with testing for now
	// this needs to be revisited ASAP as part of a holisitic review of the persistence model
	targetOrchestrator := p.orchestrators[domainAddress]
	if targetOrchestrator == nil {
		//TODO should be valid to query the status of a transaction that belongs to a domain instance that is not currently active
		errorMessage := fmt.Sprintf("Orchestrator not found for domain address %s", domainAddress)
		return components.PrivateTxStatus{}, i18n.NewError(ctx, msgs.MsgPrivateTxManagerInternalError, errorMessage)
	} else {
		return targetOrchestrator.GetTxStatus(ctx, txID)
	}

}

func (p *privateTxManager) HandleNewEvent(ctx context.Context, event ptmgrtypes.PrivateTransactionEvent) {
	targetOrchestrator := p.orchestrators[event.GetContractAddress()]
	if targetOrchestrator == nil { // this is an event that belongs to a contract that's not in flight, throw it away and rely on the engine to trigger the action again when the orchestrator is wake up. (an enhanced version is to add weight on queueing an orchestrator)
		log.L(ctx).Warnf("Ignored %T event for domain contract %s and transaction %s . If this happens a lot, check the orchestrator idle timeout is set to a reasonable number", event, event.GetContractAddress(), event.GetTransactionID())
	} else {
		targetOrchestrator.HandleEvent(ctx, event)
	}
}

func (p *privateTxManager) HandleEndorsementRequest(ctx context.Context, messagePayload []byte) {
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
		log.L(ctx).Errorf("Failed to get endorsement gathere for contract address %s: %s", contractAddressString, err)
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
		Payload:     endorsementResponseBytes,
	})
	if err != nil {
		log.L(ctx).Errorf("Failed to send endorsement response: %s", err)
		return
	}
}

func (p *privateTxManager) HandleEndorsementResponse(ctx context.Context, messagePayload []byte) {

	endorsementResponse := &pbEngine.EndorsementResponse{}
	err := proto.Unmarshal(messagePayload, endorsementResponse)
	if err != nil {
		log.L(ctx).Errorf("Failed to unmarshal endorsement request: %s", err)
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
		// TODO this is only temproary until we stop using anypb in EndorsementResponse
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

func (p *privateTxManager) ReceiveTransportMessage(ctx context.Context, message *components.TransportMessage) {
	//TODO this need to become an ultra low latency, non blocking, handover to the event loop thread.
	// need some thought on how to handle errors, retries, buffering, swapping idle orchestrators in and out of memory etc...

	//Send the event to the orchestrator for the contract and any transaction manager for the signing key
	messagePayload := message.Payload

	switch message.MessageType {
	case "EndorsementRequest":
		go p.HandleEndorsementRequest(ctx, messagePayload)
	case "EndorsementResponse":
		go p.HandleEndorsementResponse(ctx, messagePayload)
	default:
		log.L(ctx).Errorf("Unknown message type: %s", message.MessageType)
	}
}

// For now, this is here to help with testing but it seems like it could be useful thing to have
// in the future if we want to have an eventing interface but at such time we would need to put more effort
// into the reliabilty of the event delivery or maybe there is only a consumer of the event and it is responsible
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
