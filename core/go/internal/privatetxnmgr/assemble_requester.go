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

	"github.com/google/uuid"
	"github.com/hyperledger/firefly-common/pkg/i18n"
	"github.com/kaleido-io/paladin/core/internal/components"
	"github.com/kaleido-io/paladin/core/internal/msgs"
	"github.com/kaleido-io/paladin/toolkit/pkg/log"
	"github.com/kaleido-io/paladin/toolkit/pkg/prototk"
)

// AssembleCoordinator is a component that is responsible for coordinating the assembly of all transactions for a given domain contract instance
// requests to assemble transactions are accepted and the actual assembly is performed asynchronously
type AssembleCoordinator interface {
	Start(ctx context.Context)
	Stop()
	RequestAssemble(ctx context.Context, assemblingNode string, transactionID uuid.UUID, transactionInputs *components.TransactionInputs, transactionPreAssembly *components.TransactionPreAssembly, callbacks AssembleRequestCallbacks)
}

type AssembleRequestCompleteCallback func(postAssembly *components.TransactionPostAssembly)
type AssembleRequestFailedCallback func(error)
type AssembleRequestCallbacks struct {
	OnComplete AssembleRequestCompleteCallback
	OnFail     AssembleRequestFailedCallback
}

func (ar *assembleCoordinator) requestAssemble(ctx context.Context, callbacks AssembleRequestCallbacks) {
	ar.requests <- &assembleRequest{
		callbacks: callbacks,
	}
}

type assembleCoordinator struct {
	nodeName      string
	requests      chan *assembleRequest
	stopProcess   chan bool
	components    components.AllComponents
	domainAPI     components.DomainSmartContract
	domainContext components.DomainContext
}

type assembleRequest struct {
	assemblingNode         string
	assembleCoordinator    *assembleCoordinator
	transactionID          uuid.UUID
	transactionInputs      *components.TransactionInputs
	transactionPreassembly *components.TransactionPreAssembly
	callbacks              AssembleRequestCallbacks
}

func NewAssembleCoordinator(ctx context.Context, nodeName string, maxPendingRequests int, components components.AllComponents, domainAPI components.DomainSmartContract, domainContext components.DomainContext) AssembleCoordinator {
	return &assembleCoordinator{
		nodeName:      nodeName,
		stopProcess:   make(chan bool, 1),
		requests:      make(chan *assembleRequest, maxPendingRequests),
		components:    components,
		domainAPI:     domainAPI,
		domainContext: domainContext,
	}
}

func (ac *assembleCoordinator) Start(ctx context.Context) {
	log.L(ctx).Info("Starting AssembleCoordinator")
	go func() {
		for {
			select {
			case req := <-ac.requests:
				if req.assemblingNode == "" || req.assemblingNode == ac.nodeName {
					req.processLocal(ctx)
				} else {
					req.processRemote(ctx, req.assemblingNode)
				}
			case <-ac.stopProcess:
				log.L(ctx).Info("assembleCoordinator loop process stopped")
				return
			case <-ctx.Done():
				log.L(ctx).Info("AssembleCoordinator loop exit due to canceled context")
				return
			}
		}
	}()
}

func (ac *assembleCoordinator) Stop() {
	// try to send an item in `stopProcess` channel, which has a buffer of 1
	// if it already has an item in the channel, this function does nothing
	select {
	case ac.stopProcess <- true:
	default:
	}

}

// TODO really need to figure out the separation between PrivateTxManager and DomainManager
// to allow us to do the assemble on a separate thread and without worrying about locking the PrivateTransaction objects
// we copy the pertinent structures out of the PrivateTransaction and pass them to the assemble thread
// and then use them to create another private transaction object that is passed to the domain manager which then just unpicks it again
func (ac *assembleCoordinator) RequestAssemble(ctx context.Context, assemblingNode string, transactionID uuid.UUID, transactionInputs *components.TransactionInputs, transactionPreAssembly *components.TransactionPreAssembly, callbacks AssembleRequestCallbacks) {

	log.L(ctx).Debug("RequestAssemble")
	ac.requests <- &assembleRequest{
		assembleCoordinator:    ac,
		callbacks:              callbacks,
		transactionInputs:      transactionInputs,
		transactionPreassembly: transactionPreAssembly,
	}

}

func (req *assembleRequest) processLocal(ctx context.Context) {
	log.L(ctx).Debug("assembleRequest:processLocal")
	// we are the node that is responsible for assembling this transaction
	readTX := req.assembleCoordinator.components.Persistence().DB() // no DB transaction required here

	transaction := &components.PrivateTransaction{
		Inputs:      req.transactionInputs,
		PreAssembly: req.transactionPreassembly,
	}

	err := req.assembleCoordinator.domainAPI.AssembleTransaction(req.assembleCoordinator.domainContext, readTX, transaction)
	if err != nil {
		req.callbacks.OnFail(err)
		return
	}
	if transaction.PostAssembly == nil {
		// This is most likely a programming error in the domain
		err := i18n.NewError(ctx, msgs.MsgPrivateTxManagerInternalError, "AssembleTransaction returned nil PostAssembly")
		req.callbacks.OnFail(err)
		return
	}

	// Some validation that we are confident we can execute the given attestation plan
	for _, attRequest := range transaction.PostAssembly.AttestationPlan {
		switch attRequest.AttestationType {
		case prototk.AttestationType_ENDORSE:
		case prototk.AttestationType_SIGN:
		case prototk.AttestationType_GENERATE_PROOF:
			errorMessage := "AttestationType_GENERATE_PROOF is not implemented yet"
			log.L(ctx).Error(errorMessage)
			err := i18n.NewError(ctx, msgs.MsgPrivateTxManagerInternalError, errorMessage)
			req.callbacks.OnFail(err)

		default:
			errorMessage := fmt.Sprintf("Unsupported attestation type: %s", attRequest.AttestationType)
			log.L(ctx).Error(errorMessage)
			err := i18n.NewError(ctx, msgs.MsgPrivateTxManagerInternalError, errorMessage)
			req.callbacks.OnFail(err)
		}
	}

	log.L(ctx).Debug("assembleRequest:processLocal complete")

	req.callbacks.OnComplete(transaction.PostAssembly)

}

func (req *assembleRequest) processRemote(ctx context.Context, assemblingNode string) {

	//Assemble may require a call to another node ( in the case we have been delegated to coordinate transaction for other nodes)
	//Usually, they will get sent to us already assembled but there may be cases where we need to re-assemble
	// so this needs to be an async step
	// however, there must be only one assemble in progress at a time or else there is a risk that 2 transactions could chose to spend the same state
	//   (TODO - maybe in future, we could further optimize this and allow multiple assembles to be in progress if we can assert that they are not presented with the same available states)
	//   However, before we do that, we really need to sort out the separation of concerns between the domain manager, state store and private transaction manager and where the responsibility to single thread the assembly stream(s) lies

	log.L(ctx).Debug("assembleRequest:processRemote")

	log.L(ctx).Debugf("Assembling transaction %s on node %s", req.transactionID.String(), assemblingNode)
	//TODO send a request to the node that is responsible for assembling this transaction
}
