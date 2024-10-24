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

	"github.com/hyperledger/firefly-common/pkg/i18n"
	"github.com/kaleido-io/paladin/core/internal/msgs"
	"github.com/kaleido-io/paladin/toolkit/pkg/log"
	"github.com/kaleido-io/paladin/toolkit/pkg/prototk"
	"github.com/kaleido-io/paladin/toolkit/pkg/tktypes"
)

type AssembleRequester interface {
	Start(ctx context.Context)
}
type assembleRequest struct {
}
type assembleRequester struct {
	requests chan *assembleRequest
}

func NewAssembleRequester(ctx context.Context, maxPendingRequests int) AssembleRequester {
	return &assembleRequester{
		requests: make(chan *assembleRequest, maxPendingRequests),
	}
}
func (ar *assembleRequester) Start(ctx context.Context) {
	go func() {

	}()

}

func (req *assembleRequest) processLocal(ctx context.Context) {
//we are the node that is responsible for assembling this transaction
readTX := tf.components.Persistence().DB() // no DB transaction required here
err = tf.domainAPI.AssembleTransaction(tf.endorsementGatherer.DomainContext(), readTX, tf.transaction)
if err != nil {
	log.L(ctx).Errorf("AssembleTransaction failed: %s", err)
	tf.publisher.PublishTransactionAssembleFailedEvent(ctx,
		tf.transaction.ID.String(),
		i18n.ExpandWithCode(ctx, i18n.MessageKey(msgs.MsgPrivateTxManagerAssembleError), err.Error()),
	)
	return
}
if tf.transaction.PostAssembly == nil {
	// This is most likely a programming error in the domain
	log.L(ctx).Errorf("PostAssembly is nil.")
	tf.publisher.PublishTransactionAssembleFailedEvent(
		ctx,
		tf.transaction.ID.String(),
		i18n.ExpandWithCode(ctx, i18n.MessageKey(msgs.MsgPrivateTxManagerInternalError), "AssembleTransaction returned nil PostAssembly"),
	)
	return
}

// Some validation that we are confident we can execute the given attestation plan
for _, attRequest := range tf.transaction.PostAssembly.AttestationPlan {
	switch attRequest.AttestationType {
	case prototk.AttestationType_ENDORSE:
	case prototk.AttestationType_SIGN:
	case prototk.AttestationType_GENERATE_PROOF:
		errorMessage := "AttestationType_GENERATE_PROOF is not implemented yet"
		log.L(ctx).Error(errorMessage)
		tf.latestError = i18n.ExpandWithCode(ctx, i18n.MessageKey(msgs.MsgPrivateTxManagerInternalError), errorMessage)
		tf.publisher.PublishTransactionAssembleFailedEvent(ctx,
			tf.transaction.ID.String(),
			i18n.ExpandWithCode(ctx, i18n.MessageKey(msgs.MsgPrivateTxManagerAssembleError), errorMessage),
		)
	default:
		errorMessage := fmt.Sprintf("Unsupported attestation type: %s", attRequest.AttestationType)
		log.L(ctx).Error(errorMessage)
		tf.latestError = i18n.ExpandWithCode(ctx, i18n.MessageKey(msgs.MsgPrivateTxManagerInternalError), errorMessage)
		tf.publisher.PublishTransactionAssembleFailedEvent(ctx,
			tf.transaction.ID.String(),
			i18n.ExpandWithCode(ctx, i18n.MessageKey(msgs.MsgPrivateTxManagerAssembleError), errorMessage),
		)
	}
}

//TODO should probably include the assemble output in the event
// for now that is not necessary because this is a local assemble and the domain manager updates the transaction that we passed by reference
// need to decide if we want to continue with that style of interface to the domain manager and if so,
// we need to do something different when the assembling node is remote
tf.publisher.PublishTransactionAssembledEvent(ctx,
	tf.transaction.ID.String(),
)
return
}

func (req *assembleRequest) processRemote(ctx context.Context, assemblingNode string) {

	func (req *assembleRequest) processLocalAssemble(ctx context.Context) {
	//Assemble may require a call to another node ( in the case we have been delegated to coordinate transaction for other nodes)
	//Usually, they will get sent to us already assembled but there may be cases where we need to re-assemble
	// so this needs to be an async step
	// however, there must be only one assemble in progress at a time or else there is a risk that 2 transactions could chose to spend the same state
	//   (TODO - maybe in future, we could further optimise this and allow multiple assembles to be in progress if we can assert that they are not presented with the same available states)
	//   However, before we do that, we really need to sort out the separation of concerns between the domain manager, state store and private transaction manager and where the responsibility to single thread the assembly stream(s) lies

	log.L(ctx).Debug("assembleRequest:process")



	log.L(ctx).Debugf("Assembling transaction %s on node %s", tf.transaction.ID.String(), assemblingNode)
	//TODO send a request to the node that is responsible for assembling this transaction
}

type AssembleRequestCallbacks interface {
	AssembleRequestComplete()
	AssembleRequestFailed(error)
}

func (ar *assembleRequester) requestAssemble(ctx context.Context, callbacks AssembleRequestCallbacks) {
	ar.requests <- &assembleRequest{
		callbacks: callbacks,
	}
}
