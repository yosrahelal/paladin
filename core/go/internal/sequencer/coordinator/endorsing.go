/*
 * Copyright © 2026 Kaleido, Inc.
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

package coordinator

import (
	"context"

	"github.com/LFDT-Paladin/paladin/common/go/pkg/log"
	"github.com/LFDT-Paladin/paladin/core/internal/sequencer/common"
	"github.com/LFDT-Paladin/paladin/sdk/go/pkg/pldtypes"
	"github.com/LFDT-Paladin/paladin/toolkit/pkg/prototk"
)

// validator_IsEndorsementRequestFromHigherPriorityCoordinator returns true when the node
// that sent the endorsement request has strictly higher priority (lower index) than this
// node in the current coordinator priority list. Uses the same comparison as
// validator_IsHandoverRequestFromHigherPriorityCoordinator: we compare the sender against
// c.nodeName (not against c.currentActiveCoordinator), since the question is whether the
// requester outranks us.
func validator_IsEndorsementRequestFromHigherPriorityCoordinator(_ context.Context, c *coordinator, event common.Event) (bool, error) {
	e := event.(*EndorsementRequestReceivedEvent)
	return common.IsHigherPriority(c.coordinatorPriorityList, e.FromNode, c.nodeName), nil
}

// validator_IsEndorsementRequestFromSelf returns true when this node sent the endorsement
// request itself — i.e. the coordinator and the endorser are the same node. Used in Active
// and Active_Flush so the node can endorse its own transactions without stepping down.
func validator_IsEndorsementRequestFromSelf(_ context.Context, c *coordinator, event common.Event) (bool, error) {
	e := event.(*EndorsementRequestReceivedEvent)
	return e.FromNode == c.nodeName, nil
}

// action_UpdateActiveCoordinatorFromEndorsementRequest records the sender of an endorsement
// request as the current active coordinator. Called in states where this node is not active
// (Idle, Observing, Closing_Flush, Closing) or is stepping down in response to a higher-priority
// requester (Elect, Prepared, Active, Active_Flush).
func action_UpdateActiveCoordinatorFromEndorsementRequest(_ context.Context, c *coordinator, event common.Event) error {
	e := event.(*EndorsementRequestReceivedEvent)
	c.currentActiveCoordinator = e.FromNode
	return nil
}

// action_HandleEndorsementRequest spawns a background goroutine to perform the
// domain-level endorsement work and send the response. This keeps the coordinator event loop
// unblocked while allowing multiple endorsements to run concurrently.
//
// The goroutine uses c.components and c.transportWriter directly. Both are safe to call from
// concurrent goroutines: remote sends go through TransportManager.Send (goroutine-safe) and
// loopback sends go through a buffered channel.
func action_HandleEndorsementRequest(ctx context.Context, c *coordinator, event common.Event) error {
	e := event.(*EndorsementRequestReceivedEvent)
	go c.handleEndorsementRequest(ctx, e)
	return nil
}

func (c *coordinator) handleEndorsementRequest(ctx context.Context, e *EndorsementRequestReceivedEvent) {
	unqualifiedLookup, err := pldtypes.PrivateIdentityLocator(e.Party).Identity(ctx)
	if err != nil {
		log.L(ctx).Errorf("handleEndorsementRequest failed to resolve party identity: %s", err)
		return
	}
	resolvedSigner, err := c.components.KeyManager().ResolveKeyNewDatabaseTX(ctx, unqualifiedLookup, e.AttestationRequest.Algorithm, e.AttestationRequest.VerifierType)
	if err != nil {
		log.L(ctx).Errorf("handleEndorsementRequest failed to resolve key for party %s: %s", e.Party, err)
		return
	}
	endorsementRequest := e.PrivateEndorsementRequest
	endorsementRequest.Endorser = &prototk.ResolvedVerifier{
		Lookup:       e.Party,
		Algorithm:    e.AttestationRequest.Algorithm,
		Verifier:     resolvedSigner.Verifier.Verifier,
		VerifierType: e.AttestationRequest.VerifierType,
	}

	dCtx := c.components.StateManager().NewDomainContext(ctx, c.domainAPI.Domain(), c.domainAPI.Address())
	defer dCtx.Close()

	endorsementResult, err := c.domainAPI.EndorseTransaction(dCtx, c.components.Persistence().NOTX(), endorsementRequest)
	if err != nil {
		log.L(ctx).Errorf("handleEndorsementRequest failed to endorse transaction: %s", err)
		return
	}
	e.AttestationRequest.Payload = endorsementResult.Payload

	attResult := &prototk.AttestationResult{
		Name:            e.AttestationRequest.Name,
		AttestationType: e.AttestationRequest.AttestationType,
		Verifier:        endorsementResult.Endorser,
	}

	revertReason := ""

	switch endorsementResult.Result {
	case prototk.EndorseTransactionResponse_REVERT:
		revertReason = "(no revert reason)"
		if endorsementResult.RevertReason != nil {
			revertReason = *endorsementResult.RevertReason
		}
	case prototk.EndorseTransactionResponse_SIGN:
		unqualifiedLookup, signerNode, err := pldtypes.PrivateIdentityLocator(endorsementResult.Endorser.Lookup).Validate(ctx, c.nodeName, true)
		if err != nil {
			log.L(ctx).Errorf("handleEndorsementRequest failed to validate endorser: %s", err)
			return
		}
		if signerNode == c.nodeName {
			log.L(ctx).Info("endorsement response signing request includes us - signing it now")
			keyMgr := c.components.KeyManager()
			resolvedKey, err := keyMgr.ResolveKeyNewDatabaseTX(ctx, unqualifiedLookup, e.AttestationRequest.Algorithm, e.AttestationRequest.VerifierType)
			if err != nil {
				log.L(ctx).Errorf("handleEndorsementRequest failed to resolve key for endorser: %s", err)
				return
			}
			signaturePayload, err := keyMgr.Sign(ctx, resolvedKey, e.AttestationRequest.PayloadType, e.AttestationRequest.Payload)
			if err != nil {
				log.L(ctx).Errorf("handleEndorsementRequest failed to sign endorsement request: %s", err)
				return
			}
			attResult.Payload = signaturePayload
		} else {
			// This can presumably never happen, since this endorsement request came to us
			log.L(ctx).Errorf("handleEndorsementRequest received isn't for this node: %s", signerNode)
		}
	case prototk.EndorseTransactionResponse_ENDORSER_SUBMIT:
		attResult.Constraints = append(attResult.Constraints, prototk.AttestationResult_ENDORSER_MUST_SUBMIT)
	}

	c.metrics.IncEndorsedTransactions()
	err = c.transportWriter.SendEndorsementResponse(
		ctx,
		e.TransactionId,
		e.IdempotencyKey,
		c.contractAddress.String(),
		attResult,
		endorsementResult,
		revertReason,
		e.AttestationRequest.Name,
		e.Party,
		e.FromNode,
	)
	if err != nil {
		log.L(ctx).Errorf("handleEndorsementRequest failed to send endorsement response: %s", err)
	}
}
