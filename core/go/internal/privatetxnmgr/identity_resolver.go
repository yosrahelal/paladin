// Copyright © 2024 Kaleido, Inc.
//
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package privatetxnmgr

import (
	"context"
	"strings"
	"sync"

	"github.com/google/uuid"
	"github.com/hyperledger/firefly-common/pkg/i18n"
	"github.com/kaleido-io/paladin/core/internal/components"
	"github.com/kaleido-io/paladin/core/internal/msgs"
	"github.com/kaleido-io/paladin/core/internal/privatetxnmgr/ptmgrtypes"
	"github.com/kaleido-io/paladin/core/pkg/ethclient"
	engineProto "github.com/kaleido-io/paladin/core/pkg/proto/engine"
	"github.com/kaleido-io/paladin/toolkit/pkg/log"
	"github.com/kaleido-io/paladin/toolkit/pkg/tktypes"
	"google.golang.org/protobuf/proto"
)

type identityResolver struct {
	nodeID                string
	keyManager            ethclient.KeyManager
	transportManager      components.TransportManager
	inflightRequests      map[string]*inflightRequest
	inflightRequestsMutex *sync.Mutex
}

type inflightRequest struct {
	resolved func(ctx context.Context, verifier string)
	failed   func(ctx context.Context, err error)
}

func NewIdentityResolver(nodeID string, keyManager ethclient.KeyManager, transportManager components.TransportManager) ptmgrtypes.IdentityResolver {
	return &identityResolver{
		nodeID:                nodeID,
		keyManager:            keyManager,
		transportManager:      transportManager,
		inflightRequests:      make(map[string]*inflightRequest),
		inflightRequestsMutex: &sync.Mutex{},
	}
	//TODO start a reaper thread to clean up inflight requests that have been hanging around too long
}

func (ir *identityResolver) ResolveVerifier(ctx context.Context, lookup string, algorithm string) (string, error) {
	//TODO should we have a timeout here? Shoudl be related to the async timeout and reaping of the inflight requests?
	replyChan := make(chan string)
	errChan := make(chan error)
	ir.ResolveVerifierAsync(ctx, lookup, algorithm, func(ctx context.Context, verifier string) {
		replyChan <- verifier
	}, func(ctx context.Context, err error) {
		errChan <- err
	})
	select {
	case verifier := <-replyChan:
		return verifier, nil
	case err := <-errChan:
		return "", err
	}
}

func (ir *identityResolver) ResolveVerifierAsync(ctx context.Context, lookup string, algorithm string, resolved func(ctx context.Context, verifier string), failed func(ctx context.Context, err error)) {
	// if the verifier lookup is a local key, we can resolve it here
	// if it is a remote key, we need to delegate to the remote node

	atIndex := strings.Index(lookup, "@")

	if atIndex == -1 || lookup[atIndex+1:] == ir.nodeID {
		// this is an asyncronous call because the key manager may need to call out to a remote signer in order to
		// resovle the key (e.g. if this is the first time this key has been referenced)
		// its a one and done go routine so no need for additional concurency controls
		// we just need to be careful not to update the transaction object on this other thread
		go func() {
			_, verifier, err := ir.keyManager.ResolveKey(ctx, lookup, algorithm)
			if err != nil {
				log.L(ctx).Errorf("Failed to resolve local signer for %s (algorithm=%s): %s", lookup, algorithm, err)
				failed(ctx, err)
				return

			}
			resolved(ctx, verifier)
		}()

	} else {
		log.L(ctx).Debugf("resolving verifier via remote node %s", lookup)

		resolveVerifierRequest := &engineProto.ResolveVerifierRequest{
			Lookup:    lookup,
			Algorithm: algorithm,
		}
		resolveVerifierRequestBytes, err := proto.Marshal(resolveVerifierRequest)
		if err != nil {
			log.L(ctx).Errorf("Failed to marshal ResolveVerifierRequest for lookup %s: %s", lookup, err)
			failed(ctx, err)
			return
		}

		requestID := uuid.New()

		err = ir.transportManager.Send(ctx, &components.TransportMessage{
			MessageType: "ResolveVerifierRequest",
			MessageID:   requestID,
			Destination: tktypes.PrivateIdentityLocator(lookup),
			ReplyTo:     tktypes.PrivateIdentityLocator(ir.nodeID),
			Payload:     resolveVerifierRequestBytes,
		})
		if err != nil {
			failed(ctx, err)
			return
		}
		ir.addInflightRequest(requestID.String(), &inflightRequest{
			resolved: resolved,
			failed:   failed,
		})
	}
}

func (ir *identityResolver) addInflightRequest(requestID string, request *inflightRequest) {
	ir.inflightRequestsMutex.Lock()
	defer ir.inflightRequestsMutex.Unlock()
	ir.inflightRequests[requestID] = request
}

func (ir *identityResolver) resolveInflightRequest(ctx context.Context, requestID string, verifier string) {
	ir.inflightRequestsMutex.Lock()
	defer ir.inflightRequestsMutex.Unlock()
	request := ir.inflightRequests[requestID]
	if request == nil {
		log.L(ctx).Warnf("Failed to find inflight request %s", requestID)
		return
	}
	delete(ir.inflightRequests, requestID)

	// make sure we don't hold the lock while calling the callback
	go request.resolved(ctx, verifier)
}

func (ir *identityResolver) failInflightRequest(ctx context.Context, requestID string, err error) {
	ir.inflightRequestsMutex.Lock()
	defer ir.inflightRequestsMutex.Unlock()
	request := ir.inflightRequests[requestID]
	if request == nil {
		log.L(ctx).Warnf("Failed to find inflight request %s", requestID)
		return
	}
	delete(ir.inflightRequests, requestID)

	// make sure we don't hold the lock while calling the callback
	go request.failed(ctx, err)
}

func (ir *identityResolver) HandleResolveVerifierReply(ctx context.Context, event *ptmgrtypes.ResolveVerifierReply) {
	ir.resolveInflightRequest(ctx, event.RequestID, *event.Verifier)
}

func (ir *identityResolver) HandleResolveVerifierError(ctx context.Context, event *ptmgrtypes.ResolveVerifierError) {
	ir.failInflightRequest(ctx, event.RequestID, i18n.NewError(ctx, msgs.MsgResolveVerifierRemoteFailed, event.Lookup, event.Algorithm, event.ErrorMessage))
}
