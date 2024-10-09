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

package evmregistry

import (
	"context"
	"encoding/json"
	"fmt"

	_ "embed"

	"github.com/hyperledger/firefly-common/pkg/i18n"
	"github.com/kaleido-io/paladin/registries/evm/internal/msgs"
	"github.com/kaleido-io/paladin/toolkit/pkg/log"
	"github.com/kaleido-io/paladin/toolkit/pkg/plugintk"
	"github.com/kaleido-io/paladin/toolkit/pkg/prototk"
	"github.com/kaleido-io/paladin/toolkit/pkg/tktypes"
)

//go:embed abis/IdentityRegistry.json
var identityRegistryJSON []byte

var contractDetail = mustLoadIdentityRegistryContractDetail(identityRegistryJSON)

type Server interface {
	Start() error
	Stop()
}

type evmRegistry struct {
	bgCtx     context.Context
	callbacks plugintk.RegistryCallbacks

	conf *Config
	name string
}

func NewPlugin(ctx context.Context) plugintk.PluginBase {
	return plugintk.NewRegistry(evmRegistryFactory)
}

func evmRegistryFactory(callbacks plugintk.RegistryCallbacks) plugintk.RegistryAPI {
	return &evmRegistry{
		bgCtx:     context.Background(),
		callbacks: callbacks,
	}
}

func (r *evmRegistry) ConfigureRegistry(ctx context.Context, req *prototk.ConfigureRegistryRequest) (*prototk.ConfigureRegistryResponse, error) {
	r.name = req.Name

	err := json.Unmarshal([]byte(req.ConfigJson), &r.conf)
	if err != nil {
		return nil, i18n.WrapError(ctx, err, msgs.MsgInvalidRegistryConfig)
	}

	// Currently the configuration is static other than the contract address.
	//
	// The default behavior registry is as follows (code extension and future config enhancements will allow customization of this)
	// - Identities that contain transport addresses must be at the root of the registry contract
	// - This means the operator role of the smart contract is responsible for onboarding all nodes
	// - The node name is the name of the entry
	// - Each property of this top-level object is a transport type (such as "grpc")
	// - The value of the property is the transport details

	return &prototk.ConfigureRegistryResponse{
		RegistryConfig: &prototk.RegistryConfig{
			EventSources: []*prototk.RegistryEventSource{
				{
					ContractAddress: r.conf.ContractAddress.String(),
					AbiEventsJson:   tktypes.JSONString(contractDetail.abi).Pretty(),
				},
			},
		},
	}, nil
}

func (r *evmRegistry) registerNodeTransport(ctx context.Context, nodeName, transportName string, transportRecordUnparsed tktypes.RawJSON) error {
	var untyped any
	err := json.Unmarshal(transportRecordUnparsed, &untyped)
	if err != nil {
		return i18n.WrapError(ctx, err, msgs.MsgInvalidRegistryConfig, nodeName, transportName)
	}

	// We let the config contain structured JSON (well YAML in it's original form before it was passed as JSON to us)
	// Or we let the config contain a string
	var transportDetails string
	switch v := untyped.(type) {
	case string:
		// it's already a string - so it's our details directly
		transportDetails = v
	default:
		// otherwise we preserve the JSON
		transportDetails = transportRecordUnparsed.String()
	}
	_, err = r.callbacks.UpsertTransportDetails(ctx, &prototk.UpsertTransportDetails{
		TransportDetails: []*prototk.TransportDetails{
			{
				Node:      nodeName,
				Transport: transportName,
				Details:   transportDetails,
			},
		},
	})
	return err
}

func (r *evmRegistry) RegistryEventBatch(ctx context.Context, req *prototk.RegistryEventBatchRequest) (*prototk.RegistryEventBatchResponse, error) {

	// Parse all the events
	parsedEvents := make([]*prototk.TransportDetails, 0, len(req.Events))
	for _, inEvent := range req.Events {
		inSig, err := tktypes.ParseBytes32(inEvent.Signature)
		if err != nil {
			return nil, i18n.WrapError(ctx, err, msgs.MsgInvalidRegistryEvent, inEvent.Location)
		}
		if !contractDetail.identityRegisteredSignature.Equals(&inSig) {
			log.L(ctx).Debugf("Discarding event (not IdentityRegistered): %s", inEvent.SoliditySignature)
			continue
		}

		// We should be able to parse this
		var parsedEvent IdentityRegisteredEvent
		if err := json.Unmarshal([]byte(inEvent.DataJson), &parsedEvent); err != nil {
			return nil, i18n.WrapError(ctx, err, msgs.MsgInvalidRegistryEvent, inEvent.Location)
		}

		// We only look at the root entries
		if !parsedEvent.ParentIdentityHash.IsZero() {
			log.L(ctx).Debugf("Discarding IdentityRegistered for non-root identity: %+v", parsedEvent)
			continue
		}

		// Check the node is a valid identity string - as Solidity does not enforce this
		if _, err = tktypes.PrivateIdentityLocator(fmt.Sprintf("anything@%s", parsedEvent.Name)).Node(ctx, false); err != nil {
			log.L(ctx).Warnf("Discarding IdentityRegistered due to INVALID node name for Paladin: %+v", parsedEvent)
			continue
		}

		// parsedEvents = append(parsedEvents, &prototk.TransportDetails{
		// 	Node: ,
		// })
	}

	// We only consider root events interesting

	return &prototk.RegistryEventBatchResponse{}, nil
}
