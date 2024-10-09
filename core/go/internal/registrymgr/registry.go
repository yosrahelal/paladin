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

package registrymgr

import (
	"context"
	"encoding/json"
	"fmt"
	"sync/atomic"

	"github.com/google/uuid"
	"github.com/hyperledger/firefly-common/pkg/i18n"
	"github.com/hyperledger/firefly-signer/pkg/abi"
	"github.com/kaleido-io/paladin/config/pkg/pldconf"
	"github.com/kaleido-io/paladin/core/internal/components"
	"github.com/kaleido-io/paladin/core/internal/msgs"
	"github.com/kaleido-io/paladin/core/pkg/blockindexer"

	"github.com/kaleido-io/paladin/toolkit/pkg/log"
	"github.com/kaleido-io/paladin/toolkit/pkg/prototk"
	"github.com/kaleido-io/paladin/toolkit/pkg/retry"
	"github.com/kaleido-io/paladin/toolkit/pkg/tktypes"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

type registry struct {
	ctx       context.Context
	cancelCtx context.CancelFunc

	conf *pldconf.RegistryConfig
	rm   *registryManager
	id   uuid.UUID
	name string
	api  components.RegistryManagerToRegistry

	initialized atomic.Bool
	initRetry   *retry.Retry

	initError atomic.Pointer[error]
	initDone  chan struct{}

	config      *prototk.RegistryConfig
	eventStream *blockindexer.EventStream
}

func (rm *registryManager) newRegistry(id uuid.UUID, name string, conf *pldconf.RegistryConfig, toRegistry components.RegistryManagerToRegistry) *registry {
	r := &registry{
		rm:        rm,
		conf:      conf,
		initRetry: retry.NewRetryIndefinite(&conf.Init.Retry),
		name:      name,
		id:        id,
		api:       toRegistry,
		initDone:  make(chan struct{}),
	}
	r.ctx, r.cancelCtx = context.WithCancel(log.WithLogField(rm.bgCtx, "registry", r.name))
	return r
}

func (r *registry) init() {
	defer close(r.initDone)

	// We block retrying each part of init until we succeed, or are cancelled
	// (which the plugin manager will do if the registry disconnects)
	err := r.initRetry.Do(r.ctx, func(attempt int) (bool, error) {
		// Send the configuration to the registry for processing
		confJSON, _ := json.Marshal(&r.conf.Config)
		res, err := r.api.ConfigureRegistry(r.ctx, &prototk.ConfigureRegistryRequest{
			Name:       r.name,
			ConfigJson: string(confJSON),
		})
		if err == nil {
			r.config = res.RegistryConfig
			err = r.configureEventStream(r.ctx)
		}
		return true, err
	})
	if err != nil {
		log.L(r.ctx).Debugf("registry initialization cancelled before completion: %s", err)
		r.initError.Store(&err)
	} else {
		log.L(r.ctx).Debugf("registry initialization complete")
		r.initialized.Store(true)
		// Inform the plugin manager callback
		r.api.Initialized()
	}
}

func (r *registry) configureEventStream(ctx context.Context) (err error) {

	if len(r.config.EventSources) == 0 {
		return nil
	}

	stream := &blockindexer.EventStream{
		Type:    blockindexer.EventStreamTypeInternal.Enum(),
		Sources: []blockindexer.EventStreamSource{},
	}

	for i, es := range r.config.EventSources {

		var contractAddr *tktypes.EthAddress
		if es.ContractAddress != "" {
			contractAddr, err = tktypes.ParseEthAddress(es.ContractAddress)
			if err != nil {
				return i18n.WrapError(ctx, err, msgs.MsgRegistryInvalidEventSource, i)
			}
		}

		var eventsABI abi.ABI
		if err := json.Unmarshal([]byte(es.AbiEventsJson), &eventsABI); err != nil {
			return i18n.WrapError(ctx, err, msgs.MsgRegistryInvalidEventSource, i)
		}

		stream.Sources = append(stream.Sources, blockindexer.EventStreamSource{
			Address: contractAddr,
			ABI:     eventsABI,
		})
	}

	streamHash, err := stream.Sources.Hash(ctx)
	if err != nil {
		return err
	}
	stream.Name = fmt.Sprintf("registry_%s_%s", r.name, streamHash)

	r.eventStream, err = r.rm.blockIndexer.AddEventStream(ctx, &blockindexer.InternalEventStream{
		Definition: stream,
		Handler:    r.handleEventBatch,
	})
	return err
}

func (r *registry) UpsertTransportDetails(ctx context.Context, req *prototk.UpsertTransportDetails) (*prototk.UpsertTransportDetailsResponse, error) {
	var postCommit func()
	err := r.rm.persistence.DB().Transaction(func(dbTX *gorm.DB) (err error) {
		postCommit, err = r.upsertTransportDetailsBatch(ctx, dbTX, req.TransportDetails)
		return err
	})
	if err != nil {
		return nil, err
	}
	postCommit()
	return &prototk.UpsertTransportDetailsResponse{}, nil
}

func (r *registry) handleEventBatch(ctx context.Context, dbTX *gorm.DB, batch *blockindexer.EventDeliveryBatch) (blockindexer.PostCommit, error) {

	// Build the proto version of these events
	events := make([]*prototk.OnChainEvent, len(batch.Events))
	for i, be := range batch.Events {
		events[i] = &prototk.OnChainEvent{
			Location: &prototk.OnChainEventLocation{
				TransactionHash:  be.TransactionHash.String(),
				BlockNumber:      be.BlockNumber,
				TransactionIndex: be.TransactionIndex,
				LogIndex:         be.LogIndex,
			},
			Signature:         be.Signature.String(),
			SoliditySignature: be.SoliditySignature,
			DataJson:          string(be.Data),
		}
	}

	// Push them down synchronously to the registry to parse
	res, err := r.api.RegistryEventBatch(ctx, &prototk.RegistryEventBatchRequest{
		BatchId: batch.BatchID.String(),
		Events:  events,
	})
	if err != nil {
		return nil, err
	}

	// Upsert any transport details that are detected by the registry
	return r.upsertTransportDetailsBatch(ctx, dbTX, res.TransportDetails)

}

func (r *registry) upsertTransportDetailsBatch(ctx context.Context, dbTX *gorm.DB, protoEntries []*prototk.TransportDetails) (func(), error) {

	updatedNodes := make(map[string]bool)
	entries := make([]*components.RegistryNodeTransportEntry, len(protoEntries))
	for i, req := range protoEntries {
		if req.Node == "" || req.Transport == "" {
			return nil, i18n.NewError(ctx, msgs.MsgRegistryInvalidEntry)
		}
		updatedNodes[req.Node] = true
		entries[i] = &components.RegistryNodeTransportEntry{
			Registry:  r.id.String(),
			Node:      req.Node,
			Transport: req.Transport,
			Details:   req.Details,
		}
	}

	// Store entry in database
	if len(entries) > 0 {
		err := dbTX.
			WithContext(ctx).
			Table("registry_transport_details").
			Clauses(clause.OnConflict{
				Columns: []clause.Column{
					{Name: "registry"},
					{Name: "node"},
					{Name: "transport"},
				},
				DoUpdates: clause.AssignmentColumns([]string{
					"details", // we replace any existing entry
				}),
			}).
			Create(entries).
			Error
		if err != nil {
			return nil, err
		}
	}

	// return a post-commit callback to update the cache
	return func() {
		for node := range updatedNodes {
			// The cache is by node, and we only have complete entries - so just invalid the cache
			r.rm.registryCache.Delete(node)
		}
	}, nil
}

func (r *registry) close() {
	r.cancelCtx()
	<-r.initDone
}
