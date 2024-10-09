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

func (r *registry) UpsertRegistryRecords(ctx context.Context, req *prototk.UpsertRegistryRecordsRequest) (*prototk.UpsertRegistryRecordsResponse, error) {
	var postCommit func()
	err := r.rm.persistence.DB().Transaction(func(dbTX *gorm.DB) (err error) {
		postCommit, err = r.upsertRegistryRecords(ctx, dbTX, req.Entities, req.Properties)
		return err
	})
	if err != nil {
		return nil, err
	}
	postCommit()
	return &prototk.UpsertRegistryRecordsResponse{}, nil
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
	res, err := r.api.HandleRegistryEvents(ctx, &prototk.HandleRegistryEventsRequest{
		BatchId: batch.BatchID.String(),
		Events:  events,
	})
	if err != nil {
		return nil, err
	}

	// Upsert any transport details that are detected by the registry
	return r.upsertRegistryRecords(ctx, dbTX, res.Entities, res.Properties)

}

func (r *registry) upsertRegistryRecords(ctx context.Context, dbTX *gorm.DB, protoEntities []*prototk.RegistryEntity, protoProps []*prototk.RegistryProperty) (func(), error) {

	dbEntities := make([]*DBEntity, len(protoEntities))
	for i, protoEntity := range protoEntities {
		// The registry plugin code is responsible for ensuring these rules are followed
		// before pushing any data to the registry manager.
		// If the registry detects any data that is invalid according to these rules
		// published in their underlying store (such as the blockchain) it must
		// exclude it and act appropriately.
		// Otherwise the registry plugin will receive failures, and it might then stall indexing the
		// its event source in a failure loop with the registry manager.

		// The ID must be parsable as Hex bytes - this could be a 16 byte UUID formatted as plain hex,
		// or it could (more likely) be a hash of the parent_id and the name of the entry meaning
		// it is unique within the whole registry scope.
		entityID, err := tktypes.ParseHexBytes(ctx, protoEntity.Id)
		if err != nil || len(entityID) == 0 {
			return nil, i18n.WrapError(ctx, err, msgs.MsgRegistryInvalidEntityID, protoEntity.Id)
		}

		// Names must meet the criteria that is set out in tktypes.PrivateIdentityLocator for use
		// as a node name. That is not to say this is the only use of entities, but applying this
		// common rule to all entity names ensures we meet the criteria of node names.
		nodeName, err := tktypes.PrivateIdentityLocator(protoEntity.Name).Node(ctx, false)
		if err != nil || nodeName != protoEntity.Name {
			return nil, i18n.WrapError(ctx, err, msgs.MsgRegistryInvalidEntityName, protoEntity.Name)
		}

		dbe := &DBEntity{
			Registry: r.name,
			ID:       entityID,
			Name:     protoEntity.Name,
			Active:   protoEntity.Active,
		}
		if protoEntity.Location != nil {
			dbe.BlockNumber = &protoEntity.Location.BlockNumber
			dbe.TransactionIndex = &protoEntity.Location.LogIndex
			dbe.LogIndex = &protoEntity.Location.LogIndex
		}
		dbEntities[i] = dbe
	}

	dbProps := make([]*DBProperty, len(protoProps))
	for i, protoProp := range protoProps {

		// DB will check for relationship to entity, but we need to parse the ID consistently into bytes
		entityID, err := tktypes.ParseHexBytes(ctx, protoProp.EntityId)
		if err != nil || len(entityID) == 0 {
			return nil, i18n.WrapError(ctx, err, msgs.MsgRegistryInvalidEntityID, protoProp.EntityId)
		}

		// Much more relaxed here about what goes into a property name and value
		// Any restrictions on that are down to the registry plugin alone.
		// Note all properties are stored and filtered as text - there is no
		// concept of an integer-sorted property (none of the complexity we support
		// with schema typing in the state store)
		dbp := &DBProperty{
			Registry: r.name,
			EntityID: entityID,
			Name:     protoProp.Name,
			Active:   protoProp.Active,
			Value:    protoProp.Value,
		}
		if protoProp.Location != nil {
			dbp.BlockNumber = &protoProp.Location.BlockNumber
			dbp.TransactionIndex = &protoProp.Location.LogIndex
			dbp.LogIndex = &protoProp.Location.LogIndex
		}
		dbProps[i] = dbp
	}

	var err error

	if len(dbEntities) > 0 {
		err = dbTX.
			WithContext(ctx).
			Table("registry_entities").
			Clauses(clause.OnConflict{
				Columns: []clause.Column{
					{Name: "registry"},
					{Name: "id"},
				},
				DoUpdates: clause.AssignmentColumns([]string{
					"updated",
					"active", // this is the primary thing that can actually be mutated
					"block_number",
					"transaction_index",
					"log_index",
				}),
				Where: clause.Where{
					// protect against a theoretical issue that could exist with plugins that they
					// don't protect against this sufficiently in the ID generation
					Exprs: []clause.Expression{clause.Eq{Column: "parent_id", Value: "EXCLUDED.parent_id"}},
				},
			}).
			Create(dbEntities).
			Error
	}

	if len(dbProps) > 0 {
		err = dbTX.
			WithContext(ctx).
			Table("registry_properties").
			Clauses(clause.OnConflict{
				Columns: []clause.Column{
					{Name: "registry"},
					{Name: "entity_id"},
					{Name: "name"},
				},
				DoUpdates: clause.AssignmentColumns([]string{
					"updated",
					"active",
					"value",
					"block_number",
					"transaction_index",
					"log_index",
				}),
			}).
			Create(dbProps).
			Error
	}

	if err != nil {
		return nil, err
	}

	return func() {
		// It's a lot of work to determine which parts of the node transport cache are affected,
		// as the upserts above happen simply by storing properties that might/might-not match
		// queries that resolve node transports to names.
		//
		// So instead we just zap the whole cache when we have an update.
		r.rm.transportDetailsCache.Clear()
	}, nil
}

func (r *registry) close() {
	r.cancelCtx()
	<-r.initDone
}
