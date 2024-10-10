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
	"github.com/kaleido-io/paladin/core/internal/filters"
	"github.com/kaleido-io/paladin/core/internal/msgs"
	"github.com/kaleido-io/paladin/core/pkg/blockindexer"
	"github.com/kaleido-io/paladin/toolkit/pkg/log"
	"github.com/kaleido-io/paladin/toolkit/pkg/prototk"
	"github.com/kaleido-io/paladin/toolkit/pkg/query"
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

		// We require the names of properties to conform to rules, so that we can distinguish
		// these properties from our ".id", ".created", ".updated" properties.
		// Note as above it is the registry plugin's responsibility to handle cases where a
		// value that does not conform is published to it (by logging and discarding it etc.)
		if err := tktypes.ValidateSafeCharsStartEndAlphaNum(ctx, protoProp.Name, tktypes.DefaultNameMaxLen, protoProp.Name); err != nil {
			return nil, i18n.WrapError(ctx, err, msgs.MsgRegistryInvalidPropertyName, protoProp.Name)
		}

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

type dynamicFieldSet struct {
	props       []string
	propIndexes map[string]int
}

// Track which fields are used in the query, as we create a dynamic join for each
func (dfs *dynamicFieldSet) ResolverFor(propName string) filters.FieldResolver {
	switch propName {
	case ".id":
		return filters.HexBytesField(`"registry_entities"."id"`)
	case ".created":
		return filters.TimestampField(`"registry_entities"."created"`)
	case ".updated":
		return filters.TimestampField(`"registry_entities"."updated"`)
	}

	idx, exists := dfs.propIndexes[propName]
	if !exists {
		idx = len(dfs.props)
		dfs.propIndexes[propName] = idx
		dfs.props = append(dfs.props, propName)
	}
	return filters.StringField(fmt.Sprintf("p%d.value", idx))
}

func (r *registry) QueryEntities(ctx context.Context, dbTX *gorm.DB, fActive components.ActiveFilter, jq *query.QueryJSON) ([]*components.RegistryEntity, error) {

	dfs := &dynamicFieldSet{propIndexes: make(map[string]int)}

	q := filters.BuildGORM(ctx, jq,
		dbTX.WithContext(ctx).
			Table("registry_entities").
			Where(`"registry_entities"."registry" = ?`, r.name),
		dfs)

	switch fActive {
	case components.ActiveFilterAny: // no filter
	case components.ActiveFilterInactive:
		q = q.Where(`"registry_entities"."active" IS FALSE`)
	case components.ActiveFilterActive:
		fallthrough
	default:
		q = q.Where(`"registry_entities"."active" IS TRUE`)
	}

	// After BuildGORM completes, dfs will have a list of all the fields used in the query.
	// We create a join to a virtual column for each.
	for idx, prop := range dfs.props {
		q = q.Joins(fmt.Sprintf(
			// The property might not exist, so LEFT JOIN (assured to be zero or one),
			// this will give us NULL for unset properties.
			`LEFT JOIN registry_properties AS p%[1]d `+
				`ON p%[1]d.registry = ? `+
				`ON p%[1]d.active IS TRUE `+ // only select on active props, regardless of active query on entity
				`ON p%[1]d.entity_id = "registry_entities"."id" `+
				`AND p%[1]d.name = ?`, idx),
			r.name,
			prop)
	}

	var dbEntities []*DBEntity
	err := q.Find(&dbEntities).Error
	if err != nil {
		return nil, err
	}

	entities := make([]*components.RegistryEntity, len(dbEntities))
	for i, dbe := range dbEntities {
		entity := &components.RegistryEntity{
			Registry: dbe.Registry,
			ID:       dbe.ID,
			Name:     dbe.Name,
		}
		// Return nil (not empty) for parent string here - this avoids DB index complexity with null values
		if len(dbe.ParentID) > 0 {
			entity.ParentID = dbe.ParentID
		}
		// Return active if explicitly included in query
		if fActive != components.ActiveFilterActive {
			entity.ActiveFlag = &components.ActiveFlag{Active: dbe.Active}
		}
		// For block info, our insert logic ensures if one is set they are all set
		if dbe.BlockNumber != nil {
			entity.OnChainLocation = &components.OnChainLocation{
				BlockNumber:      *dbe.BlockNumber,
				TransactionIndex: *dbe.TransactionIndex,
				LogIndex:         *dbe.TransactionIndex,
			}
		}
		entities[i] = entity
	}

	return entities, nil

}

func (r *registry) GetEntityProperties(ctx context.Context, dbTX *gorm.DB, fActive components.ActiveFilter, entityIDs ...tktypes.HexBytes) ([]*components.RegistryProperty, error) {

	var dbProps []*DBProperty
	q := dbTX.WithContext(ctx).
		Table("registry_properties").
		Where("registry = ?", r.name).
		Where("entity_id IN (?)", entityIDs)

	switch fActive {
	case components.ActiveFilterAny: // no filter
	case components.ActiveFilterInactive:
		q = q.Where("active IS FALSE")
	case components.ActiveFilterActive:
		fallthrough
	default:
		q = q.Where("active IS TRUE")
	}

	err := q.Find(&dbProps).Error
	if err != nil {
		return nil, err
	}

	props := make([]*components.RegistryProperty, len(dbProps))
	for i, dbp := range dbProps {
		prop := &components.RegistryProperty{
			Registry: dbp.Registry,
			EntityID: dbp.EntityID,
			Name:     dbp.Name,
			Value:    dbp.Value,
		}
		// Return active if the query was anything apart from the active query
		if fActive != components.ActiveFilterActive {
			prop.ActiveFlag = &components.ActiveFlag{Active: dbp.Active}
		}
		// For block info, our insert logic ensures if one is set they are all set
		if dbp.BlockNumber != nil {
			prop.OnChainLocation = &components.OnChainLocation{
				BlockNumber:      *dbp.BlockNumber,
				TransactionIndex: *dbp.TransactionIndex,
				LogIndex:         *dbp.TransactionIndex,
			}
		}
		props[i] = prop
	}

	return props, nil

}

func (r *registry) QueryEntitiesWithProps(ctx context.Context, dbTX *gorm.DB, fActive components.ActiveFilter, jq *query.QueryJSON) ([]*components.RegistryEntityWithProperties, error) {

	entities, err := r.QueryEntities(ctx, dbTX, fActive, jq)
	if err != nil {
		return nil, err
	}

	entityIDs := make([]tktypes.HexBytes, len(entities))
	for i, e := range entities {
		entityIDs[i] = e.ID
	}

	entityProps, err := r.GetEntityProperties(ctx, dbTX, components.ActiveFilterActive /* still active props regardless of filter on active for entity */, entityIDs...)
	if err != nil {
		return nil, err
	}

	withProps := make([]*components.RegistryEntityWithProperties, len(entities))
	for i, e := range entities {
		props := make(map[string]string)
		for _, p := range entityProps {
			if p.EntityID.Equals(e.ID) {
				props[p.Name] = p.Value
			}
		}
		withProps[i] = &components.RegistryEntityWithProperties{
			RegistryEntity: e,
			Properties:     props,
		}
	}

	return withProps, nil
}

func (r *registry) close() {
	r.cancelCtx()
	<-r.initDone
}
