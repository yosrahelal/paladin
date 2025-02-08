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

package groupmgr

import (
	"context"

	"github.com/hyperledger/firefly-signer/pkg/abi"
	"github.com/kaleido-io/paladin/config/pkg/pldconf"
	"github.com/kaleido-io/paladin/core/internal/components"
	"github.com/kaleido-io/paladin/core/internal/msgs"
	"github.com/kaleido-io/paladin/core/pkg/persistence"

	"github.com/kaleido-io/paladin/toolkit/pkg/i18n"
	"github.com/kaleido-io/paladin/toolkit/pkg/pldapi"
	"github.com/kaleido-io/paladin/toolkit/pkg/query"
	"github.com/kaleido-io/paladin/toolkit/pkg/rpcserver"
	"github.com/kaleido-io/paladin/toolkit/pkg/tktypes"
)

type groupManager struct {
	bgCtx     context.Context
	cancelCtx context.CancelFunc

	rpcModule *rpcserver.RPCModule
	conf      *pldconf.GroupManagerConfig

	stateManager     components.StateManager
	domainManager    components.DomainManager
	transportManager components.TransportManager
	registryManager  components.RegistryManager
	persistence      persistence.Persistence
}

type persistedGroup struct {
	Domain          string            `gorm:"column:domain;primaryKey"`
	ID              tktypes.HexBytes  `gorm:"column:id;primaryKey"`
	Created         tktypes.Timestamp `gorm:"column:created"`
	SchemaID        tktypes.Bytes32   `gorm:"column:schema_id"`
	SchemaSignature string            `gorm:"column:schema_signature"`
}

func (pg persistedGroup) TableName() string {
	return "privacy_groups"
}

type persistedGroupMember struct {
	Group    tktypes.HexBytes `gorm:"column:group;primaryKey"`
	Domain   string           `gorm:"column:domain;primaryKey"`
	Identity string           `gorm:"column:identity"`
}

func (pgm persistedGroupMember) TableName() string {
	return "privacy_group_members"
}

func NewGroupManager(bgCtx context.Context, conf *pldconf.GroupManagerConfig) components.GroupManager {
	gm := &groupManager{
		conf: conf,
	}
	gm.bgCtx, gm.cancelCtx = context.WithCancel(bgCtx)
	return gm
}

func (gm *groupManager) PreInit(pic components.PreInitComponents) (*components.ManagerInitResult, error) {
	gm.initRPC()
	return &components.ManagerInitResult{
		RPCModules: []*rpcserver.RPCModule{gm.rpcModule},
	}, nil
}

func (gm *groupManager) PostInit(c components.AllComponents) error {
	gm.stateManager = c.StateManager()
	gm.domainManager = c.DomainManager()
	gm.persistence = c.Persistence()
	gm.transportManager = c.TransportManager()
	gm.registryManager = c.RegistryManager()
	return nil
}

func (gm *groupManager) Start() error {
	return nil
}

func (gm *groupManager) Stop() {
	gm.cancelCtx()
}

func (gm *groupManager) validateProperties(ctx context.Context, spec *pldapi.PrivacyGroupInput) (err error) {

	// If no specific ABI has been provided for the input properties, we infer one from the properties
	// that have been supplied. For example if `{"name": "group1", "transaction": "dvp-12345"}` is supplied in the properties, we would
	// infer a properties ABI spec of:
	//
	//  [ { "name": "name", "type": "string", "indexed": true }, { "name": "transaction", "type": "string", "indexed": true } ]
	//
	// Noting details in the ABIInferenceFromJSON() implementation on constraints, and field ordering etc.
	schemaGenerated := false
	if spec.PropertiesABI == nil {
		schemaGenerated = true
		spec.PropertiesABI, err = tktypes.ABIInferenceFromJSON(ctx, spec.Properties)
		if err != nil {
			return err
		}
	}

	// Now we do standardized formatting of the properties back again into the data we pass to the domain.
	// This validates that edge cases are handled (such as mixed arrays in the input properties, which are not supported with ABI inference).
	// It also standardizes the structure of the data format that is passed to the domain code, prior to the full state ABI/data being stored.
	cv, err := spec.PropertiesABI.ParseJSONCtx(ctx, spec.Properties)
	if err == nil {
		spec.Properties, err = tktypes.StandardABISerializer().SerializeJSONCtx(ctx, cv)
	}
	if err != nil {
		return i18n.WrapError(ctx, err, msgs.MsgPGroupsDataDoesNotMatchSchema, schemaGenerated)
	}

	return nil

}

func (gm *groupManager) validateMembers(ctx context.Context, members []string) (err error) {
	localNode := gm.transportManager.LocalNodeName()
	validatedNodes := make(map[string]bool)
	if len(members) == 0 {
		return i18n.NewError(ctx, msgs.MsgPGroupsNoMembers)
	}
	for _, m := range members {
		_, node, err := tktypes.PrivateIdentityLocator(m).Validate(ctx, "", false)
		if err != nil {
			return err
		}
		// Validate we know about a registered transport for the node (for all non-local nodes)
		if node != localNode && !validatedNodes[node] {
			_, err := gm.registryManager.GetNodeTransports(ctx, node)
			if err != nil {
				return err
			}
			validatedNodes[node] = true
		}
	}
	return nil
}

func (gm *groupManager) insertGroup(ctx context.Context, dbTX persistence.DBTX, pg *persistedGroup, members []string) error {
	err := dbTX.DB().WithContext(ctx).Create(pg).Error
	if err == nil {
		pgms := make([]*persistedGroupMember, len(members))
		for i, identity := range members {
			pgms[i] = &persistedGroupMember{
				Domain:   pg.Domain,
				Group:    pg.ID,
				Identity: identity,
			}
		}
		err = dbTX.DB().WithContext(ctx).
			Create(pgms).
			Error
	}
	return err
}

func (gm *groupManager) CreateGroup(ctx context.Context, dbTX persistence.DBTX, spec *pldapi.PrivacyGroupInput) (id tktypes.HexBytes, err error) {

	// Do local validation of the supplied properties
	if err := gm.validateProperties(ctx, spec); err != nil {
		return nil, err
	}

	// Validate the members
	if err := gm.validateMembers(ctx, spec.Members); err != nil {
		return nil, err
	}

	// Get the domain
	domain, err := gm.domainManager.GetDomainByName(ctx, spec.Domain)
	if err != nil {
		return nil, err
	}

	// Now we can ask the domain code to take the input properties, and validated members, and come back with the
	// complete genesis state object for the group
	genesis, genesisSchema, err := domain.InitPrivacyGroup(ctx, spec)
	if err != nil {
		return nil, err
	}

	// We need to ensure the ABI exists, before we can store the state
	stateABIs, err := gm.stateManager.EnsureABISchemas(ctx, dbTX, spec.Domain, []*abi.Parameter{genesisSchema})
	if err != nil {
		return nil, err
	}
	genesisSchemaID := stateABIs[0].ID()

	// Now we can upsert the state, to get the ID of the group from the state hash.
	states, err := gm.stateManager.WriteReceivedStates(ctx, dbTX, spec.Domain, []*components.StateUpsertOutsideContext{
		{
			SchemaID: genesisSchemaID,
			Data:     genesis,
			// Note there is no contract address associated with this state - as it comes into existence before the deploy
		},
	})
	if err != nil {
		return nil, err
	}
	id = states[0].ID

	// We have the privacy group, and the state, so we can store all of these in the DB transaction - along with a reliable
	// message transfer to all the parties in the group so they get notification it's there.
	err = gm.insertGroup(ctx, dbTX, &persistedGroup{
		ID:              id,
		Created:         tktypes.TimestampNow(),
		Domain:          spec.Domain,
		SchemaID:        genesisSchemaID,
		SchemaSignature: stateABIs[0].Signature(),
	}, spec.Members)
	if err != nil {
		return nil, err
	}

	return id, nil
}

func (gm *groupManager) QueryGroups(ctx context.Context, dbTX persistence.DBTX, jq *query.QueryJSON) ([]*pldapi.PrivacyGroup, error) {
	// TODO: implement
	return nil, nil
}
