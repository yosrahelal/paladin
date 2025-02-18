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

package pldclient

import (
	"context"

	"github.com/google/uuid"
	"github.com/kaleido-io/paladin/toolkit/pkg/pldapi"
	"github.com/kaleido-io/paladin/toolkit/pkg/query"
	"github.com/kaleido-io/paladin/toolkit/pkg/tktypes"
)

type PrivacyGroups interface {
	RPCModule

	CreateGroup(ctx context.Context, spec *pldapi.PrivacyGroupInput) (id tktypes.HexBytes, err error)
	GetGroupById(ctx context.Context, domainName string, id tktypes.HexBytes) (group *pldapi.PrivacyGroupWithABI, err error)
	QueryGroups(ctx context.Context, jq *query.QueryJSON) (groups []*pldapi.PrivacyGroup, err error)
	QueryGroupsByProperties(ctx context.Context, domainName string, schemaID tktypes.Bytes32, jq *query.QueryJSON) (groups []*pldapi.PrivacyGroup, err error)
	SendTransaction(ctx context.Context, tx *pldapi.PrivacyGroupTransactionInput) (txID uuid.UUID, err error)
	Call(ctx context.Context, call *pldapi.PrivacyGroupTransactionCall) (data tktypes.RawJSON, err error)
}

// This is necessary because there's no way to introspect function parameter names via reflection
var privacyGroupsInfo = &rpcModuleInfo{
	group: "pgroup",
	methodInfo: map[string]RPCMethodInfo{
		"pgroup_createGroup": {
			Inputs: []string{"spec"},
			Output: "id",
		},
		"pgroup_getGroupById": {
			Inputs: []string{"domainName", "id"},
			Output: "pgroup",
		},
		"pgroup_queryGroups": {
			Inputs: []string{"query"},
			Output: "pgroups",
		},
		"pgroup_queryGroupsByProperties": {
			Inputs: []string{"domainName", "schemaId", "query"},
			Output: "pgroups",
		},
		"pgroup_sendTransaction": {
			Inputs: []string{"tx"},
			Output: "transactionId",
		},
		"pgroup_call": {
			Inputs: []string{"call"},
			Output: "data",
		},
	},
}

type pgroup struct {
	*rpcModuleInfo
	c *paladinClient
}

func (c *paladinClient) PrivacyGroups() PrivacyGroups {
	return &pgroup{rpcModuleInfo: privacyGroupsInfo, c: c}
}

func (r *pgroup) CreateGroup(ctx context.Context, spec *pldapi.PrivacyGroupInput) (id tktypes.HexBytes, err error) {
	err = r.c.CallRPC(ctx, &id, "pgroup_createGroup", spec)
	return
}

func (r *pgroup) GetGroupById(ctx context.Context, domainName string, id tktypes.HexBytes) (group *pldapi.PrivacyGroupWithABI, err error) {
	err = r.c.CallRPC(ctx, &group, "pgroup_getGroupById", domainName, id)
	return
}

func (r *pgroup) QueryGroups(ctx context.Context, jq *query.QueryJSON) (groups []*pldapi.PrivacyGroup, err error) {
	err = r.c.CallRPC(ctx, &groups, "pgroup_queryGroups", jq)
	return
}

func (r *pgroup) QueryGroupsByProperties(ctx context.Context, domainName string, schemaID tktypes.Bytes32, jq *query.QueryJSON) (groups []*pldapi.PrivacyGroup, err error) {
	err = r.c.CallRPC(ctx, &groups, "pgroup_queryGroupsByProperties", domainName, schemaID, jq)
	return
}

func (r *pgroup) SendTransaction(ctx context.Context, tx *pldapi.PrivacyGroupTransactionInput) (txID uuid.UUID, err error) {
	err = r.c.CallRPC(ctx, &txID, "pgroup_sendTransaction", tx)
	return
}

func (r *pgroup) Call(ctx context.Context, call *pldapi.PrivacyGroupTransactionCall) (data tktypes.RawJSON, err error) {
	err = r.c.CallRPC(ctx, &data, "pgroup_call", call)
	return
}
