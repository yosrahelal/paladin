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

package groupmgr

import (
	"context"

	"github.com/kaleido-io/paladin/toolkit/pkg/pldapi"
	"github.com/kaleido-io/paladin/toolkit/pkg/query"
	"github.com/kaleido-io/paladin/toolkit/pkg/rpcserver"
)

func (gm *groupManager) RPCModule() *rpcserver.RPCModule {
	return gm.rpcModule
}

func (gm *groupManager) initRPC() {
	gm.rpcModule = rpcserver.NewRPCModule("pgroup").
		Add("pgroup_queryGroups", gm.rpcQueryGroups())
}

func (gm *groupManager) rpcQueryGroups() rpcserver.RPCHandler {
	return rpcserver.RPCMethod1(func(ctx context.Context, jq query.QueryJSON) ([]*pldapi.PrivacyGroup, error) {
		return gm.QueryGroups(ctx, gm.persistence.NOTX(), &jq)
	})
}
