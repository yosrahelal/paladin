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

	"github.com/kaleido-io/paladin/core/internal/privatetxnmgr/ptmgrtypes"
)

type IdentityResolver interface {
	IsCurrentNode(nodeID string) bool
	ConnectToBaseLeger() error // TODO: does this function connects to the base ledger of current node/any available node as well? How about events?
	GetDispatchAddress(preferredAddresses []string) string
}
type DependencyChecker interface {
	PreReqsMatchCondition(ctx context.Context, preReqTxIDs []string, conditionFunc func(tsg TxStateGetters) (preReqComplete bool)) (filteredPreReqTxIDs []string)
	GetPreReqDispatchAddresses(ctx context.Context, preReqTxIDs []string) (dispatchAddresses []string)
	RegisterPreReqTrigger(ctx context.Context, txID string, txPreReq *ptmgrtypes.TxProcessPreReq)
}
