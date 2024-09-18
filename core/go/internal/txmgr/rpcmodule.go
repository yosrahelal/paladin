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

package txmgr

import (
	"context"

	"github.com/google/uuid"
	"github.com/hyperledger/firefly-signer/pkg/abi"
	"github.com/kaleido-io/paladin/core/internal/rpcserver"
	"github.com/kaleido-io/paladin/toolkit/pkg/ptxapi"
	"github.com/kaleido-io/paladin/toolkit/pkg/query"
	"github.com/kaleido-io/paladin/toolkit/pkg/tktypes"
)

func (tm *txManager) buildRPCModule() {
	tm.rpcModule = rpcserver.NewRPCModule("ptx").
		Add("ptx_sendTransaction", tm.rpcSendTransaction()).
		Add("ptx_getTransaction", tm.rpcGetTransaction()).
		Add("ptx_queryTransactions", tm.rpcQueryTransactions()).
		Add("ptx_storeABI", tm.rpcStoreABI()).
		Add("ptx_getABI", tm.rpcGetABI()).
		Add("ptx_queryABIs", tm.rpcQueryABIs())
}

func (tm *txManager) rpcSendTransaction() rpcserver.RPCHandler {
	return rpcserver.RPCMethod1(func(ctx context.Context,
		tx ptxapi.TransactionInput,
	) (*uuid.UUID, error) {
		return tm.sendTransaction(ctx, &tx)
	})
}

func (tm *txManager) rpcGetTransaction() rpcserver.RPCHandler {
	return rpcserver.RPCMethod2(func(ctx context.Context,
		id uuid.UUID,
		full bool,
	) (any, error) {
		if full {
			return tm.getTransactionByIDFull(ctx, id)
		}
		return tm.getTransactionByID(ctx, id)
	})
}

func (tm *txManager) rpcQueryTransactions() rpcserver.RPCHandler {
	return rpcserver.RPCMethod2(func(ctx context.Context,
		query query.QueryJSON,
		full bool,
	) (any, error) {
		if full {
			return tm.queryTransactionsFull(ctx, &query)
		}
		return tm.queryTransactions(ctx, &query)
	})
}

func (tm *txManager) rpcStoreABI() rpcserver.RPCHandler {
	return rpcserver.RPCMethod1(func(ctx context.Context,
		a abi.ABI,
	) (*tktypes.Bytes32, error) {
		pa, err := tm.upsertABI(ctx, a)
		if err != nil {
			return nil, err
		}
		return &pa.Hash, nil
	})
}

func (tm *txManager) rpcGetABI() rpcserver.RPCHandler {
	return rpcserver.RPCMethod1(func(ctx context.Context,
		hash tktypes.Bytes32,
	) (*ptxapi.StoredABI, error) {
		return tm.getABIByHash(ctx, hash)
	})
}

func (tm *txManager) rpcQueryABIs() rpcserver.RPCHandler {
	return rpcserver.RPCMethod1(func(ctx context.Context,
		query query.QueryJSON,
	) ([]*ptxapi.StoredABI, error) {
		return tm.queryABIs(ctx, &query)
	})
}
