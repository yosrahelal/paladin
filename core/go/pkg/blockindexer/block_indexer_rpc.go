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

package blockindexer

import (
	"context"

	"github.com/kaleido-io/paladin/toolkit/pkg/rpcserver"
	"github.com/kaleido-io/paladin/toolkit/pkg/tktypes"
)

func (bi *blockIndexer) RPCModule() *rpcserver.RPCModule {
	return bi.rpcModule
}

func (bi *blockIndexer) initRPC() {
	bi.rpcModule = rpcserver.NewRPCModule("bidx").
		Add("bidx_GetIndexedBlockByNumber", bi.rpcGetIndexedBlockByNumber()).
		Add("bidx_GetIndexedBlockByNumber", bi.rpcGetIndexedTransactionByHash()).
		Add("bidx_GetIndexedTransactionByNonce", bi.rpcGetIndexedTransactionByNonce()).
		Add("bidx_GetBlockTransactionsByNumber", bi.rpcGetBlockTransactionsByNumber()).
		Add("bidx_GetTransactionEventsByHash", bi.rpcGetTransactionEventsByHash()).
		Add("bidx_ListTransactionEvents", bi.rpcListTransactionEvents())
}

func (bi *blockIndexer) rpcGetIndexedBlockByNumber() rpcserver.RPCHandler {
	return rpcserver.RPCMethod1(func(ctx context.Context,
		number uint64,
	) (*IndexedBlock, error) {
		return bi.GetIndexedBlockByNumber(ctx, number)
	})
}

func (bi *blockIndexer) rpcGetIndexedTransactionByHash() rpcserver.RPCHandler {
	return rpcserver.RPCMethod1(func(ctx context.Context,
		hash tktypes.Bytes32,
	) (*IndexedTransaction, error) {
		return bi.GetIndexedTransactionByHash(ctx, hash)
	})
}

func (bi *blockIndexer) rpcGetIndexedTransactionByNonce() rpcserver.RPCHandler {
	return rpcserver.RPCMethod2(func(ctx context.Context,
		from tktypes.EthAddress,
		nonce uint64,
	) (*IndexedTransaction, error) {
		return bi.GetIndexedTransactionByNonce(ctx, from, nonce)
	})
}

func (bi *blockIndexer) rpcGetBlockTransactionsByNumber() rpcserver.RPCHandler {
	return rpcserver.RPCMethod1(func(ctx context.Context,
		blockNumber int64,
	) ([]*IndexedTransaction, error) {
		return bi.GetBlockTransactionsByNumber(ctx, blockNumber)
	})
}

func (bi *blockIndexer) rpcGetTransactionEventsByHash() rpcserver.RPCHandler {
	return rpcserver.RPCMethod1(func(ctx context.Context,
		hash tktypes.Bytes32,
	) ([]*IndexedEvent, error) {
		return bi.GetTransactionEventsByHash(ctx, hash)
	})
}

func (bi *blockIndexer) rpcListTransactionEvents() rpcserver.RPCHandler {
	return rpcserver.RPCMethod5(func(ctx context.Context,
		lastBlock int64,
		lastIndex,
		limit int,
		withTransaction,
		withBlock bool,
	) ([]*IndexedEvent, error) {
		return bi.ListTransactionEvents(ctx, lastBlock, lastIndex, limit, withTransaction, withBlock)
	})
}

func (bi *blockIndexer) rpcGetConfirmedBlockHeight() rpcserver.RPCHandler {
	return rpcserver.RPCMethod0(func(ctx context.Context,
	) (uint64, error) {
		return bi.GetConfirmedBlockHeight(ctx)
	})
}
