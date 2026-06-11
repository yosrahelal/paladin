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

	"github.com/LFDT-Paladin/paladin/common/go/pkg/log"
	"github.com/LFDT-Paladin/paladin/sdk/go/pkg/pldapi"
	"github.com/LFDT-Paladin/paladin/sdk/go/pkg/pldtypes"
	"github.com/LFDT-Paladin/paladin/sdk/go/pkg/query"
	"github.com/LFDT-Paladin/paladin/toolkit/pkg/rpcclient"
	"github.com/LFDT-Paladin/paladin/toolkit/pkg/rpcserver"
	"github.com/hyperledger/firefly-signer/pkg/abi"
)

func (bi *blockIndexer) RPCModule() *rpcserver.RPCModule {
	return bi.rpcModule
}

func (bi *blockIndexer) initRPC() {
	bi.rpcModule = rpcserver.NewRPCModule("bidx").
		Add("bidx_getBlockByNumber", bi.rpcGetBlockByNumber()).
		Add("bidx_getTransactionByHash", bi.rpcGetTransactionByHash()).
		Add("bidx_getTransactionByNonce", bi.rpcGetTransactionByNonce()).
		Add("bidx_getBlockTransactionsByNumber", bi.rpcGetBlockTransactionsByNumber()).
		Add("bidx_getTransactionEventsByHash", bi.rpcGetTransactionEventsByHash()).
		Add("bidx_queryIndexedBlocks", bi.rpcQueryIndexedBlocks()).
		Add("bidx_queryIndexedTransactions", bi.rpcQueryIndexedTransactions()).
		Add("bidx_queryIndexedEvents", bi.rpcQueryIndexedEvents()).
		Add("bidx_getConfirmedBlockHeight", bi.rpcGetConfirmedBlockHeight()).
		Add("bidx_decodeTransactionEvents", bi.rpcDecodeTransactionEvents())
}

func (bi *blockIndexer) rpcGetBlockByNumber() rpcserver.RPCHandler {
	return rpcserver.RPCMethod1(func(ctx context.Context,
		number pldtypes.HexUint64,
	) (*pldapi.IndexedBlock, rpcclient.RPCCode, error) {
		ctx = log.WithComponent(ctx, "blockindexer")
		block, err := bi.GetIndexedBlockByNumber(ctx, number.Uint64())
		return block, 0, err
	})
}

func (bi *blockIndexer) rpcGetTransactionByHash() rpcserver.RPCHandler {
	return rpcserver.RPCMethod1(func(ctx context.Context,
		hash pldtypes.Bytes32,
	) (*pldapi.IndexedTransaction, rpcclient.RPCCode, error) {
		ctx = log.WithComponent(ctx, "blockindexer")
		transaction, err := bi.GetIndexedTransactionByHash(ctx, hash)
		return transaction, 0, err
	})
}

func (bi *blockIndexer) rpcGetTransactionByNonce() rpcserver.RPCHandler {
	return rpcserver.RPCMethod2(func(ctx context.Context,
		from pldtypes.EthAddress,
		nonce pldtypes.HexUint64,
	) (*pldapi.IndexedTransaction, rpcclient.RPCCode, error) {
		transaction, err := bi.GetIndexedTransactionByNonce(ctx, from, nonce.Uint64())
		return transaction, 0, err
	})
}

func (bi *blockIndexer) rpcGetBlockTransactionsByNumber() rpcserver.RPCHandler {
	return rpcserver.RPCMethod1(func(ctx context.Context,
		blockNumber pldtypes.HexUint64,
	) ([]*pldapi.IndexedTransaction, rpcclient.RPCCode, error) {
		ctx = log.WithComponent(ctx, "blockindexer")
		transactions, err := bi.GetBlockTransactionsByNumber(ctx, int64(blockNumber.Uint64()))
		return transactions, 0, err
	})
}

func (bi *blockIndexer) rpcGetTransactionEventsByHash() rpcserver.RPCHandler {
	return rpcserver.RPCMethod1(func(ctx context.Context,
		hash pldtypes.Bytes32,
	) ([]*pldapi.IndexedEvent, rpcclient.RPCCode, error) {
		ctx = log.WithComponent(ctx, "blockindexer")
		events, err := bi.GetTransactionEventsByHash(ctx, hash)
		return events, 0, err
	})
}

func (bi *blockIndexer) rpcGetConfirmedBlockHeight() rpcserver.RPCHandler {
	return rpcserver.RPCMethod0(func(ctx context.Context,
	) (pldtypes.HexUint64, rpcclient.RPCCode, error) {
		ctx = log.WithComponent(ctx, "blockindexer")
		blockHeight, err := bi.GetConfirmedBlockHeight(ctx)
		return blockHeight, 0, err
	})
}

func (bi *blockIndexer) rpcQueryIndexedBlocks() rpcserver.RPCHandler {
	return rpcserver.RPCMethod1(func(ctx context.Context,
		jq query.QueryJSON,
	) ([]*pldapi.IndexedBlock, rpcclient.RPCCode, error) {
		ctx = log.WithComponent(ctx, "blockindexer")
		blocks, err := bi.QueryIndexedBlocks(ctx, &jq)
		return blocks, 0, err
	})
}

func (bi *blockIndexer) rpcQueryIndexedTransactions() rpcserver.RPCHandler {
	return rpcserver.RPCMethod1(func(ctx context.Context,
		jq query.QueryJSON,
	) ([]*pldapi.IndexedTransaction, rpcclient.RPCCode, error) {
		ctx = log.WithComponent(ctx, "blockindexer")
		transactions, err := bi.QueryIndexedTransactions(ctx, &jq)
		return transactions, 0, err
	})
}

func (bi *blockIndexer) rpcQueryIndexedEvents() rpcserver.RPCHandler {
	return rpcserver.RPCMethod1(func(ctx context.Context,
		jq query.QueryJSON,
	) ([]*pldapi.IndexedEvent, rpcclient.RPCCode, error) {
		ctx = log.WithComponent(ctx, "blockindexer")
		events, err := bi.QueryIndexedEvents(ctx, &jq)
		return events, 0, err
	})
}

func (bi *blockIndexer) rpcDecodeTransactionEvents() rpcserver.RPCHandler {
	return rpcserver.RPCMethod3(func(ctx context.Context,
		hash pldtypes.Bytes32,
		abi abi.ABI,
		resultFormat pldtypes.JSONFormatOptions,
	) ([]*pldapi.EventWithData, rpcclient.RPCCode, error) {
		ctx = log.WithComponent(ctx, "blockindexer")
		events, err := bi.DecodeTransactionEvents(ctx, hash, abi, resultFormat)
		return events, 0, err
	})
}
