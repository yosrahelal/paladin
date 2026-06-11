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
	"strings"

	"github.com/LFDT-Paladin/paladin/common/go/pkg/log"
	"github.com/LFDT-Paladin/paladin/core/internal/components"
	"github.com/LFDT-Paladin/paladin/sdk/go/pkg/pldapi"
	"github.com/LFDT-Paladin/paladin/sdk/go/pkg/pldclient"
	"github.com/LFDT-Paladin/paladin/sdk/go/pkg/pldtypes"
	"github.com/LFDT-Paladin/paladin/sdk/go/pkg/query"
	"github.com/LFDT-Paladin/paladin/sdk/go/pkg/rpcclient"
	"github.com/LFDT-Paladin/paladin/toolkit/pkg/rpcserver"
	"github.com/google/uuid"
	"github.com/hyperledger/firefly-signer/pkg/abi"
)

func (tm *txManager) buildRPCModule() {
	tm.rpcModule = rpcserver.NewRPCModule("ptx").
		Add("ptx_sendTransaction", tm.rpcSendTransaction()).
		Add("ptx_sendTransactions", tm.rpcSendTransactions()).
		Add("ptx_prepareTransaction", tm.rpcPrepareTransaction()).
		Add("ptx_prepareTransactions", tm.rpcPrepareTransactions()).
		Add("ptx_updateTransaction", tm.rpcUpdateTransaction()).
		Add("ptx_call", tm.rpcCall()).
		Add("ptx_getTransaction", tm.rpcGetTransaction()).
		Add("ptx_getTransactionFull", tm.rpcGetTransactionFull()).
		Add("ptx_getTransactionByIdempotencyKey", tm.rpcGetTransactionByIdempotencyKey()).
		Add("ptx_queryTransactions", tm.rpcQueryTransactions()).
		Add("ptx_queryTransactionsFull", tm.rpcQueryTransactionsFull()).
		Add("ptx_queryPendingTransactions", tm.rpcQueryPendingTransactions()).
		Add("ptx_getTransactionReceipt", tm.rpcGetTransactionReceipt()).
		Add("ptx_getTransactionReceiptFull", tm.rpcGetTransactionReceiptFull()).
		Add("ptx_getDomainReceipt", tm.rpcGetDomainReceipt()).
		Add("ptx_getStateReceipt", tm.rpcGetStateReceipt()).
		Add("ptx_queryTransactionReceipts", tm.rpcQueryTransactionReceipts()).
		Add("ptx_getTransactionDependencies", tm.rpcGetTransactionDependencies()).
		Add("ptx_queryDispatches", tm.rpcQueryDispatches()).
		Add("ptx_getDispatch", tm.rpcGetDispatch()).
		Add("ptx_queryChainedDispatches", tm.rpcQueryChainedDispatches()).
		Add("ptx_getChainedDispatch", tm.rpcGetChainedDispatch()).
		Add("ptx_queryPublicTransactions", tm.rpcQueryPublicTransactions()).
		Add("ptx_queryPendingPublicTransactions", tm.rpcQueryPendingPublicTransactions()).
		Add("ptx_getPublicTransaction", tm.rpcGetPublicTransaction()).
		Add("ptx_getPublicTransactionByNonce", tm.rpcGetPublicTransactionByNonce()).
		Add("ptx_getPublicTransactionByHash", tm.rpcGetPublicTransactionByHash()).
		Add("ptx_getPreparedTransaction", tm.rpcGetPreparedTransaction()).
		Add("ptx_queryPreparedTransactions", tm.rpcQueryPreparedTransactions()).
		Add("ptx_storeABI", tm.rpcStoreABI()).
		Add("ptx_getStoredABI", tm.rpcGetStoredABI()).
		Add("ptx_queryStoredABIs", tm.rpcQueryStoredABIs()).
		Add("ptx_decodeCall", tm.rpcDecodeCall()).
		Add("ptx_decodeEvent", tm.rpcDecodeEvent()).
		Add("ptx_decodeError", tm.rpcDecodeError()).
		Add("ptx_resolveVerifier", tm.rpcResolveVerifier()).
		Add("ptx_createReceiptListener", tm.rpcCreateReceiptListener()).
		Add("ptx_queryReceiptListeners", tm.rpcQueryReceiptListeners()).
		Add("ptx_getReceiptListener", tm.rpcGetReceiptListener()).
		Add("ptx_startReceiptListener", tm.rpcStartReceiptListener()).
		Add("ptx_stopReceiptListener", tm.rpcStopReceiptListener()).
		Add("ptx_deleteReceiptListener", tm.rpcDeleteReceiptListener()).
		Add("ptx_createBlockchainEventListener", tm.rpcCreateBlockchainEventListener()).
		Add("ptx_queryBlockchainEventListeners", tm.rpcQueryBlockchainEventListeners()).
		Add("ptx_getBlockchainEventListener", tm.rpcGetBlockchainEventListener()).
		Add("ptx_startBlockchainEventListener", tm.rpcStartBlockchainEventListener()).
		Add("ptx_stopBlockchainEventListener", tm.rpcStopBlockchainEventListener()).
		Add("ptx_deleteBlockchainEventListener", tm.rpcDeleteBlockchainEventListener()).
		Add("ptx_getBlockchainEventListenerStatus", tm.rpcGetBlockchainEventListenerStatus()).
		AddAsync(tm.rpcEventStreams)

	tm.debugRpcModule = rpcserver.NewRPCModule("debug").
		Add("debug_getTransactionStatus", tm.rpcDebugTransactionStatus())
}

func (tm *txManager) rpcSendTransaction() rpcserver.RPCHandler {
	return rpcserver.RPCMethod1WithRPCCode(func(ctx context.Context,
		tx pldapi.TransactionInput,
	) (*uuid.UUID, rpcclient.RPCCode, error) {
		ctx = log.WithComponent(ctx, "txmanager")
		tm.metrics.IncRpc("sendTransaction")
		txID, err := tm.sendTransactionNewDBTX(ctx, &tx)
		if err != nil && strings.Contains(err.Error(), "PD012220") {
			return txID, pldclient.RPCCodeConflict, err
		}
		return txID, 0, err
	})
}

func (tm *txManager) rpcSendTransactions() rpcserver.RPCHandler {
	return rpcserver.RPCMethod1WithRPCCode(func(ctx context.Context,
		txs []*pldapi.TransactionInput,
	) ([]uuid.UUID, rpcclient.RPCCode, error) {
		ctx = log.WithComponent(ctx, "txmanager")
		tm.metrics.IncRpc("sendTransactions")
		txIDs, err := tm.sendTransactionsNewDBTX(ctx, txs)
		if err != nil && strings.Contains(err.Error(), "PD012220") {
			return txIDs, pldclient.RPCCodeConflict, err
		}
		return txIDs, 0, err
	})
}

func (tm *txManager) rpcPrepareTransaction() rpcserver.RPCHandler {
	return rpcserver.RPCMethod1(func(ctx context.Context,
		tx pldapi.TransactionInput,
	) (*uuid.UUID, error) {
		ctx = log.WithComponent(ctx, "txmanager")
		tm.metrics.IncRpc("prepareTransaction")
		txID, err := tm.prepareTransactionNewDBTX(ctx, &tx)
		return txID, err
	})
}

func (tm *txManager) rpcPrepareTransactions() rpcserver.RPCHandler {
	return rpcserver.RPCMethod1(func(ctx context.Context,
		txs []*pldapi.TransactionInput,
	) ([]uuid.UUID, error) {
		ctx = log.WithComponent(ctx, "txmanager")
		tm.metrics.IncRpc("prepareTransactions")
		txIDs, err := tm.prepareTransactionsNewDBTX(ctx, txs)
		return txIDs, err
	})
}

func (tm *txManager) rpcUpdateTransaction() rpcserver.RPCHandler {
	return rpcserver.RPCMethod2(func(ctx context.Context,
		id uuid.UUID,
		tx *pldapi.TransactionInput,
	) (uuid.UUID, error) {
		ctx = log.WithComponent(ctx, "txmanager")
		tm.metrics.IncRpc("updateTransaction")
		txID, err := tm.UpdateTransaction(ctx, id, tx)
		return txID, err
	})
}

func (tm *txManager) rpcCall() rpcserver.RPCHandler {
	return rpcserver.RPCMethod1(func(ctx context.Context,
		tx *pldapi.TransactionCall,
	) (result pldtypes.RawJSON, err error) {
		ctx = log.WithComponent(ctx, "txmanager")
		tm.metrics.IncRpc("call")
		err = tm.CallTransaction(ctx, tm.p.NOTX(), &result, tx)
		return result, err
	})
}

func (tm *txManager) rpcGetTransaction() rpcserver.RPCHandler {
	return rpcserver.RPCMethod1(func(ctx context.Context,
		id uuid.UUID,
	) (*pldapi.Transaction, error) {
		ctx = log.WithComponent(ctx, "txmanager")
		tm.metrics.IncRpc("getTransaction")
		tx, err := tm.GetTransactionByID(ctx, id)
		return tx, err
	})
}

func (tm *txManager) rpcGetTransactionFull() rpcserver.RPCHandler {
	return rpcserver.RPCMethod1(func(ctx context.Context,
		id uuid.UUID,
	) (*pldapi.TransactionFull, error) {
		ctx = log.WithComponent(ctx, "txmanager")
		tm.metrics.IncRpc("getTransactionFull")
		tx, err := tm.GetTransactionByIDFull(ctx, id)
		return tx, err
	})
}

func (tm *txManager) rpcGetTransactionByIdempotencyKey() rpcserver.RPCHandler {
	return rpcserver.RPCMethod1(func(ctx context.Context,
		idempotencyKey string,
	) (*pldapi.Transaction, error) {
		ctx = log.WithComponent(ctx, "txmanager")
		tm.metrics.IncRpc("getTransactionByIdempotencyKey")
		tx, err := tm.GetTransactionByIdempotencyKey(ctx, idempotencyKey)
		return tx, err
	})
}

func (tm *txManager) rpcQueryTransactions() rpcserver.RPCHandler {
	return rpcserver.RPCMethod1(func(ctx context.Context,
		query query.QueryJSON,
	) ([]*pldapi.Transaction, error) {
		ctx = log.WithComponent(ctx, "txmanager")
		tm.metrics.IncRpc("queryTransactions")
		txs, err := tm.QueryTransactions(ctx, &query, tm.p.NOTX(), false)
		return txs, err
	})
}

func (tm *txManager) rpcQueryTransactionsFull() rpcserver.RPCHandler {
	return rpcserver.RPCMethod1(func(ctx context.Context,
		query query.QueryJSON,
	) ([]*pldapi.TransactionFull, error) {
		ctx = log.WithComponent(ctx, "txmanager")
		tm.metrics.IncRpc("queryTransactionsFull")
		txs, err := tm.QueryTransactionsFull(ctx, &query, tm.p.NOTX(), false)
		return txs, err
	})
}

func (tm *txManager) rpcQueryPendingTransactions() rpcserver.RPCHandler {
	return rpcserver.RPCMethod2(func(ctx context.Context,
		query query.QueryJSON,
		full bool,
	) (any, error) {
		ctx = log.WithComponent(ctx, "txmanager")
		if full {
			tm.metrics.IncRpc("queryPendingTransactionsFull")
			txs, err := tm.QueryTransactionsFull(ctx, &query, tm.p.NOTX(), true)
			return txs, err
		}
		tm.metrics.IncRpc("queryPendingTransactions")
		txs, err := tm.QueryTransactions(ctx, &query, tm.p.NOTX(), true)
		return txs, err
	})
}

func (tm *txManager) rpcGetTransactionReceipt() rpcserver.RPCHandler {
	return rpcserver.RPCMethod1(func(ctx context.Context,
		id uuid.UUID,
	) (*pldapi.TransactionReceipt, error) {
		tm.metrics.IncRpc("getTransactionReceipt")
		receipt, err := tm.GetTransactionReceiptByID(ctx, id)
		return receipt, err
	})
}

func (tm *txManager) rpcGetTransactionReceiptFull() rpcserver.RPCHandler {
	return rpcserver.RPCMethod1(func(ctx context.Context,
		id uuid.UUID,
	) (*pldapi.TransactionReceiptFull, error) {
		ctx = log.WithComponent(ctx, "txmanager")
		tm.metrics.IncRpc("getTransactionReceiptFull")
		receipt, err := tm.GetTransactionReceiptByIDFull(ctx, id)
		return receipt, err
	})
}

func (tm *txManager) rpcGetPreparedTransaction() rpcserver.RPCHandler {
	return rpcserver.RPCMethod1(func(ctx context.Context,
		id uuid.UUID,
	) (*pldapi.PreparedTransaction, error) {
		ctx = log.WithComponent(ctx, "txmanager")
		tm.metrics.IncRpc("getPreparedTransaction")
		receipt, err := tm.GetPreparedTransactionByID(ctx, tm.p.NOTX(), id)
		return receipt, err
	})
}

func (tm *txManager) rpcGetDomainReceipt() rpcserver.RPCHandler {
	return rpcserver.RPCMethod2(func(ctx context.Context,
		domain string,
		id uuid.UUID,
	) (pldtypes.RawJSON, error) {
		ctx = log.WithComponent(ctx, "txmanager")
		tm.metrics.IncRpc("getDomainReceipt")
		receipt, err := tm.GetDomainReceiptByID(ctx, domain, id)
		return receipt, err
	})
}

func (tm *txManager) rpcGetStateReceipt() rpcserver.RPCHandler {
	return rpcserver.RPCMethod1(func(ctx context.Context,
		id uuid.UUID,
	) (*pldapi.TransactionStates, error) {
		ctx = log.WithComponent(ctx, "txmanager")
		tm.metrics.IncRpc("getStateReceipt")
		states, err := tm.GetStateReceiptByID(ctx, id)
		return states, err
	})
}

func (tm *txManager) rpcGetTransactionDependencies() rpcserver.RPCHandler {
	return rpcserver.RPCMethod1(func(ctx context.Context,
		id uuid.UUID,
	) (*pldapi.TransactionDependencies, error) {
		ctx = log.WithComponent(ctx, "txmanager")
		tm.metrics.IncRpc("getTransactionDependencies")
		dependencies, err := tm.GetTransactionDependencies(ctx, id)
		return dependencies, err
	})
}

func (tm *txManager) rpcQueryTransactionReceipts() rpcserver.RPCHandler {
	return rpcserver.RPCMethod1(func(ctx context.Context,
		query query.QueryJSON,
	) ([]*pldapi.TransactionReceipt, error) {
		ctx = log.WithComponent(ctx, "txmanager")
		tm.metrics.IncRpc("queryTransactionReceipts")
		receipts, err := tm.QueryTransactionReceipts(ctx, &query)
		return receipts, err
	})
}

func (tm *txManager) rpcQueryPreparedTransactions() rpcserver.RPCHandler {
	return rpcserver.RPCMethod1(func(ctx context.Context,
		query query.QueryJSON,
	) ([]*pldapi.PreparedTransaction, error) {
		ctx = log.WithComponent(ctx, "txmanager")
		tm.metrics.IncRpc("queryPreparedTransactions")
		preparedTransactions, err := tm.QueryPreparedTransactions(ctx, tm.p.NOTX(), &query)
		return preparedTransactions, err
	})
}

func (tm *txManager) rpcQueryPublicTransactions() rpcserver.RPCHandler {
	return rpcserver.RPCMethod1(func(ctx context.Context,
		query query.QueryJSON,
	) ([]*pldapi.PublicTxWithBinding, error) {
		ctx = log.WithComponent(ctx, "txmanager")
		tm.metrics.IncRpc("queryPublicTransactions")
		publicTransactions, err := tm.queryPublicTransactions(ctx, &query)
		return publicTransactions, err
	})
}

func (tm *txManager) rpcQueryPendingPublicTransactions() rpcserver.RPCHandler {
	return rpcserver.RPCMethod1(func(ctx context.Context,
		query query.QueryJSON,
	) ([]*pldapi.PublicTxWithBinding, error) {
		ctx = log.WithComponent(ctx, "txmanager")
		tm.metrics.IncRpc("queryPendingPublicTransactions")
		publicTransactions, err := tm.queryPublicTransactions(ctx, query.ToBuilder().Null("transactionHash").Query())
		return publicTransactions, err
	})
}

func (tm *txManager) rpcGetPublicTransactionByNonce() rpcserver.RPCHandler {
	return rpcserver.RPCMethod2(func(ctx context.Context,
		from pldtypes.EthAddress,
		nonce pldtypes.HexUint64,
	) (*pldapi.PublicTxWithBinding, error) {
		ctx = log.WithComponent(ctx, "txmanager")
		tm.metrics.IncRpc("getPublicTransactionByNonce")
		publicTransaction, err := tm.GetPublicTransactionByNonce(ctx, from, nonce)
		return publicTransaction, err
	})
}

func (tm *txManager) rpcGetPublicTransaction() rpcserver.RPCHandler {
	return rpcserver.RPCMethod1(func(ctx context.Context,
		id uint64,
	) (*pldapi.PublicTxWithBinding, error) {
		ctx = log.WithComponent(ctx, "txmanager")
		tm.metrics.IncRpc("getPublicTransaction")
		publicTransaction, err := tm.GetPublicTransactionByID(ctx, id)
		return publicTransaction, err
	})
}

func (tm *txManager) rpcGetPublicTransactionByHash() rpcserver.RPCHandler {
	return rpcserver.RPCMethod1(func(ctx context.Context,
		hash pldtypes.Bytes32,
	) (*pldapi.PublicTxWithBinding, error) {
		ctx = log.WithComponent(ctx, "txmanager")
		tm.metrics.IncRpc("getPublicTransactionByHash")
		publicTransaction, err := tm.GetPublicTransactionByHash(ctx, hash)
		return publicTransaction, err
	})
}

func (tm *txManager) rpcStoreABI() rpcserver.RPCHandler {
	return rpcserver.RPCMethod1(func(ctx context.Context,
		a abi.ABI,
	) (hash *pldtypes.Bytes32, err error) {
		ctx = log.WithComponent(ctx, "txmanager")
		tm.metrics.IncRpc("storeABI")
		hash, err = tm.storeABINewDBTX(ctx, a)
		return hash, err
	})
}

func (tm *txManager) rpcGetStoredABI() rpcserver.RPCHandler {
	return rpcserver.RPCMethod1(func(ctx context.Context,
		hash pldtypes.Bytes32,
	) (*pldapi.StoredABI, error) {
		ctx = log.WithComponent(ctx, "txmanager")
		tm.metrics.IncRpc("getStoredABI")
		abi, err := tm.getABIByHash(ctx, tm.p.NOTX(), hash)
		return abi, err
	})
}

func (tm *txManager) rpcQueryStoredABIs() rpcserver.RPCHandler {
	return rpcserver.RPCMethod1(func(ctx context.Context,
		query query.QueryJSON,
	) ([]*pldapi.StoredABI, error) {
		ctx = log.WithComponent(ctx, "txmanager")
		tm.metrics.IncRpc("queryStoredABIs")
		abis, err := tm.queryABIs(ctx, &query)
		return abis, err
	})
}

func (tm *txManager) rpcResolveVerifier() rpcserver.RPCHandler {
	return rpcserver.RPCMethod3(func(ctx context.Context,
		lookup string,
		algorithm string,
		verifierType string,
	) (string, error) {
		ctx = log.WithComponent(ctx, "txmanager")
		tm.metrics.IncRpc("resolveVerifier")
		verifier, err := tm.identityResolver.ResolveVerifier(ctx, lookup, algorithm, verifierType)
		return verifier, err
	})
}

func (tm *txManager) rpcDebugTransactionStatus() rpcserver.RPCHandler {
	return rpcserver.RPCMethod2(func(ctx context.Context,
		contractAddress string,
		id uuid.UUID,
	) (components.PrivateTxStatus, error) {
		ctx = log.WithComponent(ctx, "txmanager")
		tm.metrics.IncRpc("debugTransactionStatus")
		status, err := tm.sequencerMgr.GetTxStatus(ctx, contractAddress, id)
		return status, err
	})
}

func (tm *txManager) rpcDecodeError() rpcserver.RPCHandler {
	return rpcserver.RPCMethod2(func(ctx context.Context,
		revertError pldtypes.HexBytes,
		dataFormat pldtypes.JSONFormatOptions,
	) (*pldapi.ABIDecodedData, error) {
		ctx = log.WithComponent(ctx, "txmanager")
		tm.metrics.IncRpc("decodeError")
		decodedData, err := tm.DecodeRevertError(ctx, tm.p.NOTX(), revertError, dataFormat)
		return decodedData, err
	})
}

func (tm *txManager) rpcDecodeCall() rpcserver.RPCHandler {
	return rpcserver.RPCMethod2(func(ctx context.Context,
		callData pldtypes.HexBytes,
		dataFormat pldtypes.JSONFormatOptions,
	) (*pldapi.ABIDecodedData, error) {
		ctx = log.WithComponent(ctx, "txmanager")
		tm.metrics.IncRpc("decodeCall")
		decodedData, err := tm.DecodeCall(ctx, tm.p.NOTX(), callData, dataFormat)
		return decodedData, err
	})
}

func (tm *txManager) rpcDecodeEvent() rpcserver.RPCHandler {
	return rpcserver.RPCMethod3(func(ctx context.Context,
		topics []pldtypes.Bytes32,
		data pldtypes.HexBytes,
		dataFormat pldtypes.JSONFormatOptions,
	) (*pldapi.ABIDecodedData, error) {
		ctx = log.WithComponent(ctx, "txmanager")
		tm.metrics.IncRpc("decodeEvent")
		decodedData, err := tm.DecodeEvent(ctx, tm.p.NOTX(), topics, data, dataFormat)
		return decodedData, err
	})
}

func (tm *txManager) rpcCreateReceiptListener() rpcserver.RPCHandler {
	return rpcserver.RPCMethod1(func(ctx context.Context,
		listener *pldapi.TransactionReceiptListener,
	) (bool, error) {
		ctx = log.WithComponent(ctx, "txmanager")
		tm.metrics.IncRpc("createReceiptListener")
		err := tm.CreateReceiptListener(ctx, listener)
		return err == nil, err
	})
}

func (tm *txManager) rpcQueryReceiptListeners() rpcserver.RPCHandler {
	return rpcserver.RPCMethod1(func(ctx context.Context,
		query query.QueryJSON,
	) ([]*pldapi.TransactionReceiptListener, error) {
		ctx = log.WithComponent(ctx, "txmanager")
		tm.metrics.IncRpc("queryReceiptListeners")
		listeners, err := tm.QueryReceiptListeners(ctx, tm.p.NOTX(), &query)
		return listeners, err
	})
}

func (tm *txManager) rpcGetReceiptListener() rpcserver.RPCHandler {
	return rpcserver.RPCMethod1(func(ctx context.Context,
		name string,
	) (*pldapi.TransactionReceiptListener, error) {
		ctx = log.WithComponent(ctx, "txmanager")
		tm.metrics.IncRpc("getReceiptListener")
		return tm.GetReceiptListener(ctx, name), nil
	})
}

func (tm *txManager) rpcStartReceiptListener() rpcserver.RPCHandler {
	return rpcserver.RPCMethod1(func(ctx context.Context,
		name string,
	) (bool, error) {
		ctx = log.WithComponent(ctx, "txmanager")
		tm.metrics.IncRpc("startReceiptListener")
		err := tm.StartReceiptListener(ctx, name)
		return err == nil, err
	})
}

func (tm *txManager) rpcStopReceiptListener() rpcserver.RPCHandler {
	return rpcserver.RPCMethod1(func(ctx context.Context,
		name string,
	) (bool, error) {
		ctx = log.WithComponent(ctx, "txmanager")
		tm.metrics.IncRpc("stopReceiptListener")
		err := tm.StopReceiptListener(ctx, name)
		return err == nil, err
	})
}

func (tm *txManager) rpcDeleteReceiptListener() rpcserver.RPCHandler {
	return rpcserver.RPCMethod1(func(ctx context.Context,
		name string,
	) (bool, error) {
		ctx = log.WithComponent(ctx, "txmanager")
		tm.metrics.IncRpc("deleteReceiptListener")
		err := tm.DeleteReceiptListener(ctx, name)
		return err == nil, err
	})
}

func (tm *txManager) rpcCreateBlockchainEventListener() rpcserver.RPCHandler {
	return rpcserver.RPCMethod1(func(ctx context.Context,
		listener *pldapi.BlockchainEventListener,
	) (bool, error) {
		ctx = log.WithComponent(ctx, "txmanager")
		tm.metrics.IncRpc("createBlockchainEventListener")
		err := tm.CreateBlockchainEventListener(ctx, listener)
		return err == nil, err
	})
}

func (tm *txManager) rpcQueryBlockchainEventListeners() rpcserver.RPCHandler {
	return rpcserver.RPCMethod1(func(ctx context.Context,
		query query.QueryJSON,
	) ([]*pldapi.BlockchainEventListener, error) {
		ctx = log.WithComponent(ctx, "txmanager")
		tm.metrics.IncRpc("queryBlockchainEventListeners")
		listeners, err := tm.QueryBlockchainEventListeners(ctx, tm.p.NOTX(), &query)
		return listeners, err
	})
}

func (tm *txManager) rpcGetBlockchainEventListener() rpcserver.RPCHandler {
	return rpcserver.RPCMethod1(func(ctx context.Context,
		name string,
	) (*pldapi.BlockchainEventListener, error) {
		ctx = log.WithComponent(ctx, "txmanager")
		tm.metrics.IncRpc("getBlockchainEventListener")
		return tm.GetBlockchainEventListener(ctx, name), nil
	})
}

func (tm *txManager) rpcStartBlockchainEventListener() rpcserver.RPCHandler {
	return rpcserver.RPCMethod1(func(ctx context.Context,
		name string,
	) (bool, error) {
		ctx = log.WithComponent(ctx, "txmanager")
		tm.metrics.IncRpc("startBlockchainEventListener")
		err := tm.StartBlockchainEventListener(ctx, name)
		return err == nil, err
	})
}

func (tm *txManager) rpcStopBlockchainEventListener() rpcserver.RPCHandler {
	return rpcserver.RPCMethod1(func(ctx context.Context,
		name string,
	) (bool, error) {
		ctx = log.WithComponent(ctx, "txmanager")
		tm.metrics.IncRpc("stopBlockchainEventListener")
		err := tm.StopBlockchainEventListener(ctx, name)
		return err == nil, err
	})
}

func (tm *txManager) rpcDeleteBlockchainEventListener() rpcserver.RPCHandler {
	return rpcserver.RPCMethod1(func(ctx context.Context,
		name string,
	) (bool, error) {
		ctx = log.WithComponent(ctx, "txmanager")
		tm.metrics.IncRpc("deleteBlockchainEventListener")
		err := tm.DeleteBlockchainEventListener(ctx, name)
		return err == nil, err
	})
}

func (tm *txManager) rpcGetBlockchainEventListenerStatus() rpcserver.RPCHandler {
	return rpcserver.RPCMethod1(func(ctx context.Context,
		name string,
	) (*pldapi.BlockchainEventListenerStatus, error) {
		ctx = log.WithComponent(ctx, "txmanager")
		tm.metrics.IncRpc("getBlockchainEventListenerStatus")
		status, err := tm.GetBlockchainEventListenerStatus(ctx, name)
		return status, err
	})
}

func (tm *txManager) rpcQueryDispatches() rpcserver.RPCHandler {
	return rpcserver.RPCMethod1(func(ctx context.Context,
		query query.QueryJSON,
	) ([]*pldapi.Dispatch, error) {
		ctx = log.WithComponent(ctx, "txmanager")
		tm.metrics.IncRpc("queryDispatches")
		dispatches, err := tm.QueryDispatches(ctx, &query)
		return dispatches, err
	})
}

func (tm *txManager) rpcGetDispatch() rpcserver.RPCHandler {
	return rpcserver.RPCMethod1(func(ctx context.Context,
		id string,
	) (*pldapi.Dispatch, error) {
		ctx = log.WithComponent(ctx, "txmanager")
		tm.metrics.IncRpc("getDispatch")
		dispatch, err := tm.GetDispatchByID(ctx, id)
		return dispatch, err
	})
}

func (tm *txManager) rpcQueryChainedDispatches() rpcserver.RPCHandler {
	return rpcserver.RPCMethod1(func(ctx context.Context,
		query query.QueryJSON,
	) ([]*pldapi.ChainedDispatch, error) {
		ctx = log.WithComponent(ctx, "txmanager")
		tm.metrics.IncRpc("queryChainedDispatches")
		chainedDispatches, err := tm.QueryChainedDispatches(ctx, &query)
		return chainedDispatches, err
	})
}

func (tm *txManager) rpcGetChainedDispatch() rpcserver.RPCHandler {
	return rpcserver.RPCMethod1(func(ctx context.Context,
		id string,
	) (*pldapi.ChainedDispatch, error) {
		ctx = log.WithComponent(ctx, "txmanager")
		tm.metrics.IncRpc("getChainedDispatch")
		chainedDispatch, err := tm.GetChainedDispatchByID(ctx, id)
		return chainedDispatch, err
	})
}
