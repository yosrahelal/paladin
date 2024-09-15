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

package helpers

import (
	"context"
	_ "embed"
	"encoding/json"
	"testing"

	"github.com/hyperledger/firefly-signer/pkg/abi"
	"github.com/hyperledger/firefly-signer/pkg/ethtypes"
	"github.com/hyperledger/firefly-signer/pkg/rpcbackend"
	"github.com/kaleido-io/paladin/core/pkg/blockindexer"
	"github.com/kaleido-io/paladin/core/pkg/ethclient"
	"github.com/kaleido-io/paladin/core/pkg/testbed"
	"github.com/kaleido-io/paladin/toolkit/pkg/tktypes"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type TransactionHelper struct {
	t       *testing.T
	tb      testbed.Testbed
	builder ethclient.ABIFunctionRequestBuilder
}

type DomainTransactionHelper struct {
	t   *testing.T
	rpc rpcbackend.Backend
	tx  *tktypes.PrivateContractInvoke
}

type SentTransaction struct {
	t  *testing.T
	tb testbed.Testbed
	tx *tktypes.Bytes32
}

func NewTransactionHelper(t *testing.T, tb testbed.Testbed, builder ethclient.ABIFunctionRequestBuilder) *TransactionHelper {
	return &TransactionHelper{t: t, tb: tb, builder: builder}
}

func (th *TransactionHelper) SignAndSend(signer string) *SentTransaction {
	tx, err := th.builder.Signer(signer).SignAndSend()
	require.NoError(th.t, err)
	return &SentTransaction{t: th.t, tb: th.tb, tx: tx}
}

func (th *TransactionHelper) Prepare() ethtypes.HexBytes0xPrefix {
	require.NoError(th.t, th.builder.BuildCallData())
	return th.builder.TX().Data
}

func (st *SentTransaction) Wait(ctx context.Context) {
	waitFor(ctx, st.t, st.tb, st.tx, nil)
}

func NewDomainTransactionHelper(t *testing.T, rpc rpcbackend.Backend, to tktypes.EthAddress, fn *abi.Entry, inputs tktypes.RawJSON) *DomainTransactionHelper {
	return &DomainTransactionHelper{
		t:   t,
		rpc: rpc,
		tx: &tktypes.PrivateContractInvoke{
			To:       to,
			Function: *fn,
			Inputs:   inputs,
		},
	}
}

func (dth *DomainTransactionHelper) SendAndWait(ctx context.Context, signer string) any {
	var result any
	dth.tx.From = signer
	rpcerr := dth.rpc.CallRPC(ctx, &result, "testbed_invoke", dth.tx, true)
	if rpcerr != nil {
		require.NoError(dth.t, rpcerr.Error())
	}
	return result
}

func (dth *DomainTransactionHelper) Prepare(ctx context.Context, signer string) *tktypes.PrivateContractPreparedTransaction {
	var result tktypes.PrivateContractPreparedTransaction
	dth.tx.From = signer
	rpcerr := dth.rpc.CallRPC(ctx, &result, "testbed_prepare", dth.tx)
	if rpcerr != nil {
		require.NoError(dth.t, rpcerr.Error())
	}
	return &result
}

func toJSON(t *testing.T, v any) []byte {
	result, err := json.Marshal(v)
	assert.NoError(t, err)
	return result
}

func deployBuilder(ctx context.Context, t *testing.T, eth ethclient.EthClient, abi abi.ABI, bytecode []byte) ethclient.ABIFunctionRequestBuilder {
	abiClient, err := eth.ABI(ctx, abi)
	assert.NoError(t, err)
	construct, err := abiClient.Constructor(ctx, bytecode)
	assert.NoError(t, err)
	return construct.R(ctx)
}

func functionBuilder(ctx context.Context, t *testing.T, eth ethclient.EthClient, abi abi.ABI, functionName string) ethclient.ABIFunctionRequestBuilder {
	abiClient, err := eth.ABI(ctx, abi)
	assert.NoError(t, err)
	fn, err := abiClient.Function(ctx, functionName)
	assert.NoError(t, err)
	return fn.R(ctx)
}

func waitFor(ctx context.Context, t *testing.T, tb testbed.Testbed, txHash *tktypes.Bytes32, err error) *blockindexer.IndexedTransaction {
	require.NoError(t, err)
	tx, err := tb.Components().BlockIndexer().WaitForTransactionSuccess(ctx, *txHash, nil)
	assert.NoError(t, err)
	return tx
}

func findEvent(ctx context.Context, t *testing.T, tb testbed.Testbed, txHash tktypes.Bytes32, abi abi.ABI, eventName string, eventParams interface{}) *blockindexer.EventWithData {
	targetEvent := abi.Events()[eventName]
	assert.NotNil(t, targetEvent)
	assert.NotEmpty(t, targetEvent.SolString())
	events, err := tb.Components().BlockIndexer().DecodeTransactionEvents(ctx, txHash, abi)
	assert.NoError(t, err)
	for _, event := range events {
		if event.SoliditySignature == targetEvent.SolString() {
			err = json.Unmarshal(event.Data, eventParams)
			assert.NoError(t, err)
			return event
		}
	}
	return nil
}
