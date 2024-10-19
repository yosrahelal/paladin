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
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/hyperledger/firefly-signer/pkg/abi"
	"github.com/kaleido-io/paladin/config/pkg/confutil"
	"github.com/kaleido-io/paladin/toolkit/pkg/pldapi"
	"github.com/kaleido-io/paladin/toolkit/pkg/rpcserver"
	"github.com/kaleido-io/paladin/toolkit/pkg/solutils"
	"github.com/kaleido-io/paladin/toolkit/pkg/tktypes"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var testABIJSON = ([]byte)(`[
	{
		"type": "constructor",
		"inputs": [
			{
				"name": "supplier",
				"type": "address"
			}
		]
	},
	{
		"name": "newWidget",
		"type": "function",
		"inputs": [
			{
				"name": "widget",
				"type": "tuple",
				"components": [
					{
						"name": "id",
						"type": "address"
					},
					{
						"name": "sku",
						"type": "uint256"
					},
					{
						"name": "features",
						"type": "string[]"
					}
				]
			}
		],
		"outputs": []
	},
	{
		"name": "getWidgets",
		"type": "function",
		"inputs": [
			{
				"name": "sku",
				"type": "uint256"
			}
		],
		"outputs": [
			{
				"name": "",
				"type": "tuple[]",
				"components": [
					{
						"name": "id",
						"type": "address"
					},
					{
						"name": "sku",
						"type": "uint256"
					},
					{
						"name": "features",
						"type": "string[]"
					}
				]
			}
		]
	},
	{
	  "type": "error",
	  "name": "WidgetError",
	  "inputs": [
	    {
	      "name": "sku",
	      "type": "uint256"
	    },
	    {
	      "name": "issue",
	      "type": "string"
	    }
	  ]
	}
]`)

func TestBuildAndSubmitPublicTXOk(t *testing.T) {

	ctx, c, rpcServer, done := newTestClientAndServerHTTP(t)
	defer done()

	contractAddr := tktypes.RandAddress()
	txID := uuid.New()
	txHash := tktypes.Bytes32(tktypes.RandBytes(32))

	rpcServer.Register(rpcserver.NewRPCModule("ptx").
		Add(
			"ptx_sendTransaction", rpcserver.RPCMethod1(func(ctx context.Context, tx pldapi.TransactionInput) (*uuid.UUID, error) {
				require.JSONEq(t, `{
					"widget": {
						"id": "0x172ea50b3535721154ae5b368e850825615882bb",
						"sku": "12345",
						"features": ["blue", "round"]
					}
				}`, string(tx.Data))
				require.Equal(t, pldapi.TransactionTypePublic, tx.Type.V())
				require.Equal(t, "newWidget", tx.Function)
				require.Equal(t, contractAddr, tx.To)
				require.Equal(t, "tx.sender", tx.From)
				require.Equal(t, tktypes.HexUint64(100000), *tx.PublicTxOptions.Gas)
				return &txID, nil
			}),
		).
		Add(
			"ptx_getTransactionReceipt", rpcserver.RPCMethod1(func(ctx context.Context, suppliedID uuid.UUID) (*pldapi.TransactionReceipt, error) {
				require.Equal(t, txID, suppliedID)
				return &pldapi.TransactionReceipt{
					ID: txID,
					TransactionReceiptData: pldapi.TransactionReceiptData{
						Success: true,
						TransactionReceiptDataOnchain: &pldapi.TransactionReceiptDataOnchain{
							TransactionHash: &txHash,
						},
					},
				}, nil
			}),
		))

	res := c.TxBuilder(ctx).
		Public().
		ABIJSON(testABIJSON).
		Function("newWidget").
		Inputs(map[string]any{
			"widget": map[string]any{
				"id":       "0x172EA50B3535721154ae5B368E850825615882BB",
				"sku":      12345,
				"features": []string{"blue", "round"},
			},
		}).
		From("tx.sender").
		To(contractAddr).
		PublicTxOptions(pldapi.PublicTxOptions{
			Gas: confutil.P(tktypes.HexUint64(100000)),
		}).
		Send().
		Wait(100 * time.Millisecond)
	require.NoError(t, res.Error())
	require.Equal(t, txHash, *res.TransactionHash())

}

func TestBuildAndSubmitPublicDeployFail(t *testing.T) {

	ctx, c, rpcServer, done := newTestClientAndServerHTTP(t)
	defer done()

	bytecode := tktypes.HexBytes(tktypes.RandBytes(64))
	txID := uuid.New()

	rpcServer.Register(rpcserver.NewRPCModule("ptx").
		Add(
			"ptx_sendTransaction", rpcserver.RPCMethod1(func(ctx context.Context, tx pldapi.TransactionInput) (*uuid.UUID, error) {
				require.JSONEq(t, `{"supplier": "0x172ea50b3535721154ae5b368e850825615882bb"}`, string(tx.Data))
				require.Equal(t, bytecode, tx.Bytecode)
				return &txID, nil
			}),
		).
		Add(
			"ptx_getTransactionReceipt", rpcserver.RPCMethod1(func(ctx context.Context, suppliedID uuid.UUID) (*pldapi.TransactionReceipt, error) {
				require.Equal(t, txID, suppliedID)
				return nil, fmt.Errorf("server throws an error")
			}),
		))

	var a abi.ABI
	err := json.Unmarshal(testABIJSON, &a)
	require.NoError(t, err)

	res := c.ReceiptPollingInterval(1 * time.Millisecond).
		TxBuilder(ctx).
		Public().
		SolidityBuild(&solutils.SolidityBuild{
			ABI:      a,
			Bytecode: bytecode,
		}).
		From("tx.sender").
		Inputs(`{"supplier": "0x172EA50B3535721154ae5B368E850825615882BB"}`).
		Send().
		Wait(25 * time.Millisecond)
	require.Regexp(t, "PD020216.*timed out.*server throws an error", res.Error())
	require.Nil(t, res.TransactionHash())

}

func TestIdempotentSubmit(t *testing.T) {

	ctx, c, rpcServer, done := newTestClientAndServerHTTP(t)
	defer done()

	txID := uuid.New()

	rpcServer.Register(rpcserver.NewRPCModule("ptx").
		Add(
			"ptx_sendTransaction", rpcserver.RPCMethod1(func(ctx context.Context, tx pldapi.TransactionInput) (*uuid.UUID, error) {
				return nil, fmt.Errorf("PD012220: key clash" /* note important error code in Paladin */)
			}),
		).
		Add(
			"ptx_getTransactionByIdempotencyKey", rpcserver.RPCMethod1(func(ctx context.Context, idempotencyKey string) (*pldapi.Transaction, error) {
				require.Equal(t, "tx.12345", idempotencyKey)
				return &pldapi.Transaction{
					ID: &txID,
				}, nil
			}),
		))

	res := c.TxBuilder(ctx).
		Private().
		Domain("domain1").
		IdempotencyKey("tx.12345").
		ABIJSON(testABIJSON).
		From("tx.sender").
		Inputs(`{"supplier": "0x172EA50B3535721154ae5B368E850825615882BB"}`).
		Send()
	require.NoError(t, res.Error())
	assert.Equal(t, txID, *res.ID())

}

func TestDeferFunctionSelectError(t *testing.T) {

	ctx, c, _, done := newTestClientAndServerHTTP(t)
	defer done()

	res := c.ReceiptPollingInterval(1 * time.Millisecond).
		TxBuilder(ctx).
		Public().
		ABIJSON(testABIJSON).
		Function("wrong").
		To(tktypes.RandAddress()).
		Send().
		Wait(25 * time.Millisecond)
	require.Regexp(t, "PD020208", res.Error()) // function not found

}

func TestBuildABIDataJSONArray(t *testing.T) {

	ctx, c, _, done := newTestClientAndServerHTTP(t)
	defer done()

	data, err := c.ReceiptPollingInterval(1 * time.Millisecond).
		TxBuilder(ctx).
		Public().
		ABIJSON(testABIJSON).
		Function("getWidgets(uint256)").
		To(tktypes.RandAddress()).
		Inputs(`{"sku": 73588229205}`).
		JSONSerializer(abi.NewSerializer().
			SetFormattingMode(abi.FormatAsFlatArrays).
			SetIntSerializer(abi.HexIntSerializer0xPrefix),
		).
		BuildInputDataJSON()
	require.NoError(t, err)
	require.JSONEq(t, `["0x1122334455"]`, string(data))

}

func TestSendNoABI(t *testing.T) {

	ctx, c, rpcServer, done := newTestClientAndServerHTTP(t)
	defer done()

	txID := uuid.New()
	rpcServer.Register(rpcserver.NewRPCModule("ptx").
		Add(
			"ptx_sendTransaction", rpcserver.RPCMethod1(func(ctx context.Context, tx pldapi.TransactionInput) (*uuid.UUID, error) {
				require.JSONEq(t, `{"sku": 73588229205}`, string(tx.Data))
				return &txID, nil
			}),
		))

	res := c.ReceiptPollingInterval(1 * time.Millisecond).
		TxBuilder(ctx).
		Public().
		ABIReference((*tktypes.Bytes32)(tktypes.RandBytes(32))).
		Function("getWidgets(uint256)").
		From("tx.sender").
		To(tktypes.RandAddress()).
		Inputs(`{"sku": 73588229205}`).
		Send()
	require.NoError(t, res.Error())
	require.Equal(t, txID, *res.ID())
}

func TestBuildBadABIFunction(t *testing.T) {

	ctx, c, _, done := newTestClientAndServerHTTP(t)
	defer done()

	res := c.ReceiptPollingInterval(1 * time.Millisecond).
		TxBuilder(ctx).
		ABIFunction(&abi.Entry{Type: abi.Function, Inputs: abi.ParameterArray{{Type: "wrongness"}}}).
		Public().
		ABIReference((*tktypes.Bytes32)(tktypes.RandBytes(32))).
		Function("getWidgets(uint256)").
		From("tx.sender").
		To(tktypes.RandAddress()).
		Inputs(`{"sku": 73588229205}`).
		Send()
	assert.Regexp(t, "FF22025", res.Error())
}

func TestBuildBadABIJSON(t *testing.T) {

	ctx, c, _, done := newTestClientAndServerHTTP(t)
	defer done()

	res := c.ReceiptPollingInterval(1 * time.Millisecond).
		TxBuilder(ctx).
		ABIJSON([]byte(`{!!!! wrong`)).
		Public().
		ABIReference((*tktypes.Bytes32)(tktypes.RandBytes(32))).
		Function("getWidgets(uint256)").
		From("tx.sender").
		To(tktypes.RandAddress()).
		Inputs(`{"sku": 73588229205}`).
		Send()
	assert.Regexp(t, "PD020207", res.Error())
}

func TestGetters(t *testing.T) {

	tx := &pldapi.TransactionInput{
		Transaction: pldapi.Transaction{
			IdempotencyKey: "tx1",
			Type:           pldapi.TransactionTypePrivate.Enum(),
			Domain:         "domain1",
			ABIReference:   confutil.P(tktypes.Bytes32(tktypes.RandBytes(32))),
			From:           "tx.sender",
			To:             tktypes.RandAddress(),
			Function:       "function1",
			PublicTxOptions: pldapi.PublicTxOptions{
				Gas: confutil.P(tktypes.HexUint64(100000)),
			},
		},
		ABI:      abi.ABI{{Type: abi.Constructor}},
		Bytecode: tktypes.HexBytes(tktypes.RandBytes(64)),
	}

	// This isn't a valid TX, but we're just testing getters
	b := New().TxBuilder(context.Background()).Wrap(tx)
	assert.Equal(t, tx.ABI, b.GetABI())
	assert.Equal(t, tx.IdempotencyKey, b.GetIdempotencyKey())
	assert.Equal(t, pldapi.TransactionTypePrivate, b.GetType())
	assert.Equal(t, "domain1", b.GetDomain())
	assert.Same(t, tx.ABIReference, b.GetABIReference())
	assert.Equal(t, "tx.sender", b.GetFrom())
	assert.Equal(t, tx.To, b.GetTo())
	assert.Equal(t, tx.Data, b.GetInputs())
	assert.Equal(t, "function1", b.GetFunction())
	assert.Equal(t, tx.Bytecode, b.GetBytecode())
	assert.Equal(t, tx.PublicTxOptions, b.GetPublicTxOptions())

	// Check it doesn't change in the round trip
	tx2 := b.BuildTX().TX()
	require.Equal(t, tx, tx2)

	serializer := abi.NewSerializer()
	assert.Equal(t, serializer, b.JSONSerializer(serializer).GetJSONSerializer())
}
