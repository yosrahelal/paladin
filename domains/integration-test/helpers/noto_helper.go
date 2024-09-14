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
	"testing"

	"github.com/hyperledger/firefly-signer/pkg/ethtypes"
	"github.com/hyperledger/firefly-signer/pkg/rpcbackend"
	"github.com/kaleido-io/paladin/domains/noto/pkg/types"
	"github.com/kaleido-io/paladin/toolkit/pkg/tktypes"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type NotoHelper struct {
	t       *testing.T
	rpc     rpcbackend.Backend
	Address ethtypes.Address0xHex
}

func DeployNoto(ctx context.Context, t *testing.T, rpc rpcbackend.Backend, domainName, notary string) *NotoHelper {
	var addr ethtypes.Address0xHex
	rpcerr := rpc.CallRPC(ctx, &addr, "testbed_deploy", domainName, &types.ConstructorParams{
		Notary: notary,
	})
	if rpcerr != nil {
		assert.NoError(t, rpcerr.Error())
	}
	return &NotoHelper{
		t:       t,
		rpc:     rpc,
		Address: addr,
	}
}

func (n *NotoHelper) Mint(ctx context.Context, signer, to string, amount uint64) {
	var result bool
	rpcerr := n.rpc.CallRPC(ctx, &result, "testbed_invoke", &tktypes.PrivateContractInvoke{
		From:     signer,
		To:       tktypes.EthAddress(n.Address),
		Function: *types.NotoABI.Functions()["mint"],
		Inputs: toJSON(n.t, &types.MintParams{
			To:     to,
			Amount: ethtypes.NewHexIntegerU64(amount),
		}),
	}, true)
	if rpcerr != nil {
		require.NoError(n.t, rpcerr.Error())
	}
	assert.True(n.t, result)
}

func (n *NotoHelper) Transfer(ctx context.Context, signer, to string, amount int64) {
	var result bool
	rpcerr := n.rpc.CallRPC(ctx, &result, "testbed_invoke", &tktypes.PrivateContractInvoke{
		From:     signer,
		To:       tktypes.EthAddress(n.Address),
		Function: *types.NotoABI.Functions()["transfer"],
		Inputs: toJSON(n.t, &types.TransferParams{
			To:     to,
			Amount: ethtypes.NewHexInteger64(amount),
		}),
	}, true)
	if rpcerr != nil {
		require.NoError(n.t, rpcerr.Error())
	}
	assert.True(n.t, result)
}

func (n *NotoHelper) PrepareTransfer(ctx context.Context, signer, to string, amount uint64) *tktypes.PrivateContractPreparedTransaction {
	var prepared tktypes.PrivateContractPreparedTransaction
	rpcerr := n.rpc.CallRPC(ctx, &prepared, "testbed_prepare", &tktypes.PrivateContractInvoke{
		From:     signer,
		To:       tktypes.EthAddress(n.Address),
		Function: *types.NotoABI.Functions()["approvedTransfer"],
		Inputs: toJSON(n.t, &types.TransferParams{
			To:     to,
			Amount: ethtypes.NewHexIntegerU64(amount),
		}),
	})
	if rpcerr != nil {
		require.NoError(n.t, rpcerr.Error())
	}
	return &prepared
}

func (n *NotoHelper) Approve(ctx context.Context, signer string, delegate ethtypes.Address0xHex, call []byte) {
	var result bool
	rpcerr := n.rpc.CallRPC(ctx, &result, "testbed_invoke", &tktypes.PrivateContractInvoke{
		From:     signer,
		To:       tktypes.EthAddress(n.Address),
		Function: *types.NotoABI.Functions()["approve"],
		Inputs: toJSON(n.t, &types.ApproveParams{
			Delegate: delegate,
			Call:     call,
		}),
	}, true)
	if rpcerr != nil {
		require.NoError(n.t, rpcerr.Error())
	}
	assert.True(n.t, result)
}
