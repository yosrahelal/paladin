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
	"testing"

	"github.com/hyperledger/firefly-signer/pkg/ethtypes"
	"github.com/hyperledger/firefly-signer/pkg/rpcbackend"
	"github.com/kaleido-io/paladin/domains/noto/pkg/types"
	"github.com/kaleido-io/paladin/toolkit/pkg/tktypes"
	"github.com/stretchr/testify/assert"
)

//go:embed abis/NotoFactory.json
var NotoFactoryJSON []byte

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

func (n *NotoHelper) Mint(ctx context.Context, to string, amount uint64) *DomainTransactionHelper {
	fn := types.NotoABI.Functions()["mint"]
	return NewDomainTransactionHelper(ctx, n.t, n.rpc, tktypes.EthAddress(n.Address), fn, toJSON(n.t, &types.MintParams{
		To:     to,
		Amount: ethtypes.NewHexIntegerU64(amount),
	}))
}

func (n *NotoHelper) Transfer(ctx context.Context, to string, amount uint64) *DomainTransactionHelper {
	fn := types.NotoABI.Functions()["transfer"]
	return NewDomainTransactionHelper(ctx, n.t, n.rpc, tktypes.EthAddress(n.Address), fn, toJSON(n.t, &types.TransferParams{
		To:     to,
		Amount: ethtypes.NewHexIntegerU64(amount),
	}))
}

func (n *NotoHelper) TransferWithApproval(ctx context.Context, to string, amount uint64) *DomainTransactionHelper {
	fn := types.NotoABI.Functions()["transferWithApproval"]
	return NewDomainTransactionHelper(ctx, n.t, n.rpc, tktypes.EthAddress(n.Address), fn, toJSON(n.t, &types.TransferParams{
		To:     to,
		Amount: ethtypes.NewHexIntegerU64(amount),
	}))
}

func (n *NotoHelper) ApproveTransfer(ctx context.Context, params *types.ApproveParams) *DomainTransactionHelper {
	fn := types.NotoABI.Functions()["approveTransfer"]
	return NewDomainTransactionHelper(ctx, n.t, n.rpc, tktypes.EthAddress(n.Address), fn, toJSON(n.t, params))
}
