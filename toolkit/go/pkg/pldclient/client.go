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

	"github.com/hyperledger/firefly-common/pkg/i18n"
	"github.com/hyperledger/firefly-signer/pkg/abi"
	"github.com/kaleido-io/paladin/config/pkg/pldconf"
	"github.com/kaleido-io/paladin/toolkit/pkg/rpcclient"
	"github.com/kaleido-io/paladin/toolkit/pkg/tkmsgs"
	"github.com/kaleido-io/paladin/toolkit/pkg/tktypes"
)

type PaladinClient interface {
	ABI(ctx context.Context, a abi.ABI) (ABIClient, error)
	ABIJSON(ctx context.Context, abiJson []byte) (ABIClient, error)
	ABIFunction(ctx context.Context, functionABI *abi.Entry) (_ ABIFunctionClient, err error)
	ABIConstructor(ctx context.Context, constructorABI *abi.Entry, bytecode tktypes.HexBytes) (_ ABIFunctionClient, err error)
	MustABIJSON(abiJson []byte) ABIClient

	PTX() PTX // ptx_ function access
}

type PaladinWSClient interface {
	PaladinClient // No differences... yet
}

type paladinClient struct {
	rpc rpcclient.Client
}

func Wrap(rpc rpcclient.Client) PaladinClient {
	return &paladinClient{rpc: rpc}
}

func NewUnconnected(ctx context.Context) PaladinClient {
	return Wrap(&unconnectedRPC{})
}

func NewHTTP(ctx context.Context, conf *pldconf.HTTPClientConfig) (PaladinClient, error) {
	rpc, err := rpcclient.NewHTTPClient(ctx, conf)
	if err != nil {
		return nil, err
	}
	return Wrap(rpc), nil
}

func NewWebSockets(ctx context.Context, conf *pldconf.WSClientConfig) (PaladinClient, error) {
	rpc, err := rpcclient.NewWSClient(ctx, conf)
	if err != nil {
		return nil, err
	}
	return Wrap(rpc), nil
}

type unconnectedRPC struct{}

func (u *unconnectedRPC) CallRPC(ctx context.Context, result interface{}, method string, params ...interface{}) rpcclient.ErrorRPC {
	return rpcclient.WrapErrorRPC(rpcclient.RPCCodeInternalError, i18n.NewError(ctx, tkmsgs.MsgPaladinClientNoConnection))
}
