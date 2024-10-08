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

package api

import (
	"net/http"

	"github.com/gorilla/mux"
	"github.com/gorilla/rpc"
	"github.com/gorilla/rpc/json"
	"github.com/hyperledger/firefly-signer/pkg/ethtypes"
	"github.com/kaleido-io/paladin/registry/identity"
)

type IdentitiesRPC identity.IdentityRegistry

type ContractRPC identity.IdentityRegistry

type CacheRPC identity.IdentityRegistry

type LookupIdentityArgs struct {
	Identity string
}

type RegisterIdentityArgs struct {
	Signer string
	Parent string
	Name   string
	Owner  string
}

type SetIdentityPropertyArgs struct {
	Signer   string
	Identity string
	Key      string
	Value    string
}

type SetSmartContractAddressArgs struct {
	Address ethtypes.Address0xHex
}

type DeploySmartContractArgs struct {
	Signer string
}

func SetupJsonRpc(mux *mux.Router) {
	rpcServer := rpc.NewServer()
	rpcServer.RegisterCodec(json.NewCodec(), "application/json")
	rpcServer.RegisterCodec(json.NewCodec(), "application/json;charset=UTF-8")

	identitiesRPC := new(IdentitiesRPC)
	contractRPC := new(ContractRPC)
	syncRPC := new(CacheRPC)

	err := rpcServer.RegisterService(identitiesRPC, "identities")
	if err != nil {
		panic(err)
	}

	err = rpcServer.RegisterService(contractRPC, "contract")
	if err != nil {
		panic(err)
	}

	err = rpcServer.RegisterService(syncRPC, "syc")
	if err != nil {
		panic(err)
	}

	mux.Handle("/rpc", rpcServer)
}

func (t *IdentitiesRPC) Lookup(r *http.Request, args *LookupIdentityArgs, result *LookupIdentityResult) (err error) {
	*result, err = lookupIdentity(args.Identity)
	return
}

func (t *IdentitiesRPC) Register(r *http.Request, args *RegisterIdentityArgs, result *IdentityRegisteredResult) (err error) {
	address, err := ethtypes.NewAddress(args.Signer)
	if err != nil {
		return
	}

	*result, err = registerIdentity(args.Signer, args.Parent, args.Name, *address)
	return
}

func (t *IdentitiesRPC) SetProperty(r *http.Request, args *SetIdentityPropertyArgs, result *PropertySetResult) (err error) {
	*result, err = setIdentityProperty(args.Signer, args.Identity, args.Key, args.Value)
	return
}

func (t *ContractRPC) GetStatus(r *http.Request, args *any, result *SmartContractStatusResult) (err error) {
	address, err := identity.Registry.GetSmartContractAddress()
	if err == nil {
		result.Address = address.String()
		result.Configured = true
	}
	return
}

func (t *ContractRPC) SetAddress(r *http.Request, args *SetSmartContractAddressArgs, result *SetSmartContractAddressResult) (err error) {
	*result, err = setSmartContractAddress(args.Address)
	return
}

func (t *ContractRPC) Deploy(r *http.Request, args *DeploySmartContractArgs, result *SmartContractDeployResult) (err error) {
	*result, err = deploySmartContract(args.Signer)
	return
}

func (t *CacheRPC) GetStatus(r *http.Request, args *any, result *SyncStatusResult) (err error) {
	*result = SyncStatusResult{
		LastSync:              identity.Registry.LastSync,
		LastIncrementalUpdate: identity.Registry.LastIncrementalUpdate,
	}
	return
}

func (t *CacheRPC) Sync(r *http.Request, args *any, result *SyncStatusResult) (err error) {
	err = identity.Registry.SyncCache()
	if err != nil {
		return
	}

	*result = SyncStatusResult{
		LastSync:              identity.Registry.LastSync,
		LastIncrementalUpdate: identity.Registry.LastIncrementalUpdate,
	}
	return
}
