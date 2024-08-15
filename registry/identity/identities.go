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

package identity

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/hyperledger/firefly-signer/pkg/ethtypes"
)

type identityResponse struct {
	Identity Identity `json:"identity"`
}

type Identity struct {
	Parent   ethtypes.HexBytes0xPrefix   `json:"parent"`
	Children []ethtypes.HexBytes0xPrefix `json:"children"`
	Name     string                      `json:"name"`
	Owner    ethtypes.Address0xHex       `json:"owner"`
}

func (registry *IdentityRegistry) GetRootIdentity() (identity Identity, err error) {
	if !registry.IsSmartContractSet() {
		err = errors.New("Smart contract not set")
		return
	}

	ctx := context.Background()
	data, err := registry.abiClient.MustFunction("getRootIdentity").R(ctx).To(&registry.contractAddr).CallJSON()
	if err != nil {
		return
	}

	var ir identityResponse
	err = json.Unmarshal(data, &ir)
	if err != nil {
		return
	}

	identity = ir.Identity
	return
}

func (registry *IdentityRegistry) RegisterIdentity(signer string, parent ethtypes.HexBytes0xPrefix, owner ethtypes.Address0xHex, name string) (err error) {
	if !registry.IsSmartContractSet() {
		err = errors.New("Smart contract not set")
		return
	}

	ctx := context.Background()
	input := fmt.Sprintf(`{"parentIdentityHash":"%s","name":"%s","owner":"%s"}`, parent, name, owner)
	txHash, err := registry.abiClient.MustFunction("registerIdentity").R(ctx).Signer(signer).
		To(&registry.contractAddr).Input(input).SignAndSend()
	if err != nil {
		return
	}

	_, err = registry.indexer.WaitForTransaction(ctx, txHash.String())
	return
}

func (registry *IdentityRegistry) LookupIdentity(hash ethtypes.HexBytes0xPrefix) (identity Identity, err error) {
	if !registry.IsSmartContractSet() {
		err = errors.New("Smart contract not set")
		return
	}

	ctx := context.Background()
	input := fmt.Sprintf(`{"identityHash":"%s"}`, hash)
	data, err := registry.abiClient.MustFunction("getIdentity").R(ctx).To(&registry.contractAddr).Input(input).CallJSON()
	if err != nil {
		return
	}

	var ir identityResponse
	err = json.Unmarshal(data, &ir)
	if err != nil {
		return
	}

	identity = ir.Identity
	return
}
