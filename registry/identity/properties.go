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

type propertyHashesResponse struct {
	Hashes []ethtypes.HexBytes0xPrefix `json:"hashes"`
}

type propertyResponse struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

func (registry *IdentityRegistry) SetIdentityProperty(signer string, identityHash ethtypes.HexBytes0xPrefix, name string, value string) (err error) {
	if !registry.IsSmartContractSet() {
		err = errors.New("Smart contract not set")
		return
	}

	ctx := context.Background()
	input := fmt.Sprintf(`{"identityHash":"%s","name":"%s","value":"%s"}`, identityHash, name, value)
	txHash, err := registry.abiClient.MustFunction("setIdentityProperty").R(ctx).Signer(signer).
		To(&registry.contractAddr).Input(input).SignAndSend()
	if err != nil {
		return
	}

	_, err = registry.indexer.WaitForTransaction(ctx, txHash.String())
	return
}

func (registry *IdentityRegistry) GetIdentityProperties(identityHash ethtypes.HexBytes0xPrefix) (properties map[string]string, err error) {
	if !registry.IsSmartContractSet() {
		err = errors.New("Smart contract not set")
		return
	}

	properties = make(map[string]string)
	ctx := context.Background()
	input := fmt.Sprintf(`{"identityHash":"%s"}`, identityHash)
	data, err := registry.abiClient.MustFunction("listIdentityPropertyHashes").R(ctx).To(&registry.contractAddr).Input(input).CallJSON()
	if err != nil {
		return
	}

	var hashes propertyHashesResponse
	err = json.Unmarshal(data, &hashes)
	if err != nil {
		return
	}

	for _, hash := range hashes.Hashes {
		name, value, propertyErr := registry.getIdentityProperty(identityHash, hash)
		if propertyErr != nil {
			err = propertyErr
			return
		}
		properties[name] = value
	}
	return
}

func (registry *IdentityRegistry) getIdentityProperty(identityHash ethtypes.HexBytes0xPrefix, propertyHash ethtypes.HexBytes0xPrefix) (name string, value string, err error) {
	if !registry.IsSmartContractSet() {
		err = errors.New("Smart contract not set")
		return
	}

	ctx := context.Background()
	input := fmt.Sprintf(`{"identityHash":"%s","propertyNameHash":"%s"}`, identityHash, propertyHash)
	data, err := registry.abiClient.MustFunction("getIdentityPropertyByHash").R(ctx).To(&registry.contractAddr).Input(input).CallJSON()
	if err != nil {
		return
	}

	var pr propertyResponse
	err = json.Unmarshal(data, &pr)
	if err == nil {
		name = pr.Name
		value = pr.Value
	}

	return
}
