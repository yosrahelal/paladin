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
	"fmt"
	"log/slog"

	"github.com/hyperledger/firefly-signer/pkg/ethtypes"
	"github.com/kaleido-io/paladin/registry/identity"
)

type LookupIdentityResult struct {
	Name       string            `json:"name"`
	Owner      string            `json:"owner"`
	Parent     string            `json:"parent"`
	Children   []string          `json:"children"`
	Properties map[string]string `json:"properties"`
}

type IdentityRegisteredResult struct {
	Registered bool `json:"registered"`
}

type PropertySetResult struct {
	PropertySet bool `json:"propertySet"`
}

type SetSmartContractAddressResult struct {
	SmartContractSet bool `json:"smartContractSet"`
}

type SmartContractDeployResult struct {
	Address string `json:"address"`
}

type SmartContractStatusResult struct {
	Configured bool   `json:"configured"`
	Address    string `json:"address,omitempty"`
}

type SyncStatusResult struct {
	LastSync              int64 `json:"lastSync"`
	LastIncrementalUpdate int64 `json:"lastIncrementalUpdate"`
}

func lookupIdentity(identifier string) (response LookupIdentityResult, err error) {
	hash := identity.GetIdentityHash(identifier)
	resolvedIdentity, err := identity.Registry.LookupIdentity(hash)
	if err != nil {
		return
	}

	parent, err := identity.Registry.LookupIdentity(resolvedIdentity.Parent)
	if err != nil {
		return
	}

	properties, propertiesError := identity.Registry.GetIdentityProperties(hash)
	if propertiesError != nil {
		err = propertiesError
		return
	}

	children := []string{}
	for _, childHash := range resolvedIdentity.Children {
		resolvedChild, err := identity.Registry.LookupIdentity(childHash)
		if err == nil {
			children = append(children, resolvedChild.Name)
		} else {
			slog.Error(fmt.Sprintf("Failed to resolve child identity %s", err))
		}
	}

	response = LookupIdentityResult{
		Name:       resolvedIdentity.Name,
		Owner:      resolvedIdentity.Owner.String(),
		Parent:     parent.Name,
		Children:   children,
		Properties: properties,
	}
	return
}

func registerIdentity(signer string, parentIdentity string, name string, owner ethtypes.Address0xHex) (result IdentityRegisteredResult, err error) {
	parentIdentityHash := identity.GetIdentityHash(parentIdentity)
	err = identity.Registry.RegisterIdentity(signer, parentIdentityHash, owner, name)
	result.Registered = err == nil
	return
}

func setIdentityProperty(signer string, identifier string, name string, value string) (result PropertySetResult, err error) {
	hash := identity.GetIdentityHash(identifier)
	err = identity.Registry.SetIdentityProperty(signer, hash, name, value)
	result.PropertySet = err == nil
	return
}

func setSmartContractAddress(address ethtypes.Address0xHex) (result SetSmartContractAddressResult, err error) {
	identity.Registry.SetSmartContractAddress(address)
	err = identity.Registry.SyncCache()
	result.SmartContractSet = err == nil
	return
}

func deploySmartContract(signer string) (result SmartContractDeployResult, err error) {
	address, err := identity.Registry.DeploySmartContract(signer)
	result.Address = address.String()
	return
}
