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
	"os"
	"testing"

	"github.com/hyperledger/firefly-signer/pkg/ethtypes"
	"github.com/kaleido-io/paladin/kata/pkg/signer/api"
	"github.com/kaleido-io/paladin/registry/config"
	"github.com/stretchr/testify/assert"
)

/**
 * Test design
 * -----------
 *
 * The following identity hierarchy is registered:
 *
 *    root                  (owned by key0)
 *    ├── identity-a        (owned by key2)
 *    │   ├── identity-a-a  (owned by key3)
 *    │   └── identity-a-b  (owned by key4)
 *    └── identity-b        (owned by key0)
 *
 * The following properties are set:
 *
 *   root      key=key-root-1, value=value-root-1/updated
 *             key=key-root-2, value=value-root-2
 *
 *   identity-a    key=key-identity-a-1, value=value-identity-a-1
 *                 key=key-identity-a-2, value=value-identity-a-2
 *
 * NOTE: Hardhat node must be running during the execution of the test.
 *       Run the command: "npx run hardhat" in the solidity directory
 */

func TestRegistry(t *testing.T) {
	initialize(t)
	preContractDeploymentTests(t)
	deploySmartContract(t)
	registerChildIdentities(t)
	registerGrandChildIdentities(t)
	setProperties(t)
	verifyIdentities(t)
	verifyProperties(t)
	checkPermissions(t)
	checkIdentityNotFound(t)
	checkDuplicates(t)
	checkEmptyNames(t)

}

func initialize(t *testing.T) {
	err := os.Chdir("..")
	assert.Nil(t, err)

	err = config.Values.Load()
	assert.Nil(t, err)

	err = Registry.Initialize(config.Values)
	assert.Nil(t, err)
}

func preContractDeploymentTests(t *testing.T) {
	var rootIdentityHash = GetRootIdentityHash()

	_, err := Registry.LookupIdentity(rootIdentityHash)
	assert.Equal(t, "Smart contract not set", err.Error())

	err = Registry.RegisterIdentity("key0", rootIdentityHash, ethtypes.Address0xHex{}, "identity-a")
	assert.Equal(t, "Smart contract not set", err.Error())

	_, err = Registry.GetIdentityProperties(rootIdentityHash)
	assert.Equal(t, "Smart contract not set", err.Error())

	err = Registry.SetIdentityProperty("key0", rootIdentityHash, "key", "value")
	assert.Equal(t, "Smart contract not set", err.Error())

	err = Registry.SyncCache()
	assert.Equal(t, "Smart contract not set", err.Error())
}

func deploySmartContract(t *testing.T) {
	address, err := Registry.DeploySmartContract("key0")
	assert.Nil(t, err)

	err = Registry.SetSmartContractAddress(address)
	assert.Nil(t, err)
}

func registerChildIdentities(t *testing.T) {
	var rootIdentityHash = GetRootIdentityHash()

	err := Registry.RegisterIdentity("key0", rootIdentityHash, getAddress("key1"), "identity-a")
	assert.Nil(t, err)

	err = Registry.RegisterIdentity("key0", rootIdentityHash, getAddress("key2"), "identity-b")
	assert.Nil(t, err)
}

func registerGrandChildIdentities(t *testing.T) {
	var rootIdentityHash = GetRootIdentityHash()

	rootIdentity, err := Registry.LookupIdentity(rootIdentityHash)
	assert.Nil(t, err)

	err = Registry.RegisterIdentity("key1", rootIdentity.Children[0], getAddress("key3"), "identity-a-a")
	assert.Nil(t, err)

	err = Registry.RegisterIdentity("key1", rootIdentity.Children[0], getAddress("key4"), "identity-a-b")
	assert.Nil(t, err)
}

func setProperties(t *testing.T) {
	var rootIdentityHash = GetRootIdentityHash()

	rootIdentity, err := Registry.LookupIdentity(rootIdentityHash)
	assert.Nil(t, err)

	err = Registry.SetIdentityProperty("key0", rootIdentityHash, "key-root-1", "value-root-1")
	assert.Nil(t, err)

	err = Registry.SetIdentityProperty("key0", rootIdentityHash, "key-root-2", "value-root-2")
	assert.Nil(t, err)

	err = Registry.SetIdentityProperty("key1", rootIdentity.Children[0], "key-identity-a-1", "value-identity-a-1")
	assert.Nil(t, err)

	err = Registry.SetIdentityProperty("key1", rootIdentity.Children[0], "key-identity-a-2", "value-identity-a-2")
	assert.Nil(t, err)
}

func verifyIdentities(t *testing.T) {
	rootIdentity, err := Registry.LookupIdentity(GetRootIdentityHash())
	assert.Nil(t, err)

	assert.Equal(t, "root", rootIdentity.Name)
	assert.Equal(t, getAddress("key0").String(), rootIdentity.Owner.String())
	assert.Equal(t, GetRootIdentityHash(), rootIdentity.Parent)
	assert.Equal(t, 2, len(rootIdentity.Children))

	identityA, err := Registry.LookupIdentity(rootIdentity.Children[0])
	assert.Nil(t, err)

	assert.Equal(t, "identity-a", identityA.Name)
	assert.Equal(t, getAddress("key1"), identityA.Owner)
	assert.Equal(t, GetRootIdentityHash(), identityA.Parent)
	assert.Equal(t, 2, len(identityA.Children))

	identityAA, err := Registry.LookupIdentity(identityA.Children[0])
	assert.Nil(t, err)

	assert.Equal(t, "identity-a-a", identityAA.Name)
	assert.Equal(t, getAddress("key3"), identityAA.Owner)
	assert.Equal(t, rootIdentity.Children[0], identityAA.Parent)
	assert.Equal(t, 0, len(identityAA.Children))

	identityAB, err := Registry.LookupIdentity(identityA.Children[1])
	assert.Nil(t, err)

	assert.Equal(t, "identity-a-b", identityAB.Name)
	assert.Equal(t, getAddress("key4"), identityAB.Owner)
	assert.Equal(t, rootIdentity.Children[0], identityAB.Parent)
	assert.Equal(t, 0, len(identityAB.Children))

	identityB, err := Registry.LookupIdentity(rootIdentity.Children[1])
	assert.Nil(t, err)

	assert.Equal(t, "identity-b", identityB.Name)
	assert.Equal(t, identityB.Owner, getAddress("key2"))
	assert.Equal(t, GetRootIdentityHash(), identityB.Parent)
	assert.Equal(t, 0, len(identityB.Children))
}

func verifyProperties(t *testing.T) {
	properties, err := Registry.GetIdentityProperties(GetRootIdentityHash())
	assert.Nil(t, err)

	assert.Equal(t, "value-root-1", properties["key-root-1"])
	assert.Equal(t, "value-root-2", properties["key-root-2"])

	properties, err = Registry.GetIdentityProperties(GetIdentityHash("identity-a"))
	assert.Nil(t, err)

	assert.Equal(t, "value-identity-a-1", properties["key-identity-a-1"])
	assert.Equal(t, "value-identity-a-2", properties["key-identity-a-2"])

	properties, err = Registry.GetIdentityProperties(GetIdentityHash("identity-b"))
	assert.Nil(t, err)

	assert.Equal(t, 0, len(properties))

	properties, err = Registry.GetIdentityProperties(GetIdentityHash("identity-a/identity-a-a"))
	assert.Nil(t, err)
	assert.Equal(t, 0, len(properties))

	properties, err = Registry.GetIdentityProperties(GetIdentityHash("identity-a/identity-a-b"))
	assert.Nil(t, err)
	assert.Equal(t, 0, len(properties))
}

func checkPermissions(t *testing.T) {
	err := Registry.RegisterIdentity("key0", GetIdentityHash("identity-a"), getAddress("key0"), "identity-x")
	assert.Equal(t, "Execution reverted: Forbidden", err.Error())

	err = Registry.SetIdentityProperty("key0", GetIdentityHash("identity-a"), "key", "value")
	assert.Equal(t, "Execution reverted: Forbidden", err.Error())
}

func checkIdentityNotFound(t *testing.T) {
	_, err := Registry.LookupIdentity(GetIdentityHash("other"))
	assert.Equal(t, "Execution reverted: Identity not found", err.Error())
}

func checkDuplicates(t *testing.T) {
	var rootIdentityHash = GetRootIdentityHash()
	err := Registry.RegisterIdentity("key0", rootIdentityHash, getAddress("key1"), "identity-a")
	assert.Equal(t, "Execution reverted: Name already taken", err.Error())
}

func checkEmptyNames(t *testing.T) {
	var rootIdentityHash = GetRootIdentityHash()
	err := Registry.RegisterIdentity("key0", rootIdentityHash, getAddress("key1"), "")
	assert.Equal(t, "Execution reverted: Name cannot be empty", err.Error())
	err = Registry.SetIdentityProperty("key0", rootIdentityHash, "", "value-root-1")
	assert.Equal(t, "Execution reverted: Name cannot be empty", err.Error())
}

func getAddress(key string) (address ethtypes.Address0xHex) {
	ctx := context.Background()
	_, verifier, err := Registry.keyMgr.ResolveKey(ctx, key, api.Algorithm_ECDSA_SECP256K1_PLAINBYTES)

	if err != nil {
		panic("Failed to get address from key")
	}
	address = *ethtypes.MustNewAddress(verifier)
	return
}
