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

package smt

import (
	"github.com/hyperledger-labs/zeto/go-sdk/pkg/sparse-merkle-tree/core"
	"github.com/hyperledger-labs/zeto/go-sdk/pkg/sparse-merkle-tree/smt"
	"github.com/hyperledger/firefly-signer/pkg/ethtypes"
	"github.com/kaleido-io/paladin/core/pkg/proto"
	"github.com/kaleido-io/paladin/toolkit/pkg/plugintk"
)

const SMT_HEIGHT_UTXO = 64

var Empty_Proof proto.MerkleProof

func init() {
	var nodes []string
	for i := 0; i < SMT_HEIGHT_UTXO; i++ {
		nodes = append(nodes, "0")
	}
	Empty_Proof = proto.MerkleProof{
		Nodes: nodes,
	}
}

func New(callbacks plugintk.DomainCallbacks, name string, contractAddress *ethtypes.Address0xHex, rootSchemaId, nodeSchemaId string) (StatesStorage, core.SparseMerkleTree, error) {
	storage := NewStatesStorage(callbacks, name, contractAddress, rootSchemaId, nodeSchemaId)
	mt, err := smt.NewMerkleTree(storage, SMT_HEIGHT_UTXO)
	if err == nil && mt != nil {
		storage.(*statesStorage).rootNode = mt.Root()
	}
	return storage, mt, err
}

func MerkleTreeName(tokenName string, domainInstanceContract *ethtypes.Address0xHex) string {
	return "smt_" + tokenName + "_" + domainInstanceContract.String()
}
