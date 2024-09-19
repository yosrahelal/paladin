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
	"github.com/hyperledger-labs/zeto/go-sdk/pkg/sparse-merkle-tree/storage"
	"github.com/hyperledger/firefly-signer/pkg/ethtypes"
	"github.com/kaleido-io/paladin/core/pkg/persistence"
)

const SMT_HEIGHT_UTXO = 64

func New(p persistence.Persistence, name string) (core.SparseMerkleTree, error) {
	strg, err := storage.NewSqlStorage(p, name)
	if err != nil {
		return nil, err
	}
	return smt.NewMerkleTree(strg, SMT_HEIGHT_UTXO)
}

func MerkleTreeName(tokenName string, domainInstanceContract *ethtypes.Address0xHex) string {
	return "smt-" + tokenName + "-" + domainInstanceContract.String()
}
