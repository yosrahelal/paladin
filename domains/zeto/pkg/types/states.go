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

package types

import (
	"github.com/hyperledger/firefly-signer/pkg/abi"
	"github.com/kaleido-io/paladin/toolkit/pkg/tktypes"
)

type ZetoCoin struct {
	Salt     *tktypes.HexUint256 `json:"salt"`
	Owner    string              `json:"owner"`
	OwnerKey tktypes.HexBytes    `json:"ownerKey"`
	Amount   *tktypes.HexUint256 `json:"amount"`
	Hash     *tktypes.HexUint256 `json:"hash"`
}

var ZetoCoinABI = &abi.Parameter{
	Type:         "tuple",
	InternalType: "struct ZetoCoin",
	Components: abi.ParameterArray{
		{Name: "salt", Type: "uint256"},
		{Name: "owner", Type: "string", Indexed: true},
		{Name: "ownerKey", Type: "bytes32"},
		{Name: "amount", Type: "uint256", Indexed: true},
		{Name: "hash", Type: "uint256"},
	},
}
