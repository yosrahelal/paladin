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
	"context"
	"math/big"

	"github.com/hyperledger/firefly-common/pkg/i18n"
	"github.com/hyperledger/firefly-signer/pkg/abi"
	"github.com/iden3/go-iden3-crypto/poseidon"
	"github.com/kaleido-io/paladin/domains/zeto/internal/msgs"
	"github.com/kaleido-io/paladin/domains/zeto/pkg/zetosigner"
	"github.com/kaleido-io/paladin/toolkit/pkg/tktypes"
)

type ZetoCoinState struct {
	ID              tktypes.HexUint256 `json:"id"`
	Created         tktypes.Timestamp  `json:"created"`
	ContractAddress tktypes.EthAddress `json:"contractAddress"`
	Data            ZetoCoin           `json:"data"`
}

type ZetoCoin struct {
	Salt     *tktypes.HexUint256 `json:"salt"`
	Owner    string              `json:"owner"`
	OwnerKey tktypes.HexBytes    `json:"ownerKey"`
	Amount   *tktypes.HexUint256 `json:"amount"`
	hash     *tktypes.HexUint256
}

func (z *ZetoCoin) Hash(ctx context.Context) (*tktypes.HexUint256, error) {
	if z.hash == nil {
		ownerKey, err := zetosigner.DecodeBabyJubJubPublicKey(z.OwnerKey.HexString())
		if err != nil {
			return nil, i18n.NewError(ctx, msgs.MsgErrorDecodeBJJKey, err)
		}
		commitment, err := poseidon.Hash([]*big.Int{
			z.Amount.Int(),
			z.Salt.Int(),
			ownerKey.X,
			ownerKey.Y,
		})
		if err != nil {
			return nil, err
		}
		z.hash = (*tktypes.HexUint256)(commitment)
	}
	return z.hash, nil
}

var ZetoCoinABI = &abi.Parameter{
	Type:         "tuple",
	InternalType: "struct ZetoCoin",
	Components: abi.ParameterArray{
		{Name: "salt", Type: "uint256"},
		{Name: "owner", Type: "string", Indexed: true},
		{Name: "ownerKey", Type: "bytes32"},
		{Name: "amount", Type: "uint256", Indexed: true},
	},
}
