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

package snark

import (
	"math/big"
	"testing"

	"github.com/hyperledger-labs/zeto/go-sdk/pkg/key-manager/core"
	"github.com/kaleido-io/paladin/core/pkg/proto"
	"github.com/stretchr/testify/assert"
)

func TestAssembleInputsAnonEnc(t *testing.T) {
	inputs := commonWitnessInputs{}
	key := core.KeyEntry{}
	privateInputs, err := assembleInputs_anon_enc(&inputs, nil, &key)
	assert.NoError(t, err)
	assert.Equal(t, 9, len(privateInputs))
}

func TestAssembleInputsAnonNullifier(t *testing.T) {
	inputs := commonWitnessInputs{
		inputCommitments: []*big.Int{big.NewInt(1), big.NewInt(2)},
		inputValues:      []*big.Int{big.NewInt(3), big.NewInt(4)},
		inputSalts:       []*big.Int{big.NewInt(5), big.NewInt(6)},
	}
	privKey, pubKey, zkpKey := newKeypair()
	key := core.KeyEntry{
		PrivateKey:       privKey,
		PublicKey:        pubKey,
		PrivateKeyForZkp: zkpKey,
	}
	extras := proto.ProvingRequestExtras_Nullifiers{
		Root: "123",
	}
	privateInputs, err := assembleInputs_anon_nullifier(&inputs, &extras, &key)
	assert.NoError(t, err)
	assert.Equal(t, 12, len(privateInputs))
}

func TestAssembleInputsAnonEnc_fail(t *testing.T) {
	inputs := commonWitnessInputs{}
	extras := proto.ProvingRequestExtras_Encryption{
		EncryptionNonce: "1234",
	}
	key := core.KeyEntry{}
	privateInputs, err := assembleInputs_anon_enc(&inputs, &extras, &key)
	assert.NoError(t, err)
	assert.Equal(t, privateInputs["encryptionNonce"], new(big.Int).SetInt64(1234))

	extras.EncryptionNonce = "bad number"
	_, err = assembleInputs_anon_enc(&inputs, &extras, &key)
	assert.EqualError(t, err, "failed to parse encryption nonce")
}

func TestAssembleInputsAnonNullifier_fail(t *testing.T) {
	inputs := commonWitnessInputs{}
	extras := proto.ProvingRequestExtras_Nullifiers{
		Root: "123456",
		MerkleProofs: []*proto.MerkleProof{
			{
				Nodes: []string{"1", "2", "3"},
			},
			{
				Nodes: []string{"0", "0", "0"},
			},
		},
		Enabled: []bool{true, false},
	}
	key := core.KeyEntry{}
	privateInputs, err := assembleInputs_anon_nullifier(&inputs, &extras, &key)
	assert.NoError(t, err)
	assert.Equal(t, "123456", privateInputs["root"].(*big.Int).Text(16))
	assert.Equal(t, "1", privateInputs["enabled"].([]*big.Int)[0].Text(10))
	assert.Equal(t, "0", privateInputs["enabled"].([]*big.Int)[1].Text(10))

	extras.Root = "bad number"
	_, err = assembleInputs_anon_nullifier(&inputs, &extras, &key)
	assert.EqualError(t, err, "failed to parse root")

	extras.Root = "123456"
	extras.MerkleProofs[0].Nodes = []string{"bad number"}
	_, err = assembleInputs_anon_nullifier(&inputs, &extras, &key)
	assert.EqualError(t, err, "failed to parse node")

	inputs = commonWitnessInputs{
		inputCommitments: []*big.Int{big.NewInt(1), big.NewInt(2)},
		inputValues:      []*big.Int{big.NewInt(3), big.NewInt(4)},
		inputSalts:       []*big.Int{big.NewInt(5), big.NewInt(6)},
	}
	privKey, pubKey, _ := newKeypair()
	tooBig, ok := new(big.Int).SetString("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff", 16)
	assert.True(t, ok)
	key = core.KeyEntry{
		PrivateKey:       privKey,
		PublicKey:        pubKey,
		PrivateKeyForZkp: tooBig,
	}
	_, err = assembleInputs_anon_nullifier(&inputs, &extras, &key)
	assert.EqualError(t, err, "failed to calculate nullifier. failed to create the nullifier hash. inputs values not inside Finite Field")
}
