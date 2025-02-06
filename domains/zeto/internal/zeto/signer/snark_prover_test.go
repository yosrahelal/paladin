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

package signer

import (
	"context"
	"fmt"
	"math/big"
	"sync"
	"testing"
	"time"

	"github.com/hyperledger-labs/zeto/go-sdk/pkg/crypto"
	"github.com/hyperledger-labs/zeto/go-sdk/pkg/key-manager/core"
	"github.com/iden3/go-iden3-crypto/poseidon"
	"github.com/iden3/go-rapidsnark/types"
	"github.com/iden3/go-rapidsnark/witness/v2"
	"github.com/kaleido-io/paladin/config/pkg/confutil"
	"github.com/kaleido-io/paladin/domains/zeto/pkg/constants"
	pb "github.com/kaleido-io/paladin/domains/zeto/pkg/proto"
	"github.com/kaleido-io/paladin/domains/zeto/pkg/zetosigner/zetosignerapi"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
)

func TestNewProver(t *testing.T) {
	config := &zetosignerapi.SnarkProverConfig{
		CircuitsDir:    "test",
		ProvingKeysDir: "test",
	}
	prover, err := newSnarkProver(config)
	require.NoError(t, err)
	assert.NotNil(t, prover.circuitsCache)
	assert.NotNil(t, prover.provingKeysCache)
}

func TestSnarkProve(t *testing.T) {
	prover := NewTestProver(t)

	alice := NewTestKeypair()
	bob := NewTestKeypair()

	inputValues := []*big.Int{big.NewInt(30), big.NewInt(40)}
	outputValues := []*big.Int{big.NewInt(32), big.NewInt(38)}

	salt1 := crypto.NewSalt()
	input1, _ := poseidon.Hash([]*big.Int{inputValues[0], salt1, alice.PublicKey.X, alice.PublicKey.Y})
	salt2 := crypto.NewSalt()
	input2, _ := poseidon.Hash([]*big.Int{inputValues[1], salt2, alice.PublicKey.X, alice.PublicKey.Y})
	inputCommitments := []string{input1.Text(16), input2.Text(16)}

	inputValueInts := []uint64{inputValues[0].Uint64(), inputValues[1].Uint64()}
	inputSalts := []string{salt1.Text(16), salt2.Text(16)}
	outputValueInts := []uint64{outputValues[0].Uint64(), outputValues[1].Uint64()}

	alicePubKey := EncodeBabyJubJubPublicKey(alice.PublicKey)
	bobPubKey := EncodeBabyJubJubPublicKey(bob.PublicKey)

	req := pb.ProvingRequest{
		CircuitId: constants.CIRCUIT_ANON,
		Common: &pb.ProvingRequestCommon{
			InputCommitments: inputCommitments,
			InputValues:      inputValueInts,
			InputSalts:       inputSalts,
			InputOwner:       "alice/key0",
			OutputValues:     outputValueInts,
			OutputSalts:      []string{crypto.NewSalt().Text(16), crypto.NewSalt().Text(16)},
			OutputOwners:     []string{bobPubKey, alicePubKey},
		},
	}
	payload, err := proto.Marshal(&req)
	require.NoError(t, err)

	proof, err := prover.Sign(context.Background(), zetosignerapi.AlgoDomainZetoSnarkBJJ("zeto"), zetosignerapi.PAYLOAD_DOMAIN_ZETO_SNARK, alice.PrivateKey[:], payload)
	require.NoError(t, err)
	assert.Equal(t, 36, len(proof))
}

func TestConcurrentSnarkProofGeneration(t *testing.T) {
	config := &zetosignerapi.SnarkProverConfig{
		CircuitsDir:         "test",
		ProvingKeysDir:      "test",
		MaxProverPerCircuit: confutil.P(50), // equal to the default cache size, so all provers can be cached at once
	}
	prover, err := newSnarkProver(config)
	require.NoError(t, err)

	circuitLoadedTotal := 0
	circuitLoadedTotalMutex := &sync.Mutex{}

	peakProverCount := 0
	totalProvingRequestCount := 0
	peakProverCountMutex := &sync.Mutex{}

	testCircuitLoader := func(ctx context.Context, circuitID string, config *zetosignerapi.SnarkProverConfig) (witness.Calculator, []byte, error) {
		circuitLoadedTotalMutex.Lock()
		defer circuitLoadedTotalMutex.Unlock()
		circuitLoadedTotal++
		return &testWitnessCalculator{}, []byte("proving key"), nil
	}
	prover.circuitLoader = testCircuitLoader

	testProofGenerator := func(ctx context.Context, witness []byte, provingKey []byte) (*types.ZKProof, error) {
		peakProverCountMutex.Lock()
		peakProverCount++
		assert.LessOrEqual(t, peakProverCount, 50) // ensure the peak prover count is smaller than the default max
		peakProverCountMutex.Unlock()
		defer func() {
			peakProverCountMutex.Lock()
			peakProverCount--
			totalProvingRequestCount++
			peakProverCountMutex.Unlock()
		}()
		time.Sleep(100 * time.Millisecond) // simulate delay

		return &types.ZKProof{
			Proof: &types.ProofData{
				A:        []string{"a"},
				B:        [][]string{{"b1.1", "b1.2"}, {"b2.1", "b2.2"}},
				C:        []string{"c"},
				Protocol: "super snark",
			},
		}, nil
	}
	prover.proofGenerator = testProofGenerator

	alice := NewTestKeypair()
	bob := NewTestKeypair()

	inputValues := []*big.Int{big.NewInt(30), big.NewInt(40)}
	outputValues := []*big.Int{big.NewInt(32), big.NewInt(38)}

	salt1 := crypto.NewSalt()
	input1, _ := poseidon.Hash([]*big.Int{inputValues[0], salt1, alice.PublicKey.X, alice.PublicKey.Y})
	salt2 := crypto.NewSalt()
	input2, _ := poseidon.Hash([]*big.Int{inputValues[1], salt2, alice.PublicKey.X, alice.PublicKey.Y})
	inputCommitments := []string{input1.Text(16), input2.Text(16)}

	inputValueInts := []uint64{inputValues[0].Uint64(), inputValues[1].Uint64()}
	inputSalts := []string{salt1.Text(16), salt2.Text(16)}
	outputValueInts := []uint64{outputValues[0].Uint64(), outputValues[1].Uint64()}

	alicePubKey := EncodeBabyJubJubPublicKey(alice.PublicKey)
	bobPubKey := EncodeBabyJubJubPublicKey(bob.PublicKey)

	req := pb.ProvingRequest{
		CircuitId: constants.CIRCUIT_ANON,
		Common: &pb.ProvingRequestCommon{
			InputCommitments: inputCommitments,
			InputValues:      inputValueInts,
			InputSalts:       inputSalts,
			InputOwner:       "alice/key0",
			OutputValues:     outputValueInts,
			OutputSalts:      []string{crypto.NewSalt().Text(16), crypto.NewSalt().Text(16)},
			OutputOwners:     []string{bobPubKey, alicePubKey},
		},
	}
	payload, err := proto.Marshal(&req)
	require.NoError(t, err)
	expectReqCount := 500
	reqChan := make(chan struct{}, expectReqCount)

	for i := 0; i < expectReqCount; i++ {
		go func() {
			proof, err := prover.Sign(context.Background(), zetosignerapi.AlgoDomainZetoSnarkBJJ("zeto"), zetosignerapi.PAYLOAD_DOMAIN_ZETO_SNARK, alice.PrivateKey[:], payload)
			require.NoError(t, err)
			assert.Equal(t, 36, len(proof))
			reqChan <- struct{}{}
		}()
	}
	resCount := 0
	for {
		<-reqChan
		resCount++
		if resCount == expectReqCount {
			assert.Equal(t, expectReqCount, totalProvingRequestCount) // check all proving requests has been processed
			assert.Equal(t, 50, circuitLoadedTotal)                   // check cache works as expected, loaded circuit 50 times for 500 proving requests
			break
		}
	}
}

func TestSnarkProveError(t *testing.T) {
	config := &zetosignerapi.SnarkProverConfig{
		CircuitsDir:    "test",
		ProvingKeysDir: "test",
	}
	prover, err := newSnarkProver(config)
	require.NoError(t, err)

	alice := NewTestKeypair()

	// construct a bad payload by using the inner object
	req := pb.ProvingRequestCommon{
		InputCommitments: []string{"input1", "input2"},
		InputValues:      []uint64{30, 40},
		InputSalts:       []string{"salt1", "salt2"},
		InputOwner:       "alice/key0",
		OutputValues:     []uint64{32, 38},
		OutputOwners:     []string{"bob", "alice"},
	}
	payload, err := proto.Marshal(&req)
	require.NoError(t, err)

	_, err = prover.Sign(context.Background(), zetosignerapi.AlgoDomainZetoSnarkBJJ("zeto"), zetosignerapi.PAYLOAD_DOMAIN_ZETO_SNARK, alice.PrivateKey[:], payload)
	assert.ErrorContains(t, err, "cannot parse invalid wire-format data")
}

func TestSnarkProveErrorCircuit(t *testing.T) {
	config := &zetosignerapi.SnarkProverConfig{
		CircuitsDir:    "test",
		ProvingKeysDir: "test",
	}
	prover, err := newSnarkProver(config)
	require.NoError(t, err)

	alice := NewTestKeypair()

	// leave the circuit ID empty
	req := pb.ProvingRequest{
		Common: &pb.ProvingRequestCommon{
			InputCommitments: []string{"input1", "input2"},
			InputValues:      []uint64{30, 40},
			InputSalts:       []string{"salt1", "salt2"},
			InputOwner:       "alice/key0",
			OutputValues:     []uint64{32, 38},
			OutputSalts:      []string{"salt1", "salt2"},
			OutputOwners:     []string{"bob", "alice"},
		},
	}
	payload, err := proto.Marshal(&req)
	require.NoError(t, err)

	_, err = prover.Sign(context.Background(), zetosignerapi.AlgoDomainZetoSnarkBJJ("zeto"), zetosignerapi.PAYLOAD_DOMAIN_ZETO_SNARK, alice.PrivateKey[:], payload)
	assert.ErrorContains(t, err, "circuit ID is required")
}

func TestSnarkProveErrorInputs(t *testing.T) {
	config := &zetosignerapi.SnarkProverConfig{
		CircuitsDir:    "test",
		ProvingKeysDir: "test",
	}
	prover, err := newSnarkProver(config)
	require.NoError(t, err)

	alice := NewTestKeypair()

	req := pb.ProvingRequest{
		CircuitId: constants.CIRCUIT_ANON,
		Common: &pb.ProvingRequestCommon{
			InputCommitments: []string{"input1", "input2"},
			InputValues:      []uint64{30, 40},
			InputSalts:       []string{"salt1", "salt2"},
			OutputValues:     []uint64{32, 38},
			OutputOwners:     []string{"bob", "alice"},
		},
	}
	payload, err := proto.Marshal(&req)
	require.NoError(t, err)
	_, err = prover.Sign(context.Background(), zetosignerapi.AlgoDomainZetoSnarkBJJ("zeto"), zetosignerapi.PAYLOAD_DOMAIN_ZETO_SNARK, alice.PrivateKey[:], payload)
	assert.ErrorContains(t, err, "anon.wasm: no such file or directory")
}

func TestSnarkProveErrorLoadcircuits(t *testing.T) {
	config := &zetosignerapi.SnarkProverConfig{
		CircuitsDir:    "test",
		ProvingKeysDir: "test",
	}
	prover, err := newSnarkProver(config)
	require.NoError(t, err)

	testCircuitLoader := func(ctx context.Context, circuitID string, config *zetosignerapi.SnarkProverConfig) (witness.Calculator, []byte, error) {
		return nil, nil, fmt.Errorf("bang!")
	}
	prover.circuitLoader = testCircuitLoader

	alice := NewTestKeypair()
	bob := NewTestKeypair()

	inputValues := []*big.Int{big.NewInt(30), big.NewInt(40)}
	outputValues := []*big.Int{big.NewInt(32), big.NewInt(38)}

	salt1 := crypto.NewSalt()
	input1, _ := poseidon.Hash([]*big.Int{inputValues[0], salt1, alice.PublicKey.X, alice.PublicKey.Y})
	salt2 := crypto.NewSalt()
	input2, _ := poseidon.Hash([]*big.Int{inputValues[1], salt2, alice.PublicKey.X, alice.PublicKey.Y})
	inputCommitments := []string{input1.Text(16), input2.Text(16)}

	inputValueInts := []uint64{inputValues[0].Uint64(), inputValues[1].Uint64()}
	inputSalts := []string{salt1.Text(16), salt2.Text(16)}
	outputValueInts := []uint64{outputValues[0].Uint64(), outputValues[1].Uint64()}

	alicePubKey := EncodeBabyJubJubPublicKey(alice.PublicKey)
	bobPubKey := EncodeBabyJubJubPublicKey(bob.PublicKey)

	req := pb.ProvingRequest{
		CircuitId: constants.CIRCUIT_ANON,
		Common: &pb.ProvingRequestCommon{
			InputCommitments: inputCommitments,
			InputValues:      inputValueInts,
			InputSalts:       inputSalts,
			InputOwner:       "alice/key0",
			OutputValues:     outputValueInts,
			OutputOwners:     []string{bobPubKey, alicePubKey},
		},
	}
	payload, err := proto.Marshal(&req)
	require.NoError(t, err)

	_, err = prover.Sign(context.Background(), zetosignerapi.AlgoDomainZetoSnarkBJJ("zeto"), zetosignerapi.PAYLOAD_DOMAIN_ZETO_SNARK, alice.PrivateKey[:], payload)
	assert.EqualError(t, err, "bang!")
}

func TestSnarkProveErrorGenerateProof(t *testing.T) {
	config := &zetosignerapi.SnarkProverConfig{
		CircuitsDir:    "test",
		ProvingKeysDir: "test",
	}
	prover, err := newSnarkProver(config)
	require.NoError(t, err)

	testCircuitLoader := func(ctx context.Context, circuitID string, config *zetosignerapi.SnarkProverConfig) (witness.Calculator, []byte, error) {
		return &testWitnessCalculator{}, []byte("proving key"), nil
	}
	prover.circuitLoader = testCircuitLoader

	alice := NewTestKeypair()

	inputValues := []*big.Int{big.NewInt(30), big.NewInt(40)}
	outputValues := []*big.Int{big.NewInt(32), big.NewInt(38)}

	salt1 := crypto.NewSalt()
	input1, _ := poseidon.Hash([]*big.Int{inputValues[0], salt1, alice.PublicKey.X, alice.PublicKey.Y})
	salt2 := crypto.NewSalt()
	input2, _ := poseidon.Hash([]*big.Int{inputValues[1], salt2, alice.PublicKey.X, alice.PublicKey.Y})
	inputCommitments := []string{input1.Text(16), input2.Text(16)}

	inputValueInts := []uint64{inputValues[0].Uint64(), inputValues[1].Uint64()}
	inputSalts := []string{salt1.Text(16), salt2.Text(16)}
	outputValueInts := []uint64{outputValues[0].Uint64(), outputValues[1].Uint64()}

	req := pb.ProvingRequest{
		CircuitId: constants.CIRCUIT_ANON,
		Common: &pb.ProvingRequestCommon{
			InputCommitments: inputCommitments,
			InputValues:      inputValueInts,
			InputSalts:       inputSalts,
			InputOwner:       "alice/key0",
			OutputValues:     outputValueInts,
			OutputOwners:     []string{"badKey1", "badKey2"},
		},
	}
	payload, err := proto.Marshal(&req)
	require.NoError(t, err)

	_, err = prover.Sign(context.Background(), zetosignerapi.AlgoDomainZetoSnarkBJJ("zeto"), zetosignerapi.PAYLOAD_DOMAIN_ZETO_SNARK, alice.PrivateKey[:], payload)
	assert.ErrorContains(t, err, "witness is empty")
}

func TestSnarkProveErrorGenerateProof2(t *testing.T) {
	config := &zetosignerapi.SnarkProverConfig{
		CircuitsDir:    "test",
		ProvingKeysDir: "test",
	}
	prover, err := newSnarkProver(config)
	require.NoError(t, err)

	testCircuitLoader := func(ctx context.Context, circuitID string, config *zetosignerapi.SnarkProverConfig) (witness.Calculator, []byte, error) {
		return &testWitnessCalculator{}, []byte("proving key"), nil
	}
	prover.circuitLoader = testCircuitLoader

	alice := NewTestKeypair()
	bob := NewTestKeypair()

	inputValues := []*big.Int{big.NewInt(30), big.NewInt(40)}
	outputValues := []*big.Int{big.NewInt(32), big.NewInt(38)}

	salt1 := crypto.NewSalt()
	input1, _ := poseidon.Hash([]*big.Int{inputValues[0], salt1, alice.PublicKey.X, alice.PublicKey.Y})
	salt2 := crypto.NewSalt()
	input2, _ := poseidon.Hash([]*big.Int{inputValues[1], salt2, alice.PublicKey.X, alice.PublicKey.Y})
	inputCommitments := []string{input1.Text(16), input2.Text(16)}

	inputValueInts := []uint64{inputValues[0].Uint64(), inputValues[1].Uint64()}
	inputSalts := []string{salt1.Text(16), salt2.Text(16)}
	outputValueInts := []uint64{outputValues[0].Uint64(), outputValues[1].Uint64()}

	alicePubKey := EncodeBabyJubJubPublicKey(alice.PublicKey)
	bobPubKey := EncodeBabyJubJubPublicKey(bob.PublicKey)

	req := pb.ProvingRequest{
		CircuitId: constants.CIRCUIT_ANON,
		Common: &pb.ProvingRequestCommon{
			InputCommitments: []string{"input1", "input2"},
			InputValues:      inputValueInts,
			InputSalts:       inputSalts,
			InputOwner:       "alice/key0",
			OutputValues:     outputValueInts,
			OutputSalts:      []string{crypto.NewSalt().Text(16), crypto.NewSalt().Text(16)},
			OutputOwners:     []string{bobPubKey, alicePubKey},
		},
	}
	payload, err := proto.Marshal(&req)
	require.NoError(t, err)
	_, err = prover.Sign(context.Background(), zetosignerapi.AlgoDomainZetoSnarkBJJ("zeto"), zetosignerapi.PAYLOAD_DOMAIN_ZETO_SNARK, alice.PrivateKey[:], payload)
	assert.ErrorContains(t, err, "PD210084: Failed to parse input commitment")

	req = pb.ProvingRequest{
		CircuitId: constants.CIRCUIT_ANON,
		Common: &pb.ProvingRequestCommon{
			InputCommitments: inputCommitments,
			InputValues:      inputValueInts,
			InputSalts:       []string{"salt1", "salt2"},
			InputOwner:       "alice/key0",
			OutputValues:     outputValueInts,
			OutputSalts:      []string{crypto.NewSalt().Text(16), crypto.NewSalt().Text(16)},
			OutputOwners:     []string{bobPubKey, alicePubKey},
		},
	}
	payload, err = proto.Marshal(&req)
	require.NoError(t, err)
	_, err = prover.Sign(context.Background(), zetosignerapi.AlgoDomainZetoSnarkBJJ("zeto"), zetosignerapi.PAYLOAD_DOMAIN_ZETO_SNARK, alice.PrivateKey[:], payload)
	assert.ErrorContains(t, err, "PD210082: Failed to parse input salt")
}

func TestValidateInputs(t *testing.T) {
	ctx := context.Background()
	inputs1 := &pb.ProvingRequestCommon{
		InputCommitments: []string{"input1", "input2"},
		InputValues:      []uint64{30},
		InputSalts:       []string{"salt1", "salt2"},
	}
	err := validateInputsFungible(ctx, inputs1)
	assert.ErrorContains(t, err, "input commitments, values, and salts must have the same length")

	inputs2 := &pb.ProvingRequestCommon{
		InputCommitments: []string{"input1", "input2"},
		InputValues:      []uint64{30, 40},
		InputSalts:       []string{"salt1"},
	}
	err = validateInputsFungible(ctx, inputs2)
	assert.ErrorContains(t, err, "input commitments, values, and salts must have the same length")

	inputs3 := &pb.ProvingRequestCommon{
		InputCommitments: []string{"input1", "input2"},
		InputValues:      []uint64{30, 40},
		InputSalts:       []string{"salt1", "salt2"},
		OutputValues:     []uint64{32, 38},
		OutputOwners:     []string{"bob"},
	}
	err = validateInputsFungible(ctx, inputs3)
	assert.ErrorContains(t, err, "output values and owner keys must have the same length")
}

func TestSerializeProofResponse(t *testing.T) {
	snark := types.ZKProof{
		Proof: &types.ProofData{
			A: []string{"a"},
			B: [][]string{
				{"b1.1", "b1.2"},
				{"b2.1", "b2.2"},
			},
			C: []string{"c"},
		},
		PubSignals: []string{"1", "2", "3", "4", "5", "6", "7", "8", "9", "10", "11", "12", "13", "14", "15"},
	}
	bytes, err := serializeProofResponse(constants.CIRCUIT_ANON_ENC, &snark)
	assert.NoError(t, err)
	assert.Equal(t, 118, len(bytes))

	bytes, err = serializeProofResponse(constants.CIRCUIT_ANON_NULLIFIER, &snark)
	assert.NoError(t, err)
	assert.Equal(t, 66, len(bytes))

	snark.PubSignals = []string{
		"1", "2", "3", "4", "5", "6", "7", "8", "9", "10", "11", "12", "13", "14", "15", "16", "17", "18", "19", "20",
		"1", "2", "3", "4", "5", "6", "7", "8", "9", "10", "11", "12", "13", "14", "15", "16", "17", "18", "19", "20",
		"1", "2", "3", "4", "5", "6", "7", "8", "9", "10", "11", "12", "13", "14", "15", "16", "17", "18", "19", "20",
		"1", "2", "3"}
	bytes, err = serializeProofResponse(constants.CIRCUIT_ANON_ENC_BATCH, &snark)
	assert.NoError(t, err)
	assert.Equal(t, 202, len(bytes))

	snark.PubSignals = []string{"1", "2", "3", "4", "5", "6", "7", "8", "9", "10", "11"}
	bytes, err = serializeProofResponse(constants.CIRCUIT_ANON_NULLIFIER_BATCH, &snark)
	assert.NoError(t, err)
	assert.Equal(t, 84, len(bytes))

	bytes, err = serializeProofResponse(constants.CIRCUIT_WITHDRAW_NULLIFIER, &snark)
	assert.NoError(t, err)
	assert.Equal(t, 66, len(bytes))

	snark.PubSignals = []string{
		"1", "2", "3", "4", "5", "6", "7", "8", "9", "10", "11", "12", "13", "14", "15", "16", "17", "18", "19", "20",
		"1", "2", "3", "4", "5", "6", "7", "8", "9", "10", "11", "12", "13", "14", "15", "16", "17", "18", "19", "20",
		"1", "2", "3", "4", "5", "6", "7", "8", "9", "10", "11", "12", "13", "14", "15", "16", "17", "18", "19", "20",
		"1", "2", "3"}
	bytes, err = serializeProofResponse(constants.CIRCUIT_WITHDRAW_NULLIFIER_BATCH, &snark)
	assert.NoError(t, err)
	assert.Equal(t, 85, len(bytes))
}

func TestZKPProverInvalidAlgos(t *testing.T) {
	ctx := context.Background()
	config := &zetosignerapi.SnarkProverConfig{
		CircuitsDir:    "test",
		ProvingKeysDir: "test",
	}
	prover, err := newSnarkProver(config)
	require.NoError(t, err)

	_, err = prover.GetVerifier(ctx, "domain:zeto:unsupported", "", nil)
	assert.Regexp(t, "algorithm", err)

	_, err = prover.GetVerifier(ctx, zetosignerapi.AlgoDomainZetoSnarkBJJ("zeto"), "not_hex", nil)
	assert.Regexp(t, "verifier", err)

	_, err = prover.GetVerifier(ctx, zetosignerapi.AlgoDomainZetoSnarkBJJ("zeto"), zetosignerapi.IDEN3_PUBKEY_BABYJUBJUB_COMPRESSED_0X, nil)
	assert.Regexp(t, "Invalid key", err)

	_, err = prover.Sign(ctx, "domain:zeto:unsupported", "", nil, nil)
	assert.Regexp(t, "algorithm", err)

	_, err = prover.Sign(ctx, zetosignerapi.AlgoDomainZetoSnarkBJJ("zeto"), "domain:zeto:unsupported", nil, nil)
	assert.Regexp(t, "payloadType", err)

	_, err = prover.GetMinimumKeyLen(ctx, "domain:zeto:unsupported")
	assert.Regexp(t, "algorithm", err)

	keyLen, err := prover.GetMinimumKeyLen(ctx, zetosignerapi.AlgoDomainZetoSnarkBJJ("zeto"))
	require.NoError(t, err)
	assert.Equal(t, 32, keyLen)
}

func TestGetCircuitId(t *testing.T) {
	inputs := &pb.ProvingRequest{
		CircuitId: constants.CIRCUIT_ANON_ENC,
		Common: &pb.ProvingRequestCommon{
			InputCommitments: []string{"input1", "input2"},
		},
	}
	circuitId := getCircuitId(inputs)
	assert.Equal(t, constants.CIRCUIT_ANON_ENC, circuitId)

	inputs.Common.InputCommitments = []string{"input1", "input2", "input3"}
	circuitId = getCircuitId(inputs)
	assert.Equal(t, constants.CIRCUIT_ANON_ENC_BATCH, circuitId)
}

func TestValidateInputsNonFungible(t *testing.T) {
	ctx := context.Background()

	// Test case where input commitments and salts have different lengths
	inputs1 := &pb.ProvingRequestCommon{
		InputCommitments: []string{"input1", "input2"},
		InputSalts:       []string{"salt1"},
	}
	err := validateInputsNonFungible(ctx, inputs1)
	assert.ErrorContains(t, err, "input commitments, values, and salts must have the same length")

	// Test case where input commitments and salts have the same lengths
	inputs2 := &pb.ProvingRequestCommon{
		InputCommitments: []string{"input1", "input2"},
		InputSalts:       []string{"salt1", "salt2"},
	}
	err = validateInputsNonFungible(ctx, inputs2)
	assert.NoError(t, err)
}

func TestCalculateWitnesssss(t *testing.T) {
	ctx := context.Background()
	privKey, ok := new(big.Int).SetString("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff", 16)
	require.True(t, ok)
	keyEntry := &core.KeyEntry{
		PrivateKeyForZkp: privKey,
	}

	tests := []struct {
		name        string
		circuit     string
		inputs      *pb.ProvingRequestCommon
		extras      interface{}
		keyEntry    *core.KeyEntry
		expectErr   bool
		errContains string
		loadCircuit bool
	}{
		{
			name:    "Invalid encryption nonce",
			circuit: constants.CIRCUIT_ANON_ENC,
			inputs: &pb.ProvingRequestCommon{
				InputCommitments: []string{"1234567890123456789012345678901234567890123456789012345678901234", "1234567890123456789012345678901234567890123456789012345678901234"},
				InputValues:      []uint64{10, 20},
				InputSalts:       []string{"1234567890123456789012345678901234567890123456789012345678901234", "1234567890123456789012345678901234567890123456789012345678901234"},
				InputOwner:       "7cdd539f3ed6c283494f47d8481f84308a6d7043087fb6711c9f1df04e2b8025",
				OutputValues:     []uint64{30, 0},
				OutputSalts:      []string{"1234567890123456789012345678901234567890123456789012345678901234", "1234567890123456789012345678901234567890123456789012345678901234"},
				OutputOwners:     []string{"7cdd539f3ed6c283494f47d8481f84308a6d7043087fb6711c9f1df04e2b8025", "7cdd539f3ed6c283494f47d8481f84308a6d7043087fb6711c9f1df04e2b8025"},
			},
			extras: &pb.ProvingRequestExtras_Encryption{
				EncryptionNonce: "bad number",
			},
			expectErr:   true,
			errContains: "PD210077: Failed to parse encryption nonce",
		},
		{
			name:    "Invalid nullifier calculation",
			circuit: constants.CIRCUIT_ANON_NULLIFIER,
			inputs: &pb.ProvingRequestCommon{
				InputCommitments: []string{"1234567890123456789012345678901234567890123456789012345678901234", "1234567890123456789012345678901234567890123456789012345678901234"},
				InputValues:      []uint64{10, 20},
				InputSalts:       []string{"1234567890123456789012345678901234567890123456789012345678901234", "1234567890123456789012345678901234567890123456789012345678901234"},
				InputOwner:       "7cdd539f3ed6c283494f47d8481f84308a6d7043087fb6711c9f1df04e2b8025",
				OutputValues:     []uint64{30, 0},
				OutputSalts:      []string{"1234567890123456789012345678901234567890123456789012345678901234", "1234567890123456789012345678901234567890123456789012345678901234"},
				OutputOwners:     []string{"7cdd539f3ed6c283494f47d8481f84308a6d7043087fb6711c9f1df04e2b8025", "7cdd539f3ed6c283494f47d8481f84308a6d7043087fb6711c9f1df04e2b8025"},
			},
			extras: &pb.ProvingRequestExtras_Nullifiers{
				Root: "123456",
				MerkleProofs: []*pb.MerkleProof{
					{Nodes: []string{"1", "2", "3"}},
					{Nodes: []string{"0", "0", "0"}},
				},
				Enabled: []bool{true, false},
			},
			keyEntry:    keyEntry,
			expectErr:   true,
			errContains: "PD210079: Failed to calculate nullifier. inputs values not inside Finite Field",
		},
		{
			name:        "Failed witness calculation",
			circuit:     constants.CIRCUIT_DEPOSIT,
			inputs:      &pb.ProvingRequestCommon{},
			keyEntry:    keyEntry,
			loadCircuit: true,
			expectErr:   true,
			errContains: "PD210100: failed to calculate the witness",
		},
		{
			name:    "Withdraw failure",
			circuit: constants.CIRCUIT_WITHDRAW,
			inputs: &pb.ProvingRequestCommon{
				InputCommitments: []string{"1234567890123456789012345678901234567890123456789012345678901234", "1234567890123456789012345678901234567890123456789012345678901234"},
				InputValues:      []uint64{10, 20},
				InputSalts:       []string{"1234567890123456789012345678901234567890123456789012345678901234", "1234567890123456789012345678901234567890123456789012345678901234"},
				InputOwner:       "7cdd539f3ed6c283494f47d8481f84308a6d7043087fb6711c9f1df04e2b8025",
				OutputValues:     []uint64{30, 0},
				OutputSalts:      []string{"1234567890123456789012345678901234567890123456789012345678901234", "1234567890123456789012345678901234567890123456789012345678901234"},
				OutputOwners:     []string{"7cdd539f3ed6c283494f47d8481f84308a6d7043087fb6711c9f1df04e2b8025", "7cdd539f3ed6c283494f47d8481f84308a6d7043087fb6711c9f1df04e2b8025"},
			},
			keyEntry:    keyEntry,
			loadCircuit: true,
			expectErr:   true,
			errContains: "PD210100: failed to calculate the witness",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var circuit witness.Calculator
			if tc.loadCircuit {
				circuit, _ = loadTestCircuit(t)
			}

			_, err := calculateWitness(ctx, tc.circuit, tc.inputs, tc.extras, tc.keyEntry, circuit)

			if tc.expectErr {
				require.Error(t, err, "expected error in test case %q", tc.name)
				assert.Contains(t, err.Error(), tc.errContains, "error message should contain %q", tc.errContains)
			} else {
				require.NoError(t, err, "unexpected error in test case %q", tc.name)
			}
		})
	}
}

func TestBuildInputs(t *testing.T) {
	ctx := context.Background()

	alice := NewTestKeypair()
	sender := alice.PublicKey.Compress().String()
	bob := NewTestKeypair()
	receiver := bob.PublicKey.Compress().String()

	tests := []struct {
		name         string
		circuitId    string
		commonInputs *pb.ProvingRequestCommon
		expectErr    bool
		errContains  string
		validateFunc func(*testing.T, *commonWitnessInputs)
	}{
		{
			name:      "Successful Non-Fungible Circuit",
			circuitId: constants.CIRCUIT_NF_ANON,
			commonInputs: &pb.ProvingRequestCommon{
				InputCommitments:  []string{"1", "2"},
				InputSalts:        []string{"3", "4"},
				OutputCommitments: []string{"10", "20"},
				OutputSalts:       []string{"5", "6"},
				OutputOwners:      []string{sender, receiver},
			},
			expectErr: false,
			validateFunc: func(t *testing.T, inputs *commonWitnessInputs) {
				assert.Equal(t, 2, len(inputs.outputOwnerPublicKeys))
				assert.Equal(t, alice.PublicKey.X.Text(10), inputs.outputOwnerPublicKeys[0][0].Text(10))
				assert.Equal(t, alice.PublicKey.Y.Text(10), inputs.outputOwnerPublicKeys[0][1].Text(10))
				assert.Equal(t, bob.PublicKey.X.Text(10), inputs.outputOwnerPublicKeys[1][0].Text(10))
				assert.Equal(t, bob.PublicKey.Y.Text(10), inputs.outputOwnerPublicKeys[1][1].Text(10))
			},
		},
		{
			name:      "Successful Fungible Circuit",
			circuitId: constants.CIRCUIT_DEPOSIT,
			commonInputs: &pb.ProvingRequestCommon{
				InputCommitments: []string{"1", "2"},
				InputValues:      []uint64{10, 20},
				InputSalts:       []string{"3", "4"},
				OutputValues:     []uint64{30, 0},
				OutputSalts:      []string{"5", "0"},
				OutputOwners:     []string{sender, receiver},
			},
			expectErr: false,
			validateFunc: func(t *testing.T, inputs *commonWitnessInputs) {
				assert.Equal(t, 2, len(inputs.outputOwnerPublicKeys))
				assert.Equal(t, "0", inputs.outputOwnerPublicKeys[1][0].Text(10))
				assert.Equal(t, "0", inputs.outputOwnerPublicKeys[1][1].Text(10))
			},
		},
		{
			name:      "Invalid Non-Fungible Input Commitment",
			circuitId: constants.CIRCUIT_NF_ANON,
			commonInputs: &pb.ProvingRequestCommon{
				InputCommitments:  []string{"XYZ", "2"}, // Invalid hex
				InputSalts:        []string{"3", "4"},
				OutputCommitments: []string{"10", "20"},
				OutputSalts:       []string{"5", "6"},
				OutputOwners:      []string{sender, receiver},
			},
			expectErr:   true,
			errContains: "PD210084: Failed to parse input commitment",
		},
		{
			name:      "Invalid Fungible Output Salt",
			circuitId: constants.CIRCUIT_DEPOSIT,
			commonInputs: &pb.ProvingRequestCommon{
				InputCommitments: []string{"1", "2"},
				InputValues:      []uint64{10, 20},
				InputSalts:       []string{"3", "4"},
				OutputValues:     []uint64{30, 0},
				OutputSalts:      []string{"XYZ", "6"}, // Invalid hex
				OutputOwners:     []string{sender, receiver},
			},
			expectErr:   true,
			errContains: "PD210083: Failed to parse output salt",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			inputs, err := buildInputs(ctx, tc.circuitId, tc.commonInputs, nil)

			if tc.expectErr {
				require.Error(t, err, "expected error in test case %q", tc.name)
				assert.Contains(t, err.Error(), tc.errContains, "error message should contain %q", tc.errContains)
			} else {
				require.NoError(t, err, "unexpected error in test case %q", tc.name)
				require.NotNil(t, inputs, "expected non-nil circuit inputs")
				if tc.validateFunc != nil {
					tc.validateFunc(t, inputs)
				}
			}
		})
	}
}
func TestAssembleWitnessInputs(t *testing.T) {
	ctx := context.Background()
	privKey, ok := new(big.Int).SetString("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff", 16)
	require.True(t, ok)
	keyEntry := &core.KeyEntry{
		PrivateKeyForZkp: privKey,
	}

	tests := []struct {
		name        string
		circuitId   string
		inputs      *commonWitnessInputs
		extras      interface{}
		expectErr   bool
		errContains string
	}{
		{
			name:      "Valid anon circuit",
			circuitId: constants.CIRCUIT_ANON,
			inputs:    &commonWitnessInputs{},
			extras:    nil,
			expectErr: false,
		},
		{
			name:      "Valid non-fungible circuit",
			circuitId: constants.CIRCUIT_NF_ANON,
			inputs:    &commonWitnessInputs{},
			extras:    &pb.ProvingRequestExtras_NonFungible{},
			expectErr: false,
		},
		{
			name:        "Invalid non-fungible circuit extras type",
			circuitId:   constants.CIRCUIT_NF_ANON,
			inputs:      &commonWitnessInputs{},
			extras:      &pb.ProvingRequestExtras_Encryption{},
			expectErr:   true,
			errContains: "unexpected extras type for non-fungible circuit",
		},
		{
			name:      "Valid encryption circuit",
			circuitId: constants.CIRCUIT_ANON_ENC,
			inputs:    &commonWitnessInputs{},
			extras:    &pb.ProvingRequestExtras_Encryption{},
			expectErr: false,
		},
		{
			name:        "Invalid encryption circuit extras type",
			circuitId:   constants.CIRCUIT_ANON_ENC,
			inputs:      &commonWitnessInputs{},
			extras:      &pb.ProvingRequestExtras_NonFungible{},
			expectErr:   true,
			errContains: "unexpected extras type for encryption circuit",
		},
		{
			name:        "Invalid anon nullifier circuit extras type",
			circuitId:   constants.CIRCUIT_ANON_NULLIFIER,
			inputs:      &commonWitnessInputs{},
			extras:      &pb.ProvingRequestExtras_Encryption{},
			expectErr:   true,
			errContains: "unexpected extras type for anon nullifier circuit",
		},
		{
			name:      "Valid deposit circuit",
			circuitId: constants.CIRCUIT_DEPOSIT,
			inputs:    &commonWitnessInputs{},
			extras:    nil,
			expectErr: false,
		},
		{
			name:      "Valid withdraw circuit",
			circuitId: constants.CIRCUIT_WITHDRAW,
			inputs:    &commonWitnessInputs{},
			extras:    nil,
			expectErr: false,
		},
		{
			name:        "Invalid withdraw nullifier circuit extras type",
			circuitId:   constants.CIRCUIT_WITHDRAW_NULLIFIER,
			inputs:      &commonWitnessInputs{},
			extras:      &pb.ProvingRequestExtras_Encryption{},
			expectErr:   true,
			errContains: "unexpected extras type for withdraw nullifier circuit",
		},
		{
			name:      "Valid lock circuit",
			circuitId: constants.CIRCUIT_LOCK,
			inputs:    &commonWitnessInputs{},
			extras:    nil,
			expectErr: false,
		},
		{
			name:        "Unsupported circuit id",
			circuitId:   "unsupported_circuit",
			inputs:      &commonWitnessInputs{},
			extras:      nil,
			expectErr:   true,
			errContains: "unsupported circuit id",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := assembleWitnessInputs(ctx, tc.circuitId, tc.inputs, tc.extras, keyEntry)

			if tc.expectErr {
				require.Error(t, err, "expected error in test case %q", tc.name)
				assert.Contains(t, err.Error(), tc.errContains, "error message should contain %q", tc.errContains)
			} else {
				require.NoError(t, err, "unexpected error in test case %q", tc.name)
			}
		})
	}
}
