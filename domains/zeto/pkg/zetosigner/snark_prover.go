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

package zetosigner

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"

	"github.com/hyperledger-labs/zeto/go-sdk/pkg/key-manager/core"
	"github.com/hyperledger-labs/zeto/go-sdk/pkg/key-manager/key"
	"github.com/iden3/go-rapidsnark/prover"
	"github.com/iden3/go-rapidsnark/types"
	"github.com/iden3/go-rapidsnark/witness/v2"
	pb "github.com/kaleido-io/paladin/core/pkg/proto"
	"github.com/kaleido-io/paladin/toolkit/pkg/cache"
	"github.com/kaleido-io/paladin/toolkit/pkg/confutil"
	"github.com/kaleido-io/paladin/toolkit/pkg/verifiers"
	"google.golang.org/protobuf/proto"
)

var defaultSnarkProverConfig = SnarkProverConfig{
	MaxProverPerCircuit: confutil.P(10),
}

// snarkProver encapsulates the logic for generating SNARK proofs
type snarkProver struct {
	zkpProverConfig         *SnarkProverConfig
	circuitsCache           cache.Cache[string, witness.Calculator]
	provingKeysCache        cache.Cache[string, []byte]
	proverCacheRWLock       sync.RWMutex
	workerPerCircuit        int
	circuitsWorkerIndexChan map[string]chan int
	circuitLoader           func(circuitID string, config *SnarkProverConfig) (witness.Calculator, []byte, error)
	proofGenerator          func(witness []byte, provingKey []byte) (*types.ZKProof, error)
}

func newSnarkProver(conf *SnarkProverConfig) (*snarkProver, error) {
	cacheConfig := cache.Config{
		Capacity: confutil.P(50),
	}
	return &snarkProver{
		zkpProverConfig:         conf,
		circuitsCache:           cache.NewCache[string, witness.Calculator](&cacheConfig, &cacheConfig),
		provingKeysCache:        cache.NewCache[string, []byte](&cacheConfig, &cacheConfig),
		circuitLoader:           loadCircuit,
		proofGenerator:          generateProof,
		workerPerCircuit:        confutil.Int(conf.MaxProverPerCircuit, *defaultSnarkProverConfig.MaxProverPerCircuit),
		circuitsWorkerIndexChan: make(map[string]chan int),
	}, nil
}

func (sp *snarkProver) GetVerifier(ctx context.Context, algorithm, verifierType string, privateKey []byte) (string, error) {
	if algorithm != ALGO_DOMAIN_ZETO_SNARK_BJJ {
		return "", fmt.Errorf("'%s' does not match supported algorithm '%s'", algorithm, ALGO_DOMAIN_ZETO_SNARK_BJJ)
	}
	if verifierType != verifiers.HEX_PUBKEY_0X_PREFIX {
		return "", fmt.Errorf("'%s' does not match supported verifierType '%s'", algorithm, verifiers.HEX_PUBKEY_0X_PREFIX)
	}
	pk, err := NewBabyJubJubPrivateKey(privateKey)
	if err != nil {
		return "", err
	}
	return EncodeBabyJubJubPublicKey(pk.Public()), nil
}

func (sp *snarkProver) GetMinimumKeyLen(ctx context.Context, algorithm string) (int, error) {
	if algorithm != ALGO_DOMAIN_ZETO_SNARK_BJJ {
		return -1, fmt.Errorf("'%s' does not match supported algorithm '%s'", algorithm, ALGO_DOMAIN_ZETO_SNARK_BJJ)
	}
	return 32, nil
}

func (sp *snarkProver) Sign(ctx context.Context, algorithm, payloadType string, privateKey, payload []byte) ([]byte, error) {
	if algorithm != ALGO_DOMAIN_ZETO_SNARK_BJJ {
		return nil, fmt.Errorf("'%s' does not match supported algorithm '%s'", algorithm, ALGO_DOMAIN_ZETO_SNARK_BJJ)
	}
	if payloadType != PAYLOAD_DOMAIN_ZETO_SNARK {
		return nil, fmt.Errorf("'%s' does not match supported payloadType '%s'", payloadType, PAYLOAD_DOMAIN_ZETO_SNARK)
	}

	keyBytes := [32]byte{}
	copy(keyBytes[:], privateKey)
	keyEntry := key.NewKeyEntryFromPrivateKeyBytes(keyBytes)

	inputs, extras, err := decodeProvingRequest(payload)
	if err != nil {
		return nil, err
	}
	// Perform proof generation
	if inputs.CircuitId == "" {
		return nil, errors.New("circuit ID is required")
	}
	if err := validateInputs(inputs.Common); err != nil {
		return nil, err
	}

	// obtain a slot for the proof generation for this specific circuit
	ccChan, chanelFound := sp.circuitsWorkerIndexChan[inputs.CircuitId]
	if !chanelFound {
		ccChan = make(chan int, sp.workerPerCircuit) // init token channel
		for i := 0; i < sp.workerPerCircuit; i++ {
			ccChan <- i // add all tokens
		}
		sp.circuitsWorkerIndexChan[inputs.CircuitId] = ccChan
	}
	var workerIndex int
	select {
	case workerIndex = <-ccChan: // wait till there is a worker available
		defer func() {
			// put the worker index back into the queue upon function exit
			ccChan <- workerIndex
		}()
	case <-ctx.Done():
		return nil, errors.New("context cancelled")
	}

	workerID := fmt.Sprintf("%s-%d", inputs.CircuitId, workerIndex)
	// Perform proof generation
	// Read lock to check the cache
	sp.proverCacheRWLock.RLock()
	circuit, _ := sp.circuitsCache.Get(workerID)
	provingKey, _ := sp.provingKeysCache.Get(workerID)
	sp.proverCacheRWLock.RUnlock() // release the lock, happy path, 1 lock is good enough
	if circuit == nil || provingKey == nil {
		sp.proverCacheRWLock.Lock()
		// obtain the W&R lock and check again
		circuit, _ = sp.circuitsCache.Get(workerID)
		provingKey, _ = sp.provingKeysCache.Get(workerID)
		if circuit == nil || provingKey == nil {
			// the generated WASM instance can only generate one proof at a time, circuitsWorkerIndexChan is used to ensure only 1 proof request
			// is served per WASM instance at any given time
			c, p, err := sp.circuitLoader(inputs.CircuitId, sp.zkpProverConfig)
			if err != nil {
				return nil, err
			}
			sp.circuitsCache.Set(workerID, c)
			sp.provingKeysCache.Set(workerID, p)
			circuit = c
			provingKey = p
		}

		sp.proverCacheRWLock.Unlock()
	}
	wtns, publicInputs, err := calculateWitness(inputs.CircuitId, inputs.Common, extras, keyEntry, circuit)
	if err != nil {
		return nil, err
	}

	proof, err := sp.proofGenerator(wtns, provingKey)
	if err != nil {
		return nil, err
	}

	proofBytes, err := serializeProofResponse(inputs.CircuitId, proof, publicInputs)
	if err != nil {
		return nil, err
	}

	return proofBytes, nil
}

func validateInputs(inputs *pb.ProvingRequestCommon) error {
	if len(inputs.InputCommitments) == 0 {
		return errors.New("input commitments are required")
	}
	if len(inputs.InputValues) == 0 {
		return errors.New("input values are required")
	}
	if len(inputs.InputSalts) == 0 {
		return errors.New("input salts are required")
	}
	if len(inputs.InputCommitments) != len(inputs.InputValues) || len(inputs.InputCommitments) != len(inputs.InputSalts) {
		return errors.New("input commitments, values, and salts must have the same length")
	}
	if len(inputs.OutputValues) == 0 {
		return errors.New("output values are required")
	}
	if len(inputs.OutputOwners) == 0 {
		return errors.New("output owner keys are required")
	}
	if len(inputs.OutputValues) != len(inputs.OutputOwners) {
		return errors.New("output values and owner keys must have the same length")
	}
	return nil
}

func serializeProofResponse(circuitId string, proof *types.ZKProof, publicInputs map[string]string) ([]byte, error) {
	snark := pb.SnarkProof{}
	snark.A = proof.Proof.A
	snark.B = make([]*pb.B_Item, 0, len(proof.Proof.B))
	for _, p := range proof.Proof.B {
		bItems := pb.B_Item{}
		bItems.Items = append(bItems.Items, p...)
		snark.B = append(snark.B, &bItems)
	}
	snark.C = proof.Proof.C

	switch circuitId {
	case "anon_enc":
		publicInputs["encryptedValues"] = strings.Join(proof.PubSignals[0:4], ",")
	}

	res := pb.ProvingResponse{
		Proof:        &snark,
		PublicInputs: publicInputs,
	}

	return proto.Marshal(&res)
}

func calculateWitness(circuitId string, commonInputs *pb.ProvingRequestCommon, extras interface{}, keyEntry *core.KeyEntry, circuit witness.Calculator) ([]byte, map[string]string, error) {
	inputs, err := buildCircuitInputs(commonInputs)
	if err != nil {
		return nil, nil, err
	}

	var witnessInputs map[string]any
	var publicInputs map[string]string
	switch circuitId {
	case "anon":
		witnessInputs = assembleInputs_anon(inputs, keyEntry)
	case "anon_enc":
		witnessInputs, publicInputs, err = assembleInputs_anon_enc(inputs, extras.(*pb.ProvingRequestExtras_Encryption), keyEntry)
		if err != nil {
			return nil, nil, err
		}
	}

	wtns, err := circuit.CalculateWTNSBin(witnessInputs, true)
	if err != nil {
		return nil, nil, err
	}

	return wtns, publicInputs, nil
}

func generateProof(wtns, provingKey []byte) (*types.ZKProof, error) {
	proof, err := prover.Groth16Prover(provingKey, wtns)
	if err != nil {
		return nil, err
	}
	return proof, nil
}
