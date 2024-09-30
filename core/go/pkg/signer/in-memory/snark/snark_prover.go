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
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"

	"github.com/hyperledger-labs/zeto/go-sdk/pkg/key-manager/core"
	"github.com/hyperledger-labs/zeto/go-sdk/pkg/key-manager/key"
	"github.com/hyperledger/firefly-common/pkg/i18n"
	"github.com/iden3/go-rapidsnark/prover"
	"github.com/iden3/go-rapidsnark/types"
	"github.com/iden3/go-rapidsnark/witness/v2"
	"github.com/kaleido-io/paladin/core/internal/cache"
	"github.com/kaleido-io/paladin/core/internal/msgs"
	pb "github.com/kaleido-io/paladin/core/pkg/proto"
	"github.com/kaleido-io/paladin/core/pkg/signer/signerapi"
	"github.com/kaleido-io/paladin/toolkit/pkg/algorithms"
	"github.com/kaleido-io/paladin/toolkit/pkg/confutil"
	"github.com/kaleido-io/paladin/toolkit/pkg/log"
	"google.golang.org/protobuf/proto"
)

var defaultSnarkProverConfig = signerapi.SnarkProverConfig{
	MaxProverPerCircuit: confutil.P(10),
}

// snarkProver encapsulates the logic for generating SNARK proofs
type snarkProver struct {
	zkpProverConfig         signerapi.SnarkProverConfig
	circuitsCache           cache.Cache[string, witness.Calculator]
	provingKeysCache        cache.Cache[string, []byte]
	proverCacheRWLock       sync.RWMutex
	workerPerCircuit        int
	circuitsWorkerIndexChan map[string]chan int
	circuitLoader           func(circuitID string, config signerapi.SnarkProverConfig) (witness.Calculator, []byte, error)
	proofGenerator          func(witness []byte, provingKey []byte) (*types.ZKProof, error)
}

func Register(ctx context.Context, config signerapi.SnarkProverConfig, registry map[string]signerapi.InMemorySigner) error {
	// skip registration is no ZKP prover config is provided
	if config.CircuitsDir == "" || config.ProvingKeysDir == "" {
		log.L(ctx).Info("zkp prover not configured, skip registering as an in-memory signer")
		return nil
	}

	signer, err := newSnarkProver(config)
	if err != nil {
		return err
	}
	registry[algorithms.ZKP_BABYJUBJUB_PLAINBYTES] = signer
	return nil
}

func newSnarkProver(config signerapi.SnarkProverConfig) (*snarkProver, error) {
	cacheConfig := cache.Config{
		Capacity: confutil.P(50),
	}
	return &snarkProver{
		zkpProverConfig:         config,
		circuitsCache:           cache.NewCache[string, witness.Calculator](&cacheConfig, &cacheConfig),
		provingKeysCache:        cache.NewCache[string, []byte](&cacheConfig, &cacheConfig),
		circuitLoader:           loadCircuit,
		proofGenerator:          generateProof,
		workerPerCircuit:        confutil.Int(config.MaxProverPerCircuit, *defaultSnarkProverConfig.MaxProverPerCircuit),
		circuitsWorkerIndexChan: make(map[string]chan int),
	}, nil
}

func (sp *snarkProver) Sign(ctx context.Context, privateKey []byte, req *pb.SignRequest) (*pb.SignResponse, error) {
	keyBytes := [32]byte{}
	copy(keyBytes[:], privateKey)
	keyEntry := key.NewKeyEntryFromPrivateKeyBytes(keyBytes)

	inputs, extras, err := decodeProvingRequest(req)
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
		return nil, i18n.NewError(ctx, msgs.MsgContextCanceled)
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
	wtns, err := calculateWitness(inputs.CircuitId, inputs.Common, extras, keyEntry, circuit)
	if err != nil {
		return nil, err
	}

	proof, err := sp.proofGenerator(wtns, provingKey)
	if err != nil {
		return nil, err
	}

	proofBytes, err := serializeProofResponse(inputs.CircuitId, proof)
	if err != nil {
		return nil, err
	}

	return &pb.SignResponse{
		Payload: proofBytes,
	}, nil
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

func serializeProofResponse(circuitId string, proof *types.ZKProof) ([]byte, error) {
	snark := pb.SnarkProof{}
	snark.A = proof.Proof.A
	snark.B = make([]*pb.B_Item, 0, len(proof.Proof.B))
	for _, p := range proof.Proof.B {
		bItems := pb.B_Item{}
		bItems.Items = append(bItems.Items, p...)
		snark.B = append(snark.B, &bItems)
	}
	snark.C = proof.Proof.C

	publicInputs := make(map[string]string)
	switch circuitId {
	case "anon_enc":
		publicInputs["encryptedValues"] = strings.Join(proof.PubSignals[0:4], ",")
		publicInputs["encryptionNonce"] = proof.PubSignals[8]
	case "anon_nullifier":
		publicInputs["nullifiers"] = strings.Join(proof.PubSignals[:2], ",")
		publicInputs["root"] = proof.PubSignals[2]
	}

	res := pb.ProvingResponse{
		Proof:        &snark,
		PublicInputs: publicInputs,
	}

	return proto.Marshal(&res)
}

func calculateWitness(circuitId string, commonInputs *pb.ProvingRequestCommon, extras interface{}, keyEntry *core.KeyEntry, circuit witness.Calculator) ([]byte, error) {
	inputs, err := buildCircuitInputs(commonInputs)
	if err != nil {
		return nil, err
	}

	var witnessInputs map[string]any
	switch circuitId {
	case "anon":
		witnessInputs = assembleInputs_anon(inputs, keyEntry)
	case "anon_enc":
		witnessInputs, err = assembleInputs_anon_enc(inputs, extras.(*pb.ProvingRequestExtras_Encryption), keyEntry)
		if err != nil {
			return nil, fmt.Errorf("failed to assemble private inputs for witness calculation. %s", err)
		}
	case "anon_nullifier":
		witnessInputs, err = assembleInputs_anon_nullifier(inputs, extras.(*pb.ProvingRequestExtras_Nullifiers), keyEntry)
		if err != nil {
			return nil, fmt.Errorf("failed to assemble private inputs for witness calculation. %s", err)
		}
	}

	wtns, err := circuit.CalculateWTNSBin(witnessInputs, true)
	if err != nil {
		return nil, fmt.Errorf("failed to calculate the witness. %s", err)
	}

	return wtns, nil
}

func generateProof(wtns, provingKey []byte) (*types.ZKProof, error) {
	proof, err := prover.Groth16Prover(provingKey, wtns)
	if err != nil {
		return nil, fmt.Errorf("failed to generate proof. %s", err)
	}
	return proof, nil
}
