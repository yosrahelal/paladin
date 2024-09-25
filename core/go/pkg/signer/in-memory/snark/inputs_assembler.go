package snark

import (
	"fmt"
	"math/big"

	"github.com/hyperledger-labs/zeto/go-sdk/pkg/crypto"
	"github.com/hyperledger-labs/zeto/go-sdk/pkg/key-manager/core"
	pb "github.com/kaleido-io/paladin/core/pkg/proto"
)

func assembleInputs_anon(inputs *commonWitnessInputs, keyEntry *core.KeyEntry) map[string]interface{} {
	witnessInputs := map[string]interface{}{
		"inputCommitments":      inputs.inputCommitments,
		"inputValues":           inputs.inputValues,
		"inputSalts":            inputs.inputSalts,
		"inputOwnerPrivateKey":  keyEntry.PrivateKeyForZkp,
		"outputCommitments":     inputs.outputCommitments,
		"outputValues":          inputs.outputValues,
		"outputSalts":           inputs.outputSalts,
		"outputOwnerPublicKeys": inputs.outputOwnerPublicKeys,
	}
	return witnessInputs
}

func assembleInputs_anon_enc(inputs *commonWitnessInputs, extras *pb.ProvingRequestExtras_Encryption, keyEntry *core.KeyEntry) (map[string]any, error) {
	var nonce *big.Int
	if extras != nil && extras.EncryptionNonce != "" {
		n, ok := new(big.Int).SetString(extras.EncryptionNonce, 10)
		if !ok {
			return nil, fmt.Errorf("failed to parse encryption nonce")
		}
		nonce = n
	} else {
		nonce = crypto.NewEncryptionNonce()
	}
	witnessInputs := map[string]interface{}{
		"inputCommitments":      inputs.inputCommitments,
		"inputValues":           inputs.inputValues,
		"inputSalts":            inputs.inputSalts,
		"inputOwnerPrivateKey":  keyEntry.PrivateKeyForZkp,
		"outputCommitments":     inputs.outputCommitments,
		"outputValues":          inputs.outputValues,
		"outputSalts":           inputs.outputSalts,
		"outputOwnerPublicKeys": inputs.outputOwnerPublicKeys,
		"encryptionNonce":       nonce,
	}
	return witnessInputs, nil
}

func assembleInputs_anon_nullifier(inputs *commonWitnessInputs, extras *pb.ProvingRequestExtras_Nullifiers, keyEntry *core.KeyEntry) (map[string]any, error) {
	// calculate the nullifiers for the input UTXOs
	nullifiers := make([]*big.Int, len(inputs.inputCommitments))
	for i := 0; i < len(inputs.inputCommitments); i++ {
		nullifier, err := CalculateNullifier(inputs.inputValues[i], inputs.inputSalts[i], keyEntry.PrivateKeyForZkp)
		if err != nil {
			return nil, fmt.Errorf("failed to calculate nullifier. %s", err)
		}
		nullifiers[i] = nullifier
	}
	root, ok := new(big.Int).SetString(extras.Root, 16)
	if !ok {
		return nil, fmt.Errorf("failed to parse root")
	}
	var proofs [][]*big.Int
	for _, proof := range extras.MerkleProofs {
		var mp []*big.Int
		for _, node := range proof.Nodes {
			n, ok := new(big.Int).SetString(node, 16)
			if !ok {
				return nil, fmt.Errorf("failed to parse node")
			}
			mp = append(mp, n)
		}
		proofs = append(proofs, mp)
	}
	enabled := make([]*big.Int, len(extras.Enabled))
	for i, e := range extras.Enabled {
		if e {
			enabled[i] = big.NewInt(1)
		} else {
			enabled[i] = big.NewInt(0)
		}
	}

	witnessInputs := map[string]interface{}{
		"nullifiers":            nullifiers,
		"root":                  root,
		"merkleProof":           proofs,
		"enabled":               enabled,
		"inputCommitments":      inputs.inputCommitments,
		"inputValues":           inputs.inputValues,
		"inputSalts":            inputs.inputSalts,
		"inputOwnerPrivateKey":  keyEntry.PrivateKeyForZkp,
		"outputCommitments":     inputs.outputCommitments,
		"outputValues":          inputs.outputValues,
		"outputSalts":           inputs.outputSalts,
		"outputOwnerPublicKeys": inputs.outputOwnerPublicKeys,
	}
	return witnessInputs, nil
}
