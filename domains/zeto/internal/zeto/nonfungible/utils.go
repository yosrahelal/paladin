package nonfungible

import (
	"context"
	cryptorand "crypto/rand"
	"fmt"
	"math/big"

	"github.com/hyperledger/firefly-signer/pkg/ethtypes"
	"github.com/kaleido-io/paladin/domains/zeto/internal/zeto/common"
	corepb "github.com/kaleido-io/paladin/domains/zeto/pkg/proto"
	"github.com/kaleido-io/paladin/domains/zeto/pkg/zetosigner/zetosignerapi"
	"github.com/kaleido-io/paladin/toolkit/pkg/domain"
	pb "github.com/kaleido-io/paladin/toolkit/pkg/prototk"
	"github.com/kaleido-io/paladin/toolkit/pkg/tktypes"
)

const modulu = "21888242871839275222246405745257275088548364400416034343698204186575808495617"

var (
	encodeTransactionDataFunc func(context.Context, *pb.TransactionSpecification, ethtypes.HexBytes0xPrefix) (tktypes.HexBytes, error) = common.EncodeTransactionData
	encodeProofFunc           func(proof *corepb.SnarkProof) map[string]interface{}                                                    = common.EncodeProof
	findVerifierFunc          func(string, string, string, []*pb.ResolvedVerifier) *pb.ResolvedVerifier                                = domain.FindVerifier
	findAttestationFunc       func(string, []*pb.AttestationResult) *pb.AttestationResult                                              = domain.FindAttestation
)

func getAlgoZetoSnarkBJJ(name string) string {
	return zetosignerapi.AlgoDomainZetoSnarkBJJ(name)
}

// Generate a random 256-bit integer
func cryptoRand256() (*big.Int, error) {
	// The BN254 field modulus.
	fieldModulus, ok := new(big.Int).SetString(modulu, 10)
	if !ok {
		return nil, fmt.Errorf("failed to parse field modulus")
	}

	// Generate a random number in [0, fieldModulus).
	tokenValue, err := cryptorand.Int(cryptorand.Reader, fieldModulus)
	if err != nil {
		return nil, err
	}
	return tokenValue, nil
}
