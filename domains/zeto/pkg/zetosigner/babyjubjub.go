package zetosigner

import (
	"github.com/iden3/go-iden3-crypto/babyjub"
	"github.com/kaleido-io/paladin/domains/zeto/internal/zeto/signer"
)

func EncodeBabyJubJubPublicKey(pubKey *babyjub.PublicKey) string {
	return signer.EncodeBabyJubJubPublicKey(pubKey)
}

func DecodeBabyJubJubPublicKey(pubKeyHex string) (*babyjub.PublicKey, error) {
	return signer.DecodeBabyJubJubPublicKey(pubKeyHex)
}

func NewBabyJubJubPrivateKey(privateKey []byte) (*babyjub.PrivateKey, error) {
	return signer.NewBabyJubJubPrivateKey(privateKey)
}
