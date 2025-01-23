package nonfungible

import (
	"math/big"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestGetAlgoZetoSnarkBJJ verifies that getAlgoZetoSnarkBJJ returns the correct
// algorithm string for a given input name and that it matches the expected regexp.
func TestGetAlgoZetoSnarkBJJ(t *testing.T) {
	result := getAlgoZetoSnarkBJJ("bla")
	assert.Equal(t, "domain:bla:snark:babyjubjub", result)
}

func TestCryptoRand256(t *testing.T) {
	fieldModulus, ok := new(big.Int).SetString(modulu, 10)
	require.True(t, ok, "failed to parse field modulus")

	// Run multiple iterations to test the randomness and verify the range.
	const iterations = 10
	for i := 0; i < iterations; i++ {
		tokenValue, err := cryptoRand256()
		assert.NoError(t, err, "cryptoRand256 returned an error on iteration %d", i)
		require.NotNil(t, tokenValue, "cryptoRand256 returned a nil token on iteration %d", i)

		// Ensure the generated token is in the range [0, fieldModulus).
		// tokenValue must be less than fieldModulus.
		assert.Less(t, tokenValue.Cmp(fieldModulus), 0, "token value %s is not less than field modulus %s on iteration %d",
			tokenValue.String(), fieldModulus.String(), i)
	}
}
