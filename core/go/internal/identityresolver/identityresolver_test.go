package identityresolver

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestResolveVerifierAsync(t *testing.T) {
	r := &identityResolver{}
	resolved := func(ctx context.Context, verifier string) {
		t.Logf("Resolved verifier: %s", verifier)
	}
	errhandler := func(ctx context.Context, err error) {
		assert.ErrorContains(t, err, "PD020006: Locator string something$bad is invalid")
	}
	r.ResolveVerifierAsync(context.Background(), "something$bad", "bad algorithm", "bad type", resolved, errhandler)
}
