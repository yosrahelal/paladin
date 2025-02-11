package identityresolver

import (
	"context"
	"testing"
	"time"

	"github.com/kaleido-io/paladin/config/pkg/pldconf"
	"github.com/kaleido-io/paladin/core/mocks/componentmocks"
	"github.com/kaleido-io/paladin/toolkit/pkg/algorithms"
	"github.com/kaleido-io/paladin/toolkit/pkg/cache"
	"github.com/kaleido-io/paladin/toolkit/pkg/pldapi"
	"github.com/kaleido-io/paladin/toolkit/pkg/verifiers"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

func TestResolveVerifier(t *testing.T) {
	r := &identityResolver{}
	_, err := r.ResolveVerifier(context.Background(), "something$bad", "bad algorithm", "bad type")
	assert.ErrorContains(t, err, "PD020006: Locator string something$bad is invalid")

	capacity := 100
	config := &pldconf.CacheConfig{Capacity: &capacity}
	r = &identityResolver{
		nodeName:      "testnode",
		verifierCache: cache.NewCache[string, string](config, config),
		keyManager:    componentmocks.NewKeyManager(t),
	}
	waitChan := make(chan time.Time)
	resolvedKey := &pldapi.KeyMappingAndVerifier{
		Verifier: &pldapi.KeyVerifier{
			Verifier: "0x1234567890abcdef",
			Type:     "ETH_ADDRESS",
		},
	}
	r.keyManager.(*componentmocks.KeyManager).On("ResolveKeyNewDatabaseTX", mock.Anything, mock.Anything, mock.Anything, mock.Anything).WaitUntil(waitChan).Return(resolvedKey, nil)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer func() {
		cancel()
		close(waitChan)
	}()

	done := make(chan bool)
	go func() {
		_, err := r.ResolveVerifier(ctx, "something@testnode", algorithms.Curve_SECP256K1, verifiers.ETH_ADDRESS)
		assert.ErrorContains(t, err, "PD010301: Context canceled")
		done <- true
	}()
	<-done
}

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
