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

package keymanager

import (
	"context"
	"fmt"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/kaleido-io/paladin/config/pkg/pldconf"
	"github.com/kaleido-io/paladin/core/mocks/componentmocks"
	"github.com/kaleido-io/paladin/core/pkg/persistence"
	"github.com/kaleido-io/paladin/core/pkg/persistence/mockpersistence"
	"github.com/kaleido-io/paladin/toolkit/pkg/algorithms"
	"github.com/kaleido-io/paladin/toolkit/pkg/tktypes"
	"github.com/kaleido-io/paladin/toolkit/pkg/verifiers"
	"github.com/sirupsen/logrus"
	"gorm.io/gorm"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type mockComponents struct {
	c  *componentmocks.AllComponents
	db sqlmock.Sqlmock
}

func newTestKeyManager(t *testing.T, realDB bool, conf *pldconf.KeyManagerConfig, extraSetup ...func(mc *mockComponents)) (context.Context, *keyManager, *mockComponents, func()) {
	ctx, cancelCtx := context.WithCancel(context.Background())
	oldLevel := logrus.GetLevel()
	logrus.SetLevel(logrus.TraceLevel)

	mc := &mockComponents{c: componentmocks.NewAllComponents(t)}
	componentMocks := mc.c

	var p persistence.Persistence
	var pDone func()
	var err error
	if realDB {
		p, pDone, err = persistence.NewUnitTestPersistence(ctx)
		require.NoError(t, err)
	} else {
		mp, err := mockpersistence.NewSQLMockProvider()
		require.NoError(t, err)
		p = mp.P
		mc.db = mp.Mock
		pDone = func() {
			require.NoError(t, mp.Mock.ExpectationsWereMet())
		}
	}
	componentMocks.On("Persistence").Return(p)

	km := NewKeyManager(ctx, conf)

	ir, err := km.PreInit(mc.c)
	require.NoError(t, err)
	assert.NotNil(t, ir)

	err = km.PostInit(mc.c)
	require.NoError(t, err)

	err = km.Start()
	require.NoError(t, err)

	return ctx, km.(*keyManager), mc, func() {
		logrus.SetLevel(oldLevel)
		cancelCtx()
		km.Stop()
		pDone()
	}
}

func TestE2ESigningHDWalletRealDB(t *testing.T) {
	ctx, km, _, done := newTestKeyManager(t, true, &pldconf.KeyManagerConfig{
		Wallets: []*pldconf.WalletConfig{
			{
				Name: "hdwallet1",
				Signer: &pldconf.SignerConfig{
					KeyDerivation: pldconf.KeyDerivationConfig{
						Type: pldconf.KeyDerivationTypeBIP32,
					},
					KeyStore: pldconf.KeyStoreConfig{
						Type: pldconf.KeyStoreTypeStatic,
						Static: pldconf.StaticKeyStoreConfig{
							Keys: map[string]pldconf.StaticKeyEntryConfig{
								"seed": pldconf.StaticKeyEntryConfig{
									Encoding: "hex",
									Inline:   tktypes.RandHex(32),
								},
							},
						},
					},
				},
			},
		},
	})
	defer done()

	for i := 0; i < 3; i++ {
		// - first run creates
		// - second run validates they don't change with caching
		// - third run checks they don't change with reload
		if i == 2 {
			km.identifierCache.Clear()
			km.verifierCache.Clear()
		}

		var postCommit func()
		err := km.p.DB().Transaction(func(tx *gorm.DB) error {
			krc1 := km.NewKeyResolutionContext(ctx, tx)
			postCommit = krc1.PostCommit

			// one key out of the blue
			resolved1, err := krc1.ResolveKey("bob.keys.blue.42", algorithms.ECDSA_SECP256K1, verifiers.ETH_ADDRESS)
			require.NoError(t, err)
			assert.Equal(t, algorithms.ECDSA_SECP256K1, resolved1.Verifier.Algorithm)
			assert.Equal(t, verifiers.ETH_ADDRESS, resolved1.Verifier.Type)
			assert.Equal(t, "m/44'/60'/1'/0/0/0", resolved1.KeyHandle)

			// a root key, after we've already allocated a key under it
			resolved2, err := krc1.ResolveKey("bob", algorithms.ECDSA_SECP256K1, verifiers.ETH_ADDRESS)
			require.NoError(t, err)
			assert.Equal(t, algorithms.ECDSA_SECP256K1, resolved2.Verifier.Algorithm)
			assert.Equal(t, verifiers.ETH_ADDRESS, resolved2.Verifier.Type)
			assert.Equal(t, "m/44'/60'/1'", resolved2.KeyHandle)

			// keys at a nested layer
			for i := 0; i < 10; i++ {
				resolved, err := krc1.ResolveKey(fmt.Sprintf("bob.keys.red.%d", i), algorithms.ECDSA_SECP256K1, verifiers.ETH_ADDRESS)
				require.NoError(t, err)
				assert.Equal(t, algorithms.ECDSA_SECP256K1, resolved.Verifier.Algorithm)
				assert.Equal(t, verifiers.ETH_ADDRESS, resolved.Verifier.Type)
				assert.Equal(t, fmt.Sprintf("m/44'/60'/1'/0/1/%d", i), resolved.KeyHandle)
			}

			// same keys backwards
			for i := 9; i >= 0; i-- {
				resolved, err := krc1.ResolveKey(fmt.Sprintf("bob.keys.red.%d", i), algorithms.ECDSA_SECP256K1, verifiers.ETH_ADDRESS)
				require.NoError(t, err)
				assert.Equal(t, algorithms.ECDSA_SECP256K1, resolved.Verifier.Algorithm)
				assert.Equal(t, verifiers.ETH_ADDRESS, resolved.Verifier.Type)
				assert.Equal(t, fmt.Sprintf("m/44'/60'/1'/0/1/%d", i), resolved.KeyHandle)
			}

			// keys under a different root
			for i := 0; i < 10; i++ {
				resolved, err := krc1.ResolveKey(fmt.Sprintf("sally.%d", i), algorithms.ECDSA_SECP256K1, verifiers.ETH_ADDRESS)
				require.NoError(t, err)
				assert.Equal(t, algorithms.ECDSA_SECP256K1, resolved.Verifier.Algorithm)
				assert.Equal(t, verifiers.ETH_ADDRESS, resolved.Verifier.Type)
				assert.Equal(t, fmt.Sprintf("m/44'/60'/2'/%d", i), resolved.KeyHandle)
			}

			return nil
		})
		require.NoError(t, err)
		postCommit()
	}

}
