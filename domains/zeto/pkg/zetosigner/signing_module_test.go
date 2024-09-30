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
	"testing"

	"github.com/kaleido-io/paladin/core/pkg/proto"
	"github.com/kaleido-io/paladin/core/pkg/signer"
	"github.com/kaleido-io/paladin/core/pkg/signer/signerapi"
	"github.com/kaleido-io/paladin/toolkit/pkg/algorithms"
	"github.com/kaleido-io/paladin/toolkit/pkg/confutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestZKPSigningModuleKeyResolution(t *testing.T) {
	tmpDir := t.TempDir()
	ctx := context.Background()

	sm, err := signer.NewSigningModule(ctx, &signerapi.Config{
		KeyStore: signerapi.KeyStoreConfig{
			Type:       signerapi.KeyStoreTypeFilesystem,
			FileSystem: signerapi.FileSystemConfig{Path: confutil.P(tmpDir)},
		},
	}, nil)
	require.NoError(t, err)

	resp1, err := sm.Resolve(ctx, &proto.ResolveKeyRequest{
		Algorithms: []string{algorithms.ECDSA_SECP256K1_PLAINBYTES, algorithms.ZKP_BABYJUBJUB_PLAINBYTES},
		Name:       "blueKey",
		Path: []*proto.ResolveKeyPathSegment{
			{Name: "alice"},
		},
	})
	require.NoError(t, err)
	assert.Equal(t, 2, len(resp1.Identifiers))
}
