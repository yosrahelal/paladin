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

package signer

import (
	"context"
	"testing"

	pb "github.com/kaleido-io/paladin/domains/zeto/pkg/proto"
	"github.com/stretchr/testify/assert"
)

func TestBuildCircuitInputs(t *testing.T) {
	alice := NewTestKeypair()
	sender := alice.PublicKey.Compress().String()
	bob := NewTestKeypair()
	receiver := bob.PublicKey.Compress().String()
	req := &pb.ProvingRequestCommon{
		InputCommitments: []string{"1", "2"},
		InputValues:      []uint64{10, 20},
		InputSalts:       []string{"3", "4"},
		OutputValues:     []uint64{30, 0},
		OutputSalts:      []string{"5", "0"},
		OutputOwners:     []string{sender, receiver},
	}
	ctx := context.Background()
	inputs, err := buildCircuitInputs(ctx, req)
	assert.NoError(t, err)
	assert.Equal(t, 2, len(inputs.outputOwnerPublicKeys))
	assert.Equal(t, alice.PublicKey.X.Text(10), inputs.outputOwnerPublicKeys[0][0].Text(10))
	assert.Equal(t, alice.PublicKey.Y.Text(10), inputs.outputOwnerPublicKeys[0][1].Text(10))
	assert.Equal(t, "0", inputs.outputOwnerPublicKeys[1][0].Text(10))
	assert.Equal(t, "0", inputs.outputOwnerPublicKeys[1][1].Text(10))
	assert.Equal(t, "0", inputs.outputValues[1].Text(10))
	assert.Equal(t, "0", inputs.outputCommitments[1].Text(10))

	req.OutputOwners = []string{"1234", "5678"}
	_, err = buildCircuitInputs(ctx, req)
	assert.EqualError(t, err, "PD210037: Failed load owner public key. PD210072: Invalid compressed public key length: 2")

	req.OutputOwners = []string{sender, receiver}
	req.OutputSalts = []string{"0x5", "0x1"}
	_, err = buildCircuitInputs(ctx, req)
	assert.EqualError(t, err, "PD210083: Failed to parse output salt")
}
