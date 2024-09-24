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

package zeto

import (
	"context"
	"encoding/json"
	"math/big"
	"testing"

	"github.com/kaleido-io/paladin/domains/zeto/pkg/types"
	"github.com/kaleido-io/paladin/toolkit/pkg/tktypes"
	"github.com/stretchr/testify/assert"
)

func TestDecodeDomainConfig(t *testing.T) {
	config := &types.DomainInstanceConfig{
		CircuitId: "circuit-id",
		TokenName: "token-name",
	}
	configJSON, err := json.Marshal(config)
	assert.NoError(t, err)

	encoded, err := types.DomainInstanceConfigABI.EncodeABIDataJSON(configJSON)
	assert.NoError(t, err)

	z := &Zeto{}
	decoded, err := z.decodeDomainConfig(context.Background(), encoded)
	assert.NoError(t, err)
	assert.Equal(t, config, decoded)
}

func TestParseStatesFromEvent(t *testing.T) {
	v1 := tktypes.MustParseHexBytes("0x000100003dd63e8e9c624c6790b33094364077de00000000000000000000000000000000")
	bi, ok := new(big.Int).SetString("58495fddf70b21b46dc37f09715186ceb1499e063d29f20cbec311d4c2fa4fe", 16)
	assert.True(t, ok)
	v2 := tktypes.NewHexInteger(bi)
	updates := parseStatesFromEvent(v1, []tktypes.HexInteger{*v2})
	stateId, err := tktypes.ParseBytes32Ctx(context.Background(), updates[0].Id)
	assert.NoError(t, err)
	assert.Equal(t, "058495fddf70b21b46dc37f09715186ceb1499e063d29f20cbec311d4c2fa4fe", stateId.HexString())
}
