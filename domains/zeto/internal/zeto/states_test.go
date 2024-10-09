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
	"errors"
	"testing"

	"github.com/kaleido-io/paladin/toolkit/pkg/prototk"
	"github.com/kaleido-io/paladin/toolkit/pkg/tktypes"
	"github.com/stretchr/testify/assert"
)

func TestGetStateSchemas(t *testing.T) {
	schemas, err := getStateSchemas()
	assert.NoError(t, err)
	assert.Len(t, schemas, 3)
}

func TestPrepareInputs(t *testing.T) {
	testCallbacks := &testDomainCallbacks{
		returnFunc: func() (*prototk.FindAvailableStatesResponse, error) {
			return nil, errors.New("test error")
		},
	}
	zeto := &Zeto{
		name:      "test1",
		Callbacks: testCallbacks,
		coinSchema: &prototk.StateSchema{
			Id: "coin",
		},
		merkleTreeRootSchema: &prototk.StateSchema{
			Id: "merkle_tree_root",
		},
		merkleTreeNodeSchema: &prototk.StateSchema{
			Id: "merkle_tree_node",
		},
	}

	stateQueryContext := "test"
	ctx := context.Background()
	_, _, _, err := zeto.prepareInputs(ctx, stateQueryContext, "Alice", tktypes.Uint64ToUint256(100))
	assert.EqualError(t, err, "failed to query the state store for available coins. test error")

	testCallbacks.returnFunc = func() (*prototk.FindAvailableStatesResponse, error) {
		return &prototk.FindAvailableStatesResponse{}, nil
	}
	_, _, _, err = zeto.prepareInputs(ctx, stateQueryContext, "Alice", tktypes.Uint64ToUint256(100))
	assert.EqualError(t, err, "insufficient funds (available=0)")

	testCallbacks.returnFunc = func() (*prototk.FindAvailableStatesResponse, error) {
		return &prototk.FindAvailableStatesResponse{
			States: []*prototk.StoredState{
				{
					Id:       "state-1",
					DataJson: "bad json",
				},
			},
		}, nil
	}
	_, _, _, err = zeto.prepareInputs(ctx, stateQueryContext, "Alice", tktypes.Uint64ToUint256(100))
	assert.EqualError(t, err, "coin state-1 is invalid: invalid character 'b' looking for beginning of value")

	testCallbacks.returnFunc = func() (*prototk.FindAvailableStatesResponse, error) {
		return &prototk.FindAvailableStatesResponse{
			States: []*prototk.StoredState{
				{
					Id:       "state-1",
					DataJson: "{\"amount\": \"10\"}",
				},
				{
					Id:       "state-2",
					DataJson: "{\"amount\": \"10\"}",
				},
			},
		}, nil
	}
	_, _, _, err = zeto.prepareInputs(ctx, stateQueryContext, "Alice", tktypes.Uint64ToUint256(100))
	assert.EqualError(t, err, "could not find suitable coins")
}
