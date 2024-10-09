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

package evmregistry

import (
	"context"
	"testing"

	"github.com/kaleido-io/paladin/toolkit/pkg/prototk"
	"github.com/kaleido-io/paladin/toolkit/pkg/tktypes"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type testCallbacks struct {
	upsertTransportDetails func(ctx context.Context, req *prototk.UpsertTransportDetails) (*prototk.UpsertTransportDetailsResponse, error)
}

func (tc *testCallbacks) UpsertTransportDetails(ctx context.Context, req *prototk.UpsertTransportDetails) (*prototk.UpsertTransportDetailsResponse, error) {
	return tc.upsertTransportDetails(ctx, req)
}

func TestPluginLifecycle(t *testing.T) {
	pb := NewPlugin(context.Background())
	assert.NotNil(t, pb)
}

func TestBadConfigJSON(t *testing.T) {

	callbacks := &testCallbacks{}
	transport := evmRegistryFactory(callbacks).(*evmRegistry)
	_, err := transport.ConfigureRegistry(transport.bgCtx, &prototk.ConfigureRegistryRequest{
		Name:       "grpc",
		ConfigJson: `{!!!!`,
	})
	assert.Regexp(t, "PD060001", err)

}

func TestRegistryEventBatch(t *testing.T) {

	callbacks := &testCallbacks{}
	transport := evmRegistryFactory(callbacks).(*evmRegistry)
	_, err := transport.RegistryEventBatch(context.Background(), &prototk.RegistryEventBatchRequest{})
	require.NoError(t, err)

}

func TestRegistryUpsertBadDAta(t *testing.T) {
	callbacks := &testCallbacks{}
	transport := evmRegistryFactory(callbacks).(*evmRegistry)
	err := transport.registerNodeTransport(context.Background(), "node1", "transport1", tktypes.RawJSON(`{!!! bad json`))
	assert.Error(t, err)
}
