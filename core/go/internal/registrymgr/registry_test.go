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

package registrymgr

import (
	"context"
	"fmt"
	"sync/atomic"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/google/uuid"
	"github.com/kaleido-io/paladin/config/pkg/pldconf"
	"github.com/kaleido-io/paladin/core/internal/components"

	"github.com/kaleido-io/paladin/toolkit/pkg/plugintk"
	"github.com/kaleido-io/paladin/toolkit/pkg/prototk"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var registryID uuid.UUID

type testPlugin struct {
	plugintk.RegistryAPIBase
	initialized  atomic.Bool
	r            *registry
	sendMessages chan *prototk.SendMessageRequest
}

func (tp *testPlugin) Initialized() {
	tp.initialized.Store(true)
}

func newTestPlugin(registryFuncs *plugintk.RegistryAPIFunctions) *testPlugin {
	return &testPlugin{
		RegistryAPIBase: plugintk.RegistryAPIBase{
			Functions: registryFuncs,
		},
		sendMessages: make(chan *prototk.SendMessageRequest, 1),
	}
}

func newTestRegistry(t *testing.T, realDB bool, extraSetup ...func(mc *mockComponents, regConf *prototk.RegistryConfig)) (context.Context, *registryManager, *testPlugin, *mockComponents, func()) {
	regConf := &prototk.RegistryConfig{}

	ctx, rm, mc, done := newTestRegistryManager(t, realDB, &pldconf.RegistryManagerConfig{
		Registries: map[string]*pldconf.RegistryConfig{
			"test1": {
				Config: map[string]any{"some": "conf"},
			},
		},
	}, func(mc *mockComponents) {
		for _, fn := range extraSetup {
			fn(mc, regConf)
		}
	})

	tp := newTestPlugin(nil)
	tp.Functions = &plugintk.RegistryAPIFunctions{
		ConfigureRegistry: func(ctx context.Context, ctr *prototk.ConfigureRegistryRequest) (*prototk.ConfigureRegistryResponse, error) {
			assert.Equal(t, "test1", ctr.Name)
			assert.JSONEq(t, `{"some":"conf"}`, ctr.ConfigJson)
			return &prototk.ConfigureRegistryResponse{
				RegistryConfig: regConf,
			}, nil
		},
	}

	registerTestRegistry(t, rm, tp)
	return ctx, rm, tp, mc, done
}

func registerTestRegistry(t *testing.T, rm *registryManager, tp *testPlugin) {
	registryID = uuid.New()
	_, err := rm.RegistryRegistered("test1", registryID, tp)
	require.NoError(t, err)

	ra := rm.registriesByName["test1"]
	assert.NotNil(t, ra)
	tp.r = ra
	tp.r.initRetry.UTSetMaxAttempts(1)
	<-tp.r.initDone
}

func TestDoubleRegisterReplaces(t *testing.T) {

	_, rm, tp0, _, done := newTestRegistry(t, false)
	defer done()
	assert.Nil(t, tp0.r.initError.Load())
	assert.True(t, tp0.initialized.Load())

	// Register again
	tp1 := newTestPlugin(nil)
	tp1.Functions = tp0.Functions
	registerTestRegistry(t, rm, tp1)
	assert.Nil(t, tp1.r.initError.Load())
	assert.True(t, tp1.initialized.Load())

	// Check we get the second from all the maps
	byName := rm.registriesByName[tp1.r.name]
	assert.Same(t, tp1.r, byName)
	byUUID := rm.registriesByID[tp1.r.id]
	assert.Same(t, tp1.r, byUUID)

}

func TestUpsertTransportDetailsRealDBok(t *testing.T) {
	ctx, rm, tp, _, done := newTestRegistry(t, true)
	defer done()

	_, err := rm.GetNodeTransports(ctx, "node1")
	assert.Regexp(t, "PD012100", err)

	// Upsert bad entry
	_, err = tp.r.UpsertTransportDetails(ctx, &prototk.UpsertTransportDetails{
		TransportDetails: []*prototk.TransportDetails{
			{ /* missing Node */ },
		},
	})
	assert.Regexp(t, "PD012101", err)

	entry1 := &prototk.UpsertTransportDetails{
		TransportDetails: []*prototk.TransportDetails{
			{
				Node:      "node1",
				Transport: "grpc",
				Details:   "things and stuff",
			},
		},
	}

	// Upsert first entry
	res, err := tp.r.UpsertTransportDetails(ctx, entry1)
	require.NoError(t, err)
	assert.NotNil(t, res)

	// Check we get it
	transports, err := rm.GetNodeTransports(ctx, "node1")
	require.NoError(t, err)
	assert.Len(t, transports, 1)
	assert.Equal(t, components.RegistryNodeTransportEntry{
		Node:      "node1",
		Registry:  registryID.String(),
		Transport: "grpc",
		Details:   "things and stuff",
	}, *transports[0])

	// Upsert second entry
	entry2 := &prototk.UpsertTransportDetails{
		TransportDetails: []*prototk.TransportDetails{
			{
				Node:      "node1",
				Transport: "websockets",
				Details:   "more things and stuff",
			},
		},
	}

	// Upsert second entry
	res, err = tp.r.UpsertTransportDetails(ctx, entry2)
	require.NoError(t, err)
	transports, err = rm.GetNodeTransports(ctx, "node1")
	require.NoError(t, err)
	assert.NotNil(t, res)
	assert.Len(t, transports, 2)

	// Upsert first entry again
	res, err = tp.r.UpsertTransportDetails(ctx, entry1)
	require.NoError(t, err)
	transports, err = rm.GetNodeTransports(ctx, "node1")
	require.NoError(t, err)
	assert.NotNil(t, res)
	assert.Len(t, transports, 2)

}

func TestUpsertTransportDetailsInsertFail(t *testing.T) {
	ctx, _, tp, m, done := newTestRegistry(t, false)
	defer done()

	m.db.ExpectBegin()
	m.db.ExpectExec("INSERT.*registry_transport_details").WillReturnError(fmt.Errorf("pop"))

	_, err := tp.r.UpsertTransportDetails(ctx, &prototk.UpsertTransportDetails{
		TransportDetails: []*prototk.TransportDetails{
			{
				Node:      "node1",
				Transport: "websockets",
				Details:   "more things and stuff",
			},
		},
	})
	assert.Regexp(t, "pop", err)

}

func TestGetNodeTransportsCache(t *testing.T) {
	ctx, rm, _, m, done := newTestRegistry(t, false)
	defer done()

	m.db.ExpectQuery("SELECT.*registry_transport_details").WillReturnRows(sqlmock.NewRows([]string{
		"node", "registry", "transport", "details",
	}).AddRow(
		"node1", "test1", "websockets", "things and stuff",
	))

	expected := []*components.RegistryNodeTransportEntry{
		{
			Node:      "node1",
			Registry:  "test1",
			Transport: "websockets",
			Details:   "things and stuff",
		},
	}

	transports, err := rm.GetNodeTransports(ctx, "node1")
	require.NoError(t, err)
	assert.Equal(t, expected, transports)

	// Re-do from cache
	transports, err = rm.GetNodeTransports(ctx, "node1")
	require.NoError(t, err)
	assert.Equal(t, expected, transports)

}

func TestGetNodeTransportsErr(t *testing.T) {
	ctx, rm, _, m, done := newTestRegistry(t, false)
	defer done()

	m.db.ExpectQuery("SELECT.*registry_transport_details").WillReturnError(fmt.Errorf("pop"))

	_, err := rm.GetNodeTransports(ctx, "node1")
	require.Regexp(t, "pop", err)
}
