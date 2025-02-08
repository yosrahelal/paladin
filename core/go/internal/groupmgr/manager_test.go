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

package groupmgr

import (
	"context"
	"testing"

	"github.com/hyperledger/firefly-signer/pkg/abi"
	"github.com/kaleido-io/paladin/config/pkg/pldconf"
	"github.com/kaleido-io/paladin/core/internal/components"
	"github.com/kaleido-io/paladin/core/internal/statemgr"
	"github.com/kaleido-io/paladin/core/mocks/componentmocks"
	"github.com/kaleido-io/paladin/core/pkg/persistence"
	"github.com/kaleido-io/paladin/core/pkg/persistence/mockpersistence"
	"github.com/kaleido-io/paladin/toolkit/pkg/pldapi"
	"github.com/kaleido-io/paladin/toolkit/pkg/tktypes"
	"github.com/sirupsen/logrus"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

type mockComponents struct {
	c                *componentmocks.AllComponents
	db               *mockpersistence.SQLMockProvider
	p                persistence.Persistence
	stateManager     *componentmocks.StateManager
	domainManager    *componentmocks.DomainManager
	domain           *componentmocks.Domain
	registryManager  *componentmocks.RegistryManager
	transportManager *componentmocks.TransportManager
	txManager        *componentmocks.TXManager
}

func newMockComponents(t *testing.T, realDB bool) *mockComponents {
	mc := &mockComponents{c: componentmocks.NewAllComponents(t)}
	mc.domainManager = componentmocks.NewDomainManager(t)
	mc.domain = componentmocks.NewDomain(t)
	mc.registryManager = componentmocks.NewRegistryManager(t)
	mc.transportManager = componentmocks.NewTransportManager(t)
	mc.txManager = componentmocks.NewTXManager(t)

	mc.c.On("DomainManager").Return(mc.domainManager).Maybe()
	mc.c.On("TransportManager").Return(mc.transportManager).Maybe()
	mc.c.On("RegistryManager").Return(mc.registryManager).Maybe()
	mc.c.On("TxManager").Return(mc.txManager).Maybe()

	if realDB {
		p, cleanup, err := persistence.NewUnitTestPersistence(context.Background(), "transportmgr")
		require.NoError(t, err)
		t.Cleanup(cleanup)
		mc.p = p
		mc.c.On("Persistence").Return(p).Maybe()

		stateManager := statemgr.NewStateManager(context.Background(), &pldconf.StateStoreConfig{}, p)
		_, err = stateManager.PreInit(mc.c)
		require.NoError(t, err)
		err = stateManager.PostInit(mc.c)
		require.NoError(t, err)
		err = stateManager.Start()
		require.NoError(t, err)
		mc.c.On("StateManager").Return(stateManager).Maybe()
		t.Cleanup(stateManager.Stop)

	} else {
		mdb, err := mockpersistence.NewSQLMockProvider()
		require.NoError(t, err)
		mc.db = mdb
		mc.p = mdb.P
		mc.c.On("Persistence").Return(mc.p).Maybe()

		mc.stateManager = componentmocks.NewStateManager(t)
		mc.c.On("StateManager").Return(mc.stateManager).Maybe()
	}

	mc.domainManager.On("GetDomainByName", mock.Anything, "domain1").Return(mc.domain, nil)
	mc.domain.On("CustomHashFunction").Return(false).Maybe()
	mc.domain.On("Name").Return("domain1").Maybe()
	mc.txManager.On("NotifyStatesDBChanged", mock.Anything).Return().Maybe()
	mc.transportManager.On("LocalNodeName").Return("node1").Maybe()

	return mc
}

func newTestGroupManager(t *testing.T, realDB bool, conf *pldconf.GroupManagerConfig, extraSetup ...func(mc *mockComponents, conf *pldconf.GroupManagerConfig)) (context.Context, *groupManager, *mockComponents, func()) {
	ctx, cancelCtx := context.WithCancel(context.Background())
	oldLevel := logrus.GetLevel()
	logrus.SetLevel(logrus.TraceLevel)

	mc := newMockComponents(t, realDB)
	for _, fn := range extraSetup {
		fn(mc, conf)
	}

	gm := NewGroupManager(ctx, conf)

	ir, err := gm.PreInit(mc.c)
	require.NoError(t, err)
	assert.NotNil(t, ir)

	err = gm.PostInit(mc.c)
	require.NoError(t, err)

	err = gm.Start()
	require.NoError(t, err)

	return ctx, gm.(*groupManager), mc, func() {
		if !t.Failed() {
			logrus.SetLevel(oldLevel)
			cancelCtx()
			gm.Stop()
		}
	}
}

func TestPrivacyGroupLifecycleRealDB(t *testing.T) {
	ctx, gm, _, done := newTestGroupManager(t, true, &pldconf.GroupManagerConfig{}, func(mc *mockComponents, conf *pldconf.GroupManagerConfig) {
		mc.registryManager.On("GetNodeTransports", mock.Anything, "node2").
			Return([]*components.RegistryNodeTransportEntry{ /* contents not checked */ }, nil)
		ipg := mc.domain.On("InitPrivacyGroup", mock.Anything, mock.Anything)
		ipg.Run(func(args mock.Arguments) {
			spec := args[1].(*pldapi.PrivacyGroupInput)
			require.Equal(t, "domain1", spec.Domain)
			require.JSONEq(t, `{"name": "secret things"}`, spec.Properties.Pretty())
			require.Len(t, spec.Members, 2)
			ipg.Return(
				tktypes.RawJSON(`{
					"name": "secret things",
					"version": 200
				}`),
				&abi.Parameter{
					Name:         "TestPrivacyGroup",
					Type:         "tuple",
					InternalType: "struct TestPrivacyGroup;",
					Indexed:      true,
					Components: append(spec.PropertiesABI, &abi.Parameter{
						Name: "version",
						Type: "uint256",
					}),
				},
				nil,
			)
		})
	})
	defer done()

	err := gm.persistence.Transaction(ctx, func(ctx context.Context, dbTX persistence.DBTX) error {
		id, err := gm.CreateGroup(ctx, dbTX, &pldapi.PrivacyGroupInput{
			Domain:  "domain1",
			Members: []string{"me@node1", "you@node2"},
			Properties: tktypes.RawJSON(`{
			  "name": "secret things"
			}`),
		})
		require.NoError(t, err)
		require.NotNil(t, id)
		return err
	})
	require.NoError(t, err)
}
