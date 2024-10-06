// Copyright © 2024 Kaleido, Inc.
//
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package statemgr

import (
	"context"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"

	"github.com/kaleido-io/paladin/config/pkg/pldconf"
	"github.com/kaleido-io/paladin/core/mocks/componentmocks"
	"github.com/kaleido-io/paladin/core/pkg/persistence"
	"github.com/kaleido-io/paladin/core/pkg/persistence/mockpersistence"
	"github.com/kaleido-io/paladin/toolkit/pkg/log"
	"github.com/stretchr/testify/require"
)

type mockComponents struct {
	domainManager *componentmocks.DomainManager
	allComponents *componentmocks.AllComponents
}

func newMockComponents(t *testing.T) *mockComponents {
	m := &mockComponents{}
	m.domainManager = componentmocks.NewDomainManager(t)
	m.allComponents = componentmocks.NewAllComponents(t)
	m.allComponents.On("DomainManager").Return(m.domainManager)
	return m
}

func newDBTestStateManager(t *testing.T) (context.Context, *stateManager, *mockComponents, func()) {
	ctx := context.Background()
	p, pDone, err := persistence.NewUnitTestPersistence(ctx)
	require.NoError(t, err)
	ss := NewStateManager(ctx, &pldconf.StateStoreConfig{}, p)

	m := newMockComponents(t)

	ir, err := ss.PreInit(m.allComponents)
	require.NoError(t, err)
	require.NotNil(t, ir)
	require.NotEmpty(t, ir.RPCModules)

	err = ss.PostInit(m.allComponents)
	require.NoError(t, err)

	err = ss.Start()
	require.NoError(t, err)

	return ctx, ss.(*stateManager), m, func() {
		ss.Stop()
		pDone()
	}
}

func newDBMockStateManager(t *testing.T) (context.Context, *stateManager, sqlmock.Sqlmock, *mockComponents, func()) {
	ctx := context.Background()
	log.SetLevel("debug")
	p, err := mockpersistence.NewSQLMockProvider()
	require.NoError(t, err)
	ss := NewStateManager(ctx, &pldconf.StateStoreConfig{}, p.P)

	m := newMockComponents(t)

	_, err = ss.PreInit(m.allComponents)
	require.NoError(t, err)

	err = ss.PostInit(m.allComponents)
	require.NoError(t, err)

	err = ss.Start()
	require.NoError(t, err)

	return ctx, ss.(*stateManager), p.Mock, m, func() {
		ss.Stop()
		require.NoError(t, p.Mock.ExpectationsWereMet())
	}
}
