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
	"database/sql/driver"
	"fmt"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/google/uuid"
	"github.com/hyperledger/firefly-signer/pkg/abi"
	"github.com/kaleido-io/paladin/config/pkg/pldconf"
	"github.com/kaleido-io/paladin/core/internal/components"
	"github.com/kaleido-io/paladin/core/internal/statemgr"
	"github.com/kaleido-io/paladin/core/mocks/componentmocks"
	"github.com/kaleido-io/paladin/core/pkg/persistence"
	"github.com/kaleido-io/paladin/core/pkg/persistence/mockpersistence"
	"github.com/kaleido-io/paladin/toolkit/pkg/pldapi"
	"github.com/kaleido-io/paladin/toolkit/pkg/query"
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
	txManager        *componentmocks.TXManager
	domainManager    *componentmocks.DomainManager
	domain           *componentmocks.Domain
	registryManager  *componentmocks.RegistryManager
	transportManager *componentmocks.TransportManager
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
		p, cleanup, err := persistence.NewUnitTestPersistence(context.Background(), "groupmgr")
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

	mc.domainManager.On("GetDomainByName", mock.Anything, "domain1").Return(mc.domain, nil).Maybe()
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

func mockBeginRollback(mc *mockComponents, conf *pldconf.GroupManagerConfig) {
	mc.db.Mock.ExpectBegin()
	mc.db.Mock.ExpectRollback()
}

func TestPrivacyGroupInvalidABI(t *testing.T) {

	ctx, gm, _, done := newTestGroupManager(t, false, &pldconf.GroupManagerConfig{}, mockEmptyMessageListeners, mockBeginRollback)
	defer done()

	err := gm.p.Transaction(ctx, func(ctx context.Context, dbTX persistence.DBTX) error {
		_, err := gm.CreateGroup(ctx, dbTX, &pldapi.PrivacyGroupInput{
			Domain:  "domain1",
			Members: []string{"me@node1", "you@node2"},
			Properties: tktypes.RawJSON(`{
			  "name": null
			}`),
		})
		return err
	})
	require.Regexp(t, "PD020021", err)
}

func TestPrivacyGroupMixedArrayFailParseAfterInfer(t *testing.T) {

	ctx, gm, _, done := newTestGroupManager(t, false, &pldconf.GroupManagerConfig{}, mockEmptyMessageListeners, mockBeginRollback)
	defer done()

	err := gm.p.Transaction(ctx, func(ctx context.Context, dbTX persistence.DBTX) error {
		_, err := gm.CreateGroup(ctx, dbTX, &pldapi.PrivacyGroupInput{
			Domain:  "domain1",
			Members: []string{"me@node1", "you@node2"},
			Properties: tktypes.RawJSON(`{
			  "name": ["abc", [ "nested" ]]
			}`),
		})
		return err
	})
	require.Regexp(t, "PD012500", err)
}

func TestPrivacyGroupNoMembers(t *testing.T) {

	ctx, gm, _, done := newTestGroupManager(t, false, &pldconf.GroupManagerConfig{}, mockEmptyMessageListeners, mockBeginRollback)
	defer done()

	err := gm.p.Transaction(ctx, func(ctx context.Context, dbTX persistence.DBTX) error {
		_, err := gm.CreateGroup(ctx, dbTX, &pldapi.PrivacyGroupInput{
			Domain: "domain1",
		})
		return err
	})
	require.Regexp(t, "PD012501", err)
}

func TestPrivacyGroupNonQualfiedMembers(t *testing.T) {

	ctx, gm, _, done := newTestGroupManager(t, false, &pldconf.GroupManagerConfig{}, mockEmptyMessageListeners, mockBeginRollback)
	defer done()

	err := gm.p.Transaction(ctx, func(ctx context.Context, dbTX persistence.DBTX) error {
		_, err := gm.CreateGroup(ctx, dbTX, &pldapi.PrivacyGroupInput{
			Domain:  "domain1",
			Members: []string{"me", "you"},
		})
		return err
	})
	require.Regexp(t, "PD020017", err)
}

func TestPrivacyGroupNoTransportsForNode(t *testing.T) {

	ctx, gm, _, done := newTestGroupManager(t, false, &pldconf.GroupManagerConfig{},
		mockEmptyMessageListeners,
		mockBeginRollback,
		func(mc *mockComponents, conf *pldconf.GroupManagerConfig) {
			mc.registryManager.On("GetNodeTransports", mock.Anything, "node2").
				Return(nil, fmt.Errorf("nope"))
		})
	defer done()

	err := gm.p.Transaction(ctx, func(ctx context.Context, dbTX persistence.DBTX) error {
		_, err := gm.CreateGroup(ctx, dbTX, &pldapi.PrivacyGroupInput{
			Domain:  "domain1",
			Members: []string{"me@node1", "you@node2"},
		})
		return err
	})
	require.Regexp(t, "nope", err)
}

func TestPrivacyGroupInvalidDomain(t *testing.T) {

	ctx, gm, _, done := newTestGroupManager(t, false, &pldconf.GroupManagerConfig{},
		mockEmptyMessageListeners,
		mockBeginRollback,
		func(mc *mockComponents, conf *pldconf.GroupManagerConfig) {
			mc.registryManager.On("GetNodeTransports", mock.Anything, "node2").Return(nil, nil)

			mc.domainManager.On("GetDomainByName", mock.Anything, "domain2").Return(nil, fmt.Errorf("nope"))
		})
	defer done()

	err := gm.p.Transaction(ctx, func(ctx context.Context, dbTX persistence.DBTX) error {
		_, err := gm.CreateGroup(ctx, dbTX, &pldapi.PrivacyGroupInput{
			Domain:  "domain2",
			Members: []string{"me@node1", "you@node2"},
		})
		return err
	})
	require.Regexp(t, "nope", err)
}

func TestPrivacyGroupDomainInitFail(t *testing.T) {

	ctx, gm, _, done := newTestGroupManager(t, false, &pldconf.GroupManagerConfig{},
		mockEmptyMessageListeners,
		mockBeginRollback,
		func(mc *mockComponents, conf *pldconf.GroupManagerConfig) {
			mc.registryManager.On("GetNodeTransports", mock.Anything, "node2").Return(nil, nil)
			mc.domain.On("InitPrivacyGroup", mock.Anything, mock.Anything).Return(nil, fmt.Errorf("pop"))
		})
	defer done()

	err := gm.p.Transaction(ctx, func(ctx context.Context, dbTX persistence.DBTX) error {
		_, err := gm.CreateGroup(ctx, dbTX, &pldapi.PrivacyGroupInput{
			Domain:  "domain1",
			Members: []string{"me@node1", "you@node2"},
		})
		return err
	})
	require.Regexp(t, "pop", err)
}

func TestPrivacyGroupDomainInitGenerateBadSchema(t *testing.T) {

	ctx, gm, _, done := newTestGroupManager(t, false, &pldconf.GroupManagerConfig{},
		mockEmptyMessageListeners,
		mockBeginRollback,
		func(mc *mockComponents, conf *pldconf.GroupManagerConfig) {
			mc.registryManager.On("GetNodeTransports", mock.Anything, "node2").Return(nil, nil)
			mc.domain.On("InitPrivacyGroup", mock.Anything, mock.Anything).
				Return(&components.PreparedGroupInitTransaction{
					GenesisState:  tktypes.RawJSON(`{}`),
					GenesisSchema: &abi.Parameter{},
				}, nil)
			mc.stateManager.On("EnsureABISchemas", mock.Anything, mock.Anything, "domain1", mock.Anything).
				Return(nil, fmt.Errorf("pop"))
		})
	defer done()

	err := gm.p.Transaction(ctx, func(ctx context.Context, dbTX persistence.DBTX) error {
		_, err := gm.CreateGroup(ctx, dbTX, &pldapi.PrivacyGroupInput{
			Domain:  "domain1",
			Members: []string{"me@node1", "you@node2"},
		})
		return err
	})
	require.Regexp(t, "pop", err)
}

func TestPrivacyGroupWriteStateFail(t *testing.T) {

	ctx, gm, _, done := newTestGroupManager(t, false, &pldconf.GroupManagerConfig{},
		mockEmptyMessageListeners,
		mockBeginRollback,
		func(mc *mockComponents, conf *pldconf.GroupManagerConfig) {
			mc.registryManager.On("GetNodeTransports", mock.Anything, "node2").Return(nil, nil)
			mc.domain.On("InitPrivacyGroup", mock.Anything, mock.Anything).
				Return(&components.PreparedGroupInitTransaction{
					GenesisState:  tktypes.RawJSON(`{}`),
					GenesisSchema: &abi.Parameter{},
				}, nil)
			ms := componentmocks.NewSchema(t)
			ms.On("ID").Return(tktypes.RandBytes32())
			mc.stateManager.On("EnsureABISchemas", mock.Anything, mock.Anything, "domain1", mock.Anything).
				Return([]components.Schema{ms}, nil)
			mc.stateManager.On("WriteReceivedStates", mock.Anything, mock.Anything, "domain1", mock.Anything).
				Return(nil, fmt.Errorf("pop"))
		})
	defer done()

	err := gm.p.Transaction(ctx, func(ctx context.Context, dbTX persistence.DBTX) error {
		_, err := gm.CreateGroup(ctx, dbTX, &pldapi.PrivacyGroupInput{
			Domain:  "domain1",
			Members: []string{"me@node1", "you@node2"},
		})
		return err
	})
	require.Regexp(t, "pop", err)
}

func TestPrivacyGroupSendTransactionFail(t *testing.T) {

	ctx, gm, _, done := newTestGroupManager(t, false, &pldconf.GroupManagerConfig{},
		mockEmptyMessageListeners,
		mockBeginRollback,
		mockReadyToSendTransaction(t),
		func(mc *mockComponents, conf *pldconf.GroupManagerConfig) {
			mc.txManager.On("SendTransactions", mock.Anything, mock.Anything, mock.Anything).Return(nil, fmt.Errorf("pop"))
		})
	defer done()

	err := gm.p.Transaction(ctx, func(ctx context.Context, dbTX persistence.DBTX) error {
		_, err := gm.CreateGroup(ctx, dbTX, &pldapi.PrivacyGroupInput{
			Domain:  "domain1",
			Members: []string{"me@node1", "you@node2"},
		})
		return err
	})
	require.Regexp(t, "pop", err)
}

func mockReadyToSendTransaction(t *testing.T) func(mc *mockComponents, conf *pldconf.GroupManagerConfig) {
	return func(mc *mockComponents, conf *pldconf.GroupManagerConfig) {
		mc.registryManager.On("GetNodeTransports", mock.Anything, "node2").Return(nil, nil)
		mc.domain.On("InitPrivacyGroup", mock.Anything, mock.Anything).
			Return(&components.PreparedGroupInitTransaction{
				TX: &pldapi.TransactionInput{
					TransactionBase: pldapi.TransactionBase{
						Domain: "domain1",
						Type:   pldapi.TransactionTypePrivate.Enum(),
					},
				},
				GenesisState: tktypes.RawJSON(`{}`),
				GenesisSchema: &abi.Parameter{
					Type:         "tuple",
					Name:         "TestGroup",
					InternalType: "struct TestGroup;",
					Components:   abi.ParameterArray{},
				},
			}, nil)
		ms := componentmocks.NewSchema(t)
		ms.On("ID").Return(tktypes.RandBytes32())
		ms.On("Signature").Return("").Maybe()
		mc.stateManager.On("EnsureABISchemas", mock.Anything, mock.Anything, "domain1", mock.Anything).
			Return([]components.Schema{ms}, nil)
		mc.stateManager.On("WriteReceivedStates", mock.Anything, mock.Anything, "domain1", mock.Anything).
			Return([]*pldapi.State{
				{StateBase: pldapi.StateBase{
					ID: tktypes.RandBytes(32),
				}},
			}, nil)
	}
}

func mockReadyToInsertGroup(t *testing.T) func(mc *mockComponents, conf *pldconf.GroupManagerConfig) {
	return func(mc *mockComponents, conf *pldconf.GroupManagerConfig) {
		mockReadyToSendTransaction(t)(mc, conf)
		mc.txManager.On("SendTransactions", mock.Anything, mock.Anything, mock.Anything).Return([]uuid.UUID{uuid.New()}, nil)
	}
}

func TestPrivacyGroupWriteGroupFail(t *testing.T) {

	ctx, gm, mc, done := newTestGroupManager(t, false, &pldconf.GroupManagerConfig{},
		mockEmptyMessageListeners,
		mockReadyToInsertGroup(t),
		func(mc *mockComponents, conf *pldconf.GroupManagerConfig) {
			mc.db.Mock.ExpectBegin()
			mc.db.Mock.ExpectExec("INSERT.*privacy_groups").WillReturnError(fmt.Errorf("pop"))
			mc.db.Mock.ExpectRollback()
		})
	defer done()

	err := gm.p.Transaction(ctx, func(ctx context.Context, dbTX persistence.DBTX) error {
		_, err := gm.CreateGroup(ctx, dbTX, &pldapi.PrivacyGroupInput{
			Domain:  "domain1",
			Members: []string{"me@node1", "you@node2"},
		})
		return err
	})
	require.Regexp(t, "pop", err)

	require.NoError(t, mc.db.Mock.ExpectationsWereMet())

}

func TestPrivacyGroupMembersWriteFail(t *testing.T) {

	ctx, gm, mc, done := newTestGroupManager(t, false, &pldconf.GroupManagerConfig{},
		mockEmptyMessageListeners,
		mockReadyToInsertGroup(t),
		func(mc *mockComponents, conf *pldconf.GroupManagerConfig) {
			mc.db.Mock.ExpectBegin()
			mc.db.Mock.ExpectExec("INSERT.*privacy_groups").WillReturnResult(driver.ResultNoRows)
			mc.db.Mock.ExpectExec("INSERT.*privacy_group_members").WillReturnError(fmt.Errorf("pop"))
			mc.db.Mock.ExpectRollback()
		})
	defer done()

	err := gm.p.Transaction(ctx, func(ctx context.Context, dbTX persistence.DBTX) error {
		_, err := gm.CreateGroup(ctx, dbTX, &pldapi.PrivacyGroupInput{
			Domain:  "domain1",
			Members: []string{"me@node1", "you@node2"},
		})
		return err
	})
	require.Regexp(t, "pop", err)

	require.NoError(t, mc.db.Mock.ExpectationsWereMet())
}

func mockInsertPrivacyGroupOK(mc *mockComponents, conf *pldconf.GroupManagerConfig) {
	mc.db.Mock.ExpectBegin()
	mc.db.Mock.ExpectExec("INSERT.*privacy_groups").WillReturnResult(driver.ResultNoRows)
	mc.db.Mock.ExpectExec("INSERT.*privacy_group_members").WillReturnResult(driver.ResultNoRows)
	mc.db.Mock.ExpectRollback()
}

func TestPrivacyGroupSendReliableFail(t *testing.T) {

	ctx, gm, mc, done := newTestGroupManager(t, false, &pldconf.GroupManagerConfig{},
		mockEmptyMessageListeners,
		mockReadyToInsertGroup(t),
		mockInsertPrivacyGroupOK,
		func(mc *mockComponents, conf *pldconf.GroupManagerConfig) {
			mc.transportManager.On("SendReliable", mock.Anything, mock.Anything, mock.Anything).
				Return(fmt.Errorf("pop"))
		},
	)
	defer done()

	err := gm.p.Transaction(ctx, func(ctx context.Context, dbTX persistence.DBTX) error {
		_, err := gm.CreateGroup(ctx, dbTX, &pldapi.PrivacyGroupInput{
			Domain:  "domain1",
			Members: []string{"me@node1", "you@node2"},
		})
		return err
	})
	require.Regexp(t, "pop", err)

	require.NoError(t, mc.db.Mock.ExpectationsWereMet())
}

func TestQueryGroupsFail(t *testing.T) {

	ctx, gm, mc, done := newTestGroupManager(t, false, &pldconf.GroupManagerConfig{}, mockEmptyMessageListeners)
	defer done()

	mc.db.Mock.ExpectQuery("SELECT.*privacy_groups").WillReturnError(fmt.Errorf("pop"))

	_, err := gm.QueryGroups(ctx, gm.p.NOTX(), query.NewQueryBuilder().Limit(1).Query())
	require.Regexp(t, "pop", err)
}

func TestQueryGroupsEnrichMembersFail(t *testing.T) {

	ctx, gm, mc, done := newTestGroupManager(t, false, &pldconf.GroupManagerConfig{}, mockEmptyMessageListeners)
	defer done()

	mc.db.Mock.ExpectQuery("SELECT.*privacy_groups").WillReturnRows(sqlmock.NewRows([]string{
		"domain",
		"id",
	}).AddRow(
		"domain1",
		tktypes.RandBytes(32),
	))
	mc.db.Mock.ExpectQuery("SELECT.*privacy_group_members").WillReturnError(fmt.Errorf("pop"))

	_, err := gm.QueryGroups(ctx, gm.p.NOTX(), query.NewQueryBuilder().Limit(1).Query())
	require.Regexp(t, "pop", err)
}

func TestQueryGroupsEnrichGenesisFail(t *testing.T) {

	ctx, gm, mc, done := newTestGroupManager(t, false, &pldconf.GroupManagerConfig{}, mockEmptyMessageListeners)
	defer done()

	mc.db.Mock.ExpectQuery("SELECT.*privacy_groups").WillReturnRows(sqlmock.NewRows([]string{
		"domain",
		"id",
	}).AddRow(
		"domain1",
		tktypes.RandBytes(32),
	))
	mc.db.Mock.ExpectQuery("SELECT.*privacy_group_members").WillReturnRows(sqlmock.NewRows([]string{}))

	mc.stateManager.On("GetStatesByID", mock.Anything, mock.Anything, "domain1", (*tktypes.EthAddress)(nil), mock.Anything, false, false).
		Return(nil, fmt.Errorf("pop"))

	_, err := gm.QueryGroups(ctx, gm.p.NOTX(), query.NewQueryBuilder().Limit(1).Query())
	require.Regexp(t, "pop", err)
}

func TestQueryGroupsByPropertiesFail(t *testing.T) {

	ctx, gm, mc, done := newTestGroupManager(t, false, &pldconf.GroupManagerConfig{}, mockEmptyMessageListeners)
	defer done()

	schemaID := tktypes.RandBytes32()
	dbTX := gm.p.NOTX()
	mc.stateManager.On("FindStates", mock.Anything, dbTX, "domain1", schemaID, mock.Anything, mock.Anything).
		Return(nil, fmt.Errorf("pop"))

	_, err := gm.QueryGroupsByProperties(ctx, dbTX, "domain1", schemaID, query.NewQueryBuilder().Limit(1).Query())
	require.Regexp(t, "pop", err)
}

func TestQueryGroupsByPropertiesNoResults(t *testing.T) {

	ctx, gm, mc, done := newTestGroupManager(t, false, &pldconf.GroupManagerConfig{}, mockEmptyMessageListeners)
	defer done()

	schemaID := tktypes.RandBytes32()
	dbTX := gm.p.NOTX()
	mc.stateManager.On("FindStates", mock.Anything, dbTX, "domain1", schemaID, mock.Anything, mock.Anything).
		Return([]*pldapi.State{}, nil)

	groups, err := gm.QueryGroupsByProperties(ctx, dbTX, "domain1", schemaID, query.NewQueryBuilder().Limit(1).Query())
	require.NoError(t, err)
	require.NotNil(t, groups)
	require.Empty(t, groups)
}

func TestQueryGroupsByPropertiesQueryFail(t *testing.T) {

	ctx, gm, mc, done := newTestGroupManager(t, false, &pldconf.GroupManagerConfig{}, mockEmptyMessageListeners)
	defer done()

	schemaID := tktypes.RandBytes32()
	dbTX := gm.p.NOTX()
	mc.stateManager.On("FindStates", mock.Anything, dbTX, "domain1", schemaID, mock.Anything, mock.Anything).
		Return([]*pldapi.State{
			{
				StateBase: pldapi.StateBase{
					ID: tktypes.RandBytes(32),
				},
			},
		}, nil)

	mc.db.Mock.ExpectQuery("SELECT.*privacy_groups").WillReturnError(fmt.Errorf("pop"))

	_, err := gm.QueryGroupsByProperties(ctx, dbTX, "domain1", schemaID, query.NewQueryBuilder().Limit(1).Query())
	assert.Regexp(t, "pop", err)
}

func TestQueryGroupsByPropertiesMembersFail(t *testing.T) {

	ctx, gm, mc, done := newTestGroupManager(t, false, &pldconf.GroupManagerConfig{}, mockEmptyMessageListeners)
	defer done()

	schemaID := tktypes.RandBytes32()
	dbTX := gm.p.NOTX()
	stateID := tktypes.RandBytes(32)
	mc.stateManager.On("FindStates", mock.Anything, dbTX, "domain1", schemaID, mock.Anything, mock.Anything).
		Return([]*pldapi.State{
			{
				StateBase: pldapi.StateBase{
					ID: stateID,
				},
			},
		}, nil)

	mc.db.Mock.ExpectQuery("SELECT.*privacy_groups").WillReturnRows(sqlmock.NewRows([]string{
		"domain",
		"id",
	}).AddRow(
		"domain1",
		stateID,
	))
	mc.db.Mock.ExpectQuery("SELECT.*privacy_group_members").WillReturnError(fmt.Errorf("pop"))

	_, err := gm.QueryGroupsByProperties(ctx, dbTX, "domain1", schemaID, query.NewQueryBuilder().Limit(1).Query())
	assert.Regexp(t, "pop", err)
}

func TestGetGroupByIDFailDB(t *testing.T) {

	ctx, gm, mc, done := newTestGroupManager(t, false, &pldconf.GroupManagerConfig{}, mockEmptyMessageListeners)
	defer done()

	mc.db.Mock.ExpectQuery("SELECT.*privacy_groups").WillReturnError(fmt.Errorf("pop"))

	_, err := gm.GetGroupByID(ctx, gm.p.NOTX(), "domain1", tktypes.RandBytes(32))
	assert.Regexp(t, "pop", err)
}

func mockDBPrivacyGroup(mc *mockComponents, schemaID tktypes.Bytes32, stateID tktypes.HexBytes, contractAddr *tktypes.EthAddress, members ...string) {
	mc.db.Mock.ExpectQuery("SELECT.*privacy_groups").WillReturnRows(sqlmock.NewRows([]string{
		"domain",
		"id",
		"schema_id",
		`Receipt__contract_address`,
	}).AddRow(
		"domain1",
		stateID,
		schemaID,
		contractAddr,
	))
	memberRows := sqlmock.NewRows([]string{"group", "domain", "idx", "identity"})
	for i, m := range members {
		memberRows.AddRow(stateID, "domain1", i, m)
	}
	mc.db.Mock.ExpectQuery("SELECT.*privacy_group_members").WillReturnRows(memberRows)
}

func mockPrivacyGroupState(mc *mockComponents, schemaID tktypes.Bytes32, id tktypes.HexBytes) {
	mc.stateManager.On("GetStatesByID", mock.Anything, mock.Anything, "domain1", (*tktypes.EthAddress)(nil), []tktypes.HexBytes{id}, false, false).
		Return([]*pldapi.State{
			{StateBase: pldapi.StateBase{
				ID:     id,
				Schema: schemaID,
				Data:   tktypes.RawJSON(`{}`),
			}},
		}, nil)
	mc.stateManager.On("GetSchemaByID", mock.Anything, mock.Anything, "domain1", schemaID, true).
		Return(&pldapi.Schema{
			ID:         schemaID,
			Definition: tktypes.JSONString(&abi.Parameter{Type: "tuple", InternalType: "struct MyType;", Components: abi.ParameterArray{}}),
		}, nil)
}

func TestGetGroupByIDFailSchema(t *testing.T) {

	ctx, gm, mc, done := newTestGroupManager(t, false, &pldconf.GroupManagerConfig{}, mockEmptyMessageListeners)
	defer done()

	schemaID := tktypes.RandBytes32()
	groupID := tktypes.RandBytes(32)
	mockDBPrivacyGroup(mc, schemaID, groupID, nil)

	mc.stateManager.On("GetStatesByID", mock.Anything, mock.Anything, "domain1", (*tktypes.EthAddress)(nil), mock.Anything, false, false).
		Return(nil, nil)
	mc.stateManager.On("GetSchemaByID", mock.Anything, mock.Anything, "domain1", schemaID, true).
		Return(nil, fmt.Errorf("pop"))

	_, err := gm.GetGroupByID(ctx, gm.p.NOTX(), "domain1", groupID)
	assert.Regexp(t, "pop", err)
}

func TestSendTransactionNoDomain(t *testing.T) {

	ctx, gm, _, done := newTestGroupManager(t, false, &pldconf.GroupManagerConfig{}, mockEmptyMessageListeners)
	defer done()

	_, err := gm.SendTransaction(ctx, gm.p.NOTX(), &pldapi.PrivacyGroupEVMTXInput{})
	require.Regexp(t, "PD012505", err)

}

func TestSendTransactionNoGroup(t *testing.T) {

	ctx, gm, _, done := newTestGroupManager(t, false, &pldconf.GroupManagerConfig{}, mockEmptyMessageListeners)
	defer done()

	_, err := gm.SendTransaction(ctx, gm.p.NOTX(), &pldapi.PrivacyGroupEVMTXInput{
		Domain: "domain1",
	})
	require.Regexp(t, "PD012504", err)

}

func TestSendTransactionGroupNotFound(t *testing.T) {

	ctx, gm, mc, done := newTestGroupManager(t, false, &pldconf.GroupManagerConfig{}, mockEmptyMessageListeners)
	defer done()

	mc.db.Mock.ExpectQuery("SELECT.*privacy_groups").WillReturnRows(sqlmock.NewRows([]string{}))

	_, err := gm.SendTransaction(ctx, gm.p.NOTX(), &pldapi.PrivacyGroupEVMTXInput{
		Domain: "domain1",
		Group:  tktypes.RandBytes(32),
	})
	require.Regexp(t, "PD012502", err)

}

func TestSendTransactionGroupFailQuery(t *testing.T) {

	ctx, gm, mc, done := newTestGroupManager(t, false, &pldconf.GroupManagerConfig{}, mockEmptyMessageListeners)
	defer done()

	mc.db.Mock.ExpectQuery("SELECT.*privacy_groups").WillReturnError(fmt.Errorf("pop"))

	_, err := gm.SendTransaction(ctx, gm.p.NOTX(), &pldapi.PrivacyGroupEVMTXInput{
		Domain: "domain1",
		Group:  tktypes.RandBytes(32),
	})
	require.Regexp(t, "pop", err)

}

func TestSendTransactionGroupNotReady(t *testing.T) {

	ctx, gm, mc, done := newTestGroupManager(t, false, &pldconf.GroupManagerConfig{}, mockEmptyMessageListeners)
	defer done()

	schemaID := tktypes.RandBytes32()
	groupID := tktypes.RandBytes(32)
	mockDBPrivacyGroup(mc, schemaID, groupID, nil)
	mockPrivacyGroupState(mc, schemaID, groupID)

	_, err := gm.SendTransaction(ctx, gm.p.NOTX(), &pldapi.PrivacyGroupEVMTXInput{
		Domain: "domain1",
		Group:  groupID,
	})
	require.Regexp(t, "PD012503", err)

}

func TestSendTransactionGroupGetContractFail(t *testing.T) {

	ctx, gm, mc, done := newTestGroupManager(t, false, &pldconf.GroupManagerConfig{}, mockEmptyMessageListeners)
	defer done()

	schemaID := tktypes.RandBytes32()
	groupID := tktypes.RandBytes(32)
	contractAddr := tktypes.RandAddress()
	mockDBPrivacyGroup(mc, schemaID, groupID, contractAddr)
	mockPrivacyGroupState(mc, schemaID, groupID)

	mc.domainManager.On("GetSmartContractByAddress", mock.Anything, mock.Anything, *contractAddr).Return(nil, fmt.Errorf("pop"))

	var res any
	err := gm.Call(ctx, gm.p.NOTX(), &res, &pldapi.PrivacyGroupEVMCall{
		Domain: "domain1",
		Group:  groupID,
	})
	require.Regexp(t, "pop", err)

}

func TestSendTransactionSendPreparedTx(t *testing.T) {

	ctx, gm, mc, done := newTestGroupManager(t, false, &pldconf.GroupManagerConfig{}, mockEmptyMessageListeners)
	defer done()

	schemaID := tktypes.RandBytes32()
	groupID := tktypes.RandBytes(32)
	contractAddr := tktypes.RandAddress()
	mockDBPrivacyGroup(mc, schemaID, groupID, contractAddr)
	mockPrivacyGroupState(mc, schemaID, groupID)

	psc := componentmocks.NewDomainSmartContract(t)
	mc.domainManager.On("GetSmartContractByAddress", mock.Anything, mock.Anything, *contractAddr).Return(psc, nil)

	psc.On("WrapPrivacyGroupEVMTX", mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(&pldapi.TransactionInput{}, nil)
	mc.txManager.On("SendTransactions", mock.Anything, mock.Anything, mock.Anything).Return(nil, fmt.Errorf("pop"))

	_, err := gm.SendTransaction(ctx, gm.p.NOTX(), &pldapi.PrivacyGroupEVMTXInput{
		Domain: "domain1",
		Group:  groupID,
	})
	require.Regexp(t, "pop", err)

}

func TestStoreReceivedGroupOk(t *testing.T) {

	ctx, gm, mc, done := newTestGroupManager(t, false, &pldconf.GroupManagerConfig{}, mockEmptyMessageListeners)
	defer done()

	txID := uuid.New()
	schema := &pldapi.Schema{
		Signature: "signature1",
		ID:        tktypes.RandBytes32(),
	}
	state := &pldapi.State{
		StateBase: pldapi.StateBase{
			ID:     tktypes.RandBytes(32),
			Schema: schema.ID,
		},
	}

	mc.db.Mock.ExpectBegin()
	mc.domain.On("ValidatePrivacyGroup", mock.Anything, schema, state).Return([]string{"me@node1", "you@node2"}, nil)
	mc.db.Mock.ExpectExec("INSERT.*privacy_groups").WillReturnResult(driver.ResultNoRows)
	mc.db.Mock.ExpectExec("INSERT.*privacy_group_members").WillReturnResult(driver.ResultNoRows)
	mc.db.Mock.ExpectCommit()

	err := gm.p.Transaction(ctx, func(ctx context.Context, dbTX persistence.DBTX) error {
		validationErr, err := gm.StoreReceivedGroup(ctx, dbTX, "domain1", txID, schema, state)
		require.NoError(t, validationErr)
		return err
	})
	require.NoError(t, err)

}

func TestStoreReceivedGroupFailInsert(t *testing.T) {

	ctx, gm, mc, done := newTestGroupManager(t, false, &pldconf.GroupManagerConfig{}, mockEmptyMessageListeners)
	defer done()

	txID := uuid.New()
	schema := &pldapi.Schema{
		Signature: "signature1",
		ID:        tktypes.RandBytes32(),
	}
	state := &pldapi.State{
		StateBase: pldapi.StateBase{
			ID:     tktypes.RandBytes(32),
			Schema: schema.ID,
		},
	}

	mc.db.Mock.ExpectBegin()
	mc.domain.On("ValidatePrivacyGroup", mock.Anything, schema, state).Return([]string{"me@node1", "you@node2"}, nil)
	mc.db.Mock.ExpectExec("INSERT.*privacy_groups").WillReturnError(fmt.Errorf("pop"))

	err := gm.p.Transaction(ctx, func(ctx context.Context, dbTX persistence.DBTX) error {
		validationErr, err := gm.StoreReceivedGroup(ctx, dbTX, "domain1", txID, schema, state)
		require.NoError(t, validationErr)
		return err
	})
	require.Regexp(t, "pop", err)

}

func TestStoreReceivedGroupFailUnknownDomain(t *testing.T) {

	ctx, gm, mc, done := newTestGroupManager(t, false, &pldconf.GroupManagerConfig{}, mockEmptyMessageListeners,
		func(mc *mockComponents, conf *pldconf.GroupManagerConfig) {
			mc.domainManager.On("GetDomainByName", mock.Anything, "domain2").Return(nil, fmt.Errorf("domain not found"))
		})
	defer done()

	txID := uuid.New()
	schema := &pldapi.Schema{
		Signature: "signature1",
		ID:        tktypes.RandBytes32(),
	}
	state := &pldapi.State{
		StateBase: pldapi.StateBase{
			ID:     tktypes.RandBytes(32),
			Schema: schema.ID,
		},
	}

	mc.db.Mock.ExpectBegin()
	mc.db.Mock.ExpectCommit()

	err := gm.p.Transaction(ctx, func(ctx context.Context, dbTX persistence.DBTX) error {
		validationErr, err := gm.StoreReceivedGroup(ctx, dbTX, "domain2", txID, schema, state)
		require.Regexp(t, "domain not found", validationErr)
		return err
	})
	require.NoError(t, err)

}

func TestStoreReceivedGroupFailValidation(t *testing.T) {

	ctx, gm, mc, done := newTestGroupManager(t, false, &pldconf.GroupManagerConfig{}, mockEmptyMessageListeners)
	defer done()

	txID := uuid.New()
	schema := &pldapi.Schema{
		Signature: "signature1",
		ID:        tktypes.RandBytes32(),
	}
	state := &pldapi.State{
		StateBase: pldapi.StateBase{
			ID:     tktypes.RandBytes(32),
			Schema: schema.ID,
		},
	}

	mc.db.Mock.ExpectBegin()
	mc.domain.On("ValidatePrivacyGroup", mock.Anything, schema, state).Return(nil, fmt.Errorf("wrong"))
	mc.db.Mock.ExpectCommit()

	err := gm.p.Transaction(ctx, func(ctx context.Context, dbTX persistence.DBTX) error {
		validationErr, err := gm.StoreReceivedGroup(ctx, dbTX, "domain1", txID, schema, state)
		require.Regexp(t, "wrong", validationErr)
		return err
	})
	require.NoError(t, err)

}
