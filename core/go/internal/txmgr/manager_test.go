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

package txmgr

import (
	"context"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/kaleido-io/paladin/core/internal/statestore"
	"github.com/kaleido-io/paladin/core/mocks/componentmocks"
	"github.com/kaleido-io/paladin/core/pkg/persistence"
	"github.com/kaleido-io/paladin/core/pkg/persistence/mockpersistence"
	"github.com/stretchr/testify/require"
)

type mockComponents struct {
	db            sqlmock.Sqlmock
	ethClient     *componentmocks.EthClient
	domainManager *componentmocks.DomainManager
	blockIndexer  *componentmocks.BlockIndexer
}

func newTestTransactionManager(t *testing.T, realDB bool, init ...func(conf *Config, mc *mockComponents)) (context.Context, *txManager, func()) {

	ctx := context.Background()

	conf := &Config{}
	mc := &mockComponents{
		blockIndexer:  componentmocks.NewBlockIndexer(t),
		domainManager: componentmocks.NewDomainManager(t),
	}

	componentMocks := componentmocks.NewAllComponents(t)
	componentMocks.On("BlockIndexer").Return(mc.blockIndexer).Maybe()
	componentMocks.On("DomainManager").Return(mc.domainManager).Maybe()

	var p persistence.Persistence
	var err error
	var pDone func()
	if realDB {
		p, pDone, err = persistence.NewUnitTestPersistence(ctx)
		require.NoError(t, err)
		realStateStore := statestore.NewStateStore(ctx, &statestore.Config{}, p)
		componentMocks.On("StateStore").Return(realStateStore)
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

	for _, fn := range init {
		fn(conf, mc)
	}

	txm := NewTXManager(ctx, conf)
	return ctx, txm.(*txManager), func() {
		pDone()
		txm.Stop()
	}

}
