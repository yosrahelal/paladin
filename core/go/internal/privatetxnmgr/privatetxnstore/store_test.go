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

package privatetxnstore

import (
	"context"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/kaleido-io/paladin/core/pkg/persistence"
	"github.com/kaleido-io/paladin/core/pkg/persistence/mockpersistence"
	"github.com/stretchr/testify/require"
)

func newDBTestStateStore(t *testing.T) (context.Context, *store, func()) {
	ctx := context.Background()
	p, pDone, err := persistence.NewUnitTestPersistence(ctx)
	require.NoError(t, err)
	ss := NewStore(ctx, &Config{}, p)
	return ctx, ss.(*store), func() {
		ss.Close()
		pDone()
	}
}

func newDBMockStateStore(t *testing.T) (context.Context, *store, sqlmock.Sqlmock, func()) {
	ctx := context.Background()
	p, err := mockpersistence.NewSQLMockProvider()
	require.NoError(t, err)
	ss := NewStore(ctx, &Config{}, p.P)
	return ctx, ss.(*store), p.Mock, func() {
		require.NoError(t, p.Mock.ExpectationsWereMet())
	}
}
