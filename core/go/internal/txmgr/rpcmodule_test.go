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
	"fmt"
	"testing"

	"github.com/hyperledger/firefly-signer/pkg/rpcbackend"
	"github.com/kaleido-io/paladin/core/internal/httpserver"
	"github.com/kaleido-io/paladin/core/internal/rpcserver"
	"github.com/kaleido-io/paladin/toolkit/pkg/confutil"
	"github.com/stretchr/testify/require"
)

func newTestTransactionManagerWithRPC(t *testing.T, init ...func(*Config, *mockComponents)) (context.Context, string, *txManager, func()) {
	ctx, txm, txmDone := newTestTransactionManager(t, true, init...)

	rpcServer, err := rpcserver.NewRPCServer(ctx, &rpcserver.Config{
		HTTP: rpcserver.HTTPEndpointConfig{
			Config: httpserver.Config{
				Port:            confutil.P(0),
				ShutdownTimeout: confutil.P("0"),
			},
		},
		WS: rpcserver.WSEndpointConfig{Disabled: true},
	})
	require.NoError(t, err)

	return ctx, fmt.Sprintf("http://%s", rpcServer.HTTPAddr()), txm, func() {
		txmDone()
		rpcServer.Stop()
	}

}

func TestTransactionLifecycle(t *testing.T) {

	ctx, url, txm, done := newTestTransactionManagerWithRPC(t)
	defer done()

	rpcClient := rpcbackend.NewRPCClient()

}
