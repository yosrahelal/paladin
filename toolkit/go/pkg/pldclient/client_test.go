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

package pldclient

import (
	"context"
	"fmt"
	"testing"

	"github.com/kaleido-io/paladin/config/pkg/confutil"
	"github.com/kaleido-io/paladin/config/pkg/pldconf"
	"github.com/kaleido-io/paladin/toolkit/pkg/rpcserver"
	"github.com/stretchr/testify/require"
)

func newTestRPCServerHTTP(t *testing.T, conf *pldconf.RPCServerConfig) (string, rpcserver.RPCServer) {
	conf.HTTP.Address = confutil.P("127.0.0.1")
	conf.HTTP.Port = confutil.P(0)
	conf.HTTP.ShutdownTimeout = confutil.P("0s")
	conf.WS.Disabled = true
	rpcServer, err := rpcserver.NewRPCServer(context.Background(), conf)
	require.NoError(t, err)
	err = rpcServer.Start()
	require.NoError(t, err)
	return fmt.Sprintf("http://%s", rpcServer.HTTPAddr()), rpcServer
}

func newTestClientAndServerHTTP(t *testing.T) (context.Context, PaladinClient, rpcserver.RPCServer, func()) {

	ctx := context.Background()
	url, rpcServer := newTestRPCServerHTTP(t, &pldconf.RPCServerConfig{})
	c, err := New().HTTP(context.Background(), &pldconf.HTTPClientConfig{
		URL: url,
	})
	require.NoError(t, err)

	return ctx, c, rpcServer, rpcServer.Stop

}

func newTestRPCServerWebSockets(t *testing.T, conf *pldconf.RPCServerConfig) (string, rpcserver.RPCServer) {
	conf.WS.Address = confutil.P("127.0.0.1")
	conf.WS.Port = confutil.P(0)
	conf.WS.ShutdownTimeout = confutil.P("0s")
	conf.HTTP.Disabled = true
	rpcServer, err := rpcserver.NewRPCServer(context.Background(), conf)
	require.NoError(t, err)
	err = rpcServer.Start()
	require.NoError(t, err)
	return fmt.Sprintf("ws://%s", rpcServer.WSAddr()), rpcServer
}

func newTestClientAndServerWebSockets(t *testing.T) (context.Context, PaladinClient, rpcserver.RPCServer, func()) {

	ctx := context.Background()
	url, rpcServer := newTestRPCServerWebSockets(t, &pldconf.RPCServerConfig{})
	c, err := New().WebSocket(context.Background(), &pldconf.WSClientConfig{
		HTTPClientConfig: pldconf.HTTPClientConfig{
			URL: url,
		},
	})
	require.NoError(t, err)

	return ctx, c, rpcServer, func() {
		c.Close()
		rpcServer.Stop()
	}

}

func TestHTTPBadConfig(t *testing.T) {
	_, err := New().HTTP(context.Background(), &pldconf.HTTPClientConfig{})
	require.Regexp(t, "PD020501", err)
}

func TestWSBadConfig(t *testing.T) {
	_, err := New().WebSocket(context.Background(), &pldconf.WSClientConfig{})
	require.Regexp(t, "PD020500", err)
}
