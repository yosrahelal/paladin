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

package rpcclient

import (
	"context"
	"fmt"
	"testing"

	"github.com/hyperledger/firefly-common/pkg/fftypes"
	"github.com/hyperledger/firefly-common/pkg/i18n"
	"github.com/hyperledger/firefly-signer/pkg/rpcbackend"
	"github.com/kaleido-io/paladin/toolkit/mocks/rpcbackendmocks"
	"github.com/kaleido-io/paladin/toolkit/pkg/tktypes"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

func newWrappedHTTP(t *testing.T) (context.Context, *httpWrap, *rpcbackendmocks.Backend) {
	ctx := context.Background()
	iC, err := NewHTTPClient(ctx, &HTTPConfig{
		URL: "http://localhost:8545",
	})
	require.NoError(t, err)

	mc := rpcbackendmocks.NewBackend(t)
	c := iC.(*httpWrap)
	c.c = mc

	return ctx, c, mc
}

func newWrappedWS(t *testing.T) (context.Context, *wsWrap, *rpcbackendmocks.WebSocketRPCClient) {
	ctx := context.Background()
	iC, err := NewWSClient(ctx, &WSConfig{
		HTTPConfig: HTTPConfig{
			URL: "ws://localhost:8545",
		},
	})
	require.NoError(t, err)

	mc := rpcbackendmocks.NewWebSocketRPCClient(t)
	c := iC.(*wsWrap)
	c.c = mc

	return ctx, c, mc
}

func TestHTTPClientWrappingOK(t *testing.T) {

	ctx, c, mc := newWrappedHTTP(t)

	mc.On("CallRPC", ctx, mock.Anything, "any_method", "param1").Return(nil).Run(func(args mock.Arguments) {
		*(args[1].(*string)) = "result"
	})

	var s string
	err := c.CallRPC(ctx, &s, "any_method", "param1")
	assert.NoError(t, err)

	assert.Equal(t, "result", s)
}

func TestHTTPClientWrappingErr(t *testing.T) {

	ctx, c, mc := newWrappedHTTP(t)

	mc.On("CallRPC", ctx, mock.Anything, "any_method", "param1").Return(
		NewRPCError(ctx, RPCCodeInternalError, i18n.Msg404NoResult),
	)

	var s string
	err := c.CallRPC(ctx, &s, "any_method", "param1")
	assert.Regexp(t, "FF00164.*", err)
	assert.NotNil(t, err.RPCError())
	assert.Equal(t, int64(RPCCodeInternalError), err.RPCError().Code)
}

func TestWSClientWrappingOK(t *testing.T) {

	ctx, c, mc := newWrappedWS(t)

	mc.On("CallRPC", ctx, mock.Anything, "any_method", "param1").Return(nil).Run(func(args mock.Arguments) {
		*(args[1].(*string)) = "result"
	})

	var s string
	err := c.CallRPC(ctx, &s, "any_method", "param1")
	assert.NoError(t, err)

	assert.Equal(t, "result", s)
}

func TestWSClientWrappingErr(t *testing.T) {

	ctx, c, mc := newWrappedWS(t)

	mc.On("CallRPC", ctx, mock.Anything, "any_method", "param1").Return(
		NewRPCError(ctx, RPCCodeInternalError, i18n.Msg404NoResult),
	)

	var s string
	err := c.CallRPC(ctx, &s, "any_method", "param1")
	assert.Regexp(t, "FF00164.*", err)
	assert.NotNil(t, err.RPCError())
	assert.Equal(t, int64(RPCCodeInternalError), err.RPCError().Code)
}

func TestWSClientSubscribeWrappingOK(t *testing.T) {

	ctx, c, mc := newWrappedWS(t)

	ms := rpcbackendmocks.NewSubscription(t)
	mc.On("Connect", ctx).Return(nil)
	mc.On("Subscriptions").Return([]rpcbackend.Subscription{ms})
	mc.On("Subscribe", ctx, "param1").Return(nil,
		NewRPCError(ctx, RPCCodeInternalError, i18n.Msg404NoResult),
	).Once()
	mc.On("Subscribe", ctx, "param1").Return(ms, nil)
	mc.On("UnsubscribeAll", ctx).Return(nil)
	mc.On("Close").Return(nil)

	err := c.Connect(ctx)
	assert.NoError(t, err)

	subs := c.Subscriptions()
	assert.Len(t, subs, 1)

	_, err = c.Subscribe(ctx, "param1")
	assert.Regexp(t, "FF00164", err)

	s, err := c.Subscribe(ctx, "param1")
	assert.NoError(t, err)
	assert.NotNil(t, s)

	u := fftypes.NewUUID()
	ms.On("LocalID").Return(u)
	assert.Equal(t, u.String(), s.LocalID().String())

	ms.On("Unsubscribe", ctx).Return(nil)
	err = s.Unsubscribe(ctx)
	assert.NoError(t, err)

	ch := make(chan *rpcbackend.RPCSubscriptionNotification, 1)
	ch <- &rpcbackend.RPCSubscriptionNotification{CurrentSubID: "sub1", Result: fftypes.JSONAnyPtr(`{"hello":"world"}`)}
	ms.On("Notifications").Return(ch)
	n := <-s.Notifications()
	assert.Equal(t, RPCSubscriptionNotification{
		CurrentSubID: "sub1",
		Result:       tktypes.RawJSON(`{"hello":"world"}`),
	}, *n)
	close(ch)

	err = c.UnsubscribeAll(ctx)
	assert.NoError(t, err)

	c.Close()
}

func TestRPCErrorResponse(t *testing.T) {
	rpcRes := NewRPCErrorResponse(fmt.Errorf("pop"), tktypes.RawJSON(`"1"`), RPCCodeInternalError)
	assert.Equal(t, &RPCResponse{
		JSONRpc: "2.0",
		ID:      fftypes.JSONAnyPtr(`"1"`),
		Error: &RPCError{
			Code:    -32603,
			Message: "pop",
		},
	}, rpcRes)
}

func TestWrapErrorRPC(t *testing.T) {
	err := WrapErrorRPC(RPCCodeInternalError, fmt.Errorf("pop"))
	assert.Equal(t, &RPCError{
		Code:    -32603,
		Message: "pop",
	}, err.RPCError())
}
