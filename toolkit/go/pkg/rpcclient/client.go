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
	"sync"

	"github.com/go-resty/resty/v2"
	"github.com/google/uuid"
	"github.com/hyperledger/firefly-signer/pkg/rpcbackend"
	"github.com/kaleido-io/paladin/toolkit/pkg/tktypes"
)

const (
	RPCCodeParseError     int64 = int64(rpcbackend.RPCCodeParseError)
	RPCCodeInvalidRequest int64 = int64(rpcbackend.RPCCodeInvalidRequest)
	RPCCodeInternalError  int64 = int64(rpcbackend.RPCCodeInternalError)
)

type RPCRequest = rpcbackend.RPCRequest

type RPCResponse = rpcbackend.RPCResponse

type RPCError = rpcbackend.RPCError

type ErrorRPC interface {
	error
	RPCError() *RPCError
}

type Client interface {
	CallRPC(ctx context.Context, result interface{}, method string, params ...interface{}) ErrorRPC
}

type WSClient interface {
	Client
	Subscribe(ctx context.Context, params ...interface{}) (Subscription, error)
	Subscriptions() []Subscription
	UnsubscribeAll(ctx context.Context) ErrorRPC
	Connect(ctx context.Context) error
	Close()
}

type Subscription interface {
	LocalID() uuid.UUID // does not change through reconnects
	Notifications() chan *RPCSubscriptionNotification
	Unsubscribe(ctx context.Context) ErrorRPC
}

type RPCSubscriptionNotification struct {
	CurrentSubID string // will change on each reconnect
	Result       tktypes.RawJSON
}

// Note this is (currently) a very thin wrapper around rpcbackend in firefly-signer, which has a lot of very
// helpful code/utility, but a couple of weirdnesses in the interface that this package addresses.
// The biggest being the fact that the errors, are not errors (the Error() function returns the error, not a string).
func NewHTTPClient(ctx context.Context, conf *HTTPConfig) (Client, error) {
	rc, err := parseHTTPConfig(ctx, conf)
	if err != nil {
		return nil, err
	}
	return WrapRestyClient(rc), nil
}

func WrapRestyClient(rc *resty.Client) Client {
	return &httpWrap{c: rpcbackend.NewRPCClient(rc)}
}

func NewWSClient(ctx context.Context, conf *WSConfig) (WSClient, error) {
	wsc, err := parseWSConfig(ctx, conf)
	if err != nil {
		return nil, err
	}
	return &wsWrap{c: rpcbackend.NewWSRPCClient(wsc)}, nil
}

type httpWrap struct {
	c rpcbackend.Backend
}

type errWrap struct {
	e *RPCError
}

func (w *errWrap) Error() string {
	return w.e.Error().Error()
}

func (w *errWrap) RPCError() *RPCError {
	return w.e
}

func wrapIfErr(rpcErr *RPCError) ErrorRPC {
	if rpcErr != nil {
		return &errWrap{rpcErr}
	}
	return nil
}

func (w *httpWrap) CallRPC(ctx context.Context, result interface{}, method string, params ...interface{}) ErrorRPC {
	rpcErr := w.c.CallRPC(ctx, result, method, params...)
	return wrapIfErr(rpcErr)
}

type wsWrap struct {
	c rpcbackend.WebSocketRPCClient
}

func (w *wsWrap) CallRPC(ctx context.Context, result interface{}, method string, params ...interface{}) ErrorRPC {
	rpcErr := w.c.CallRPC(ctx, result, method, params...)
	return wrapIfErr(rpcErr)
}

func (w *wsWrap) Subscribe(ctx context.Context, params ...interface{}) (Subscription, error) {
	s, rpcErr := w.c.Subscribe(ctx, params...)
	if rpcErr != nil {
		return nil, &errWrap{rpcErr}
	}
	return &sWrap{s: s}, nil
}

func (w *wsWrap) Subscriptions() []Subscription {
	subs := w.c.Subscriptions()
	wSubs := make([]Subscription, len(subs))
	for i, s := range subs {
		wSubs[i] = &sWrap{s: s}
	}
	return wSubs
}

func (w *wsWrap) UnsubscribeAll(ctx context.Context) ErrorRPC {
	rpcErr := w.c.UnsubscribeAll(ctx)
	return wrapIfErr(rpcErr)
}

func (w *wsWrap) Connect(ctx context.Context) error {
	return w.c.Connect(ctx)
}

func (w *wsWrap) Close() {
	w.c.Close()
}

type sWrap struct {
	s    rpcbackend.Subscription
	lock sync.Mutex
	ch   chan *RPCSubscriptionNotification
}

func (w *sWrap) LocalID() uuid.UUID {
	u := w.s.LocalID()
	return uuid.UUID(*u)
}

func (w *sWrap) Notifications() chan *RPCSubscriptionNotification {
	w.lock.Lock()
	defer w.lock.Unlock()
	if w.ch == nil {
		w.ch = make(chan *RPCSubscriptionNotification)
		go func() {
			for n := range w.s.Notifications() {
				w.ch <- &RPCSubscriptionNotification{
					CurrentSubID: n.CurrentSubID,
					Result:       n.Result.Bytes(),
				}
			}
		}()
	}
	return w.ch
}

func (w *sWrap) Unsubscribe(ctx context.Context) ErrorRPC {
	rpcErr := w.s.Unsubscribe(ctx)
	return wrapIfErr(rpcErr)
}
