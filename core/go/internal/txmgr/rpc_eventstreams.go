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
	"sync"

	"github.com/hyperledger/firefly-common/pkg/fftypes"
	"github.com/hyperledger/firefly-common/pkg/i18n"
	"github.com/kaleido-io/paladin/core/internal/components"
	"github.com/kaleido-io/paladin/core/internal/msgs"
	"github.com/kaleido-io/paladin/toolkit/pkg/log"
	"github.com/kaleido-io/paladin/toolkit/pkg/pldapi"
	"github.com/kaleido-io/paladin/toolkit/pkg/rpcclient"
	"github.com/kaleido-io/paladin/toolkit/pkg/rpcserver"
	"github.com/kaleido-io/paladin/toolkit/pkg/tktypes"
)

type rpcEventStreams struct {
	tm          *txManager
	subLock     sync.Mutex
	receiptSubs map[string]*receiptListenerSubscription
}

func newRPCEventStreams(tm *txManager) *rpcEventStreams {
	es := &rpcEventStreams{
		tm:          tm,
		receiptSubs: make(map[string]*receiptListenerSubscription),
	}
	return es
}

func (es *rpcEventStreams) RPCAsyncHandler() rpcserver.RPCAsyncHandler {
	return es
}

func (es *rpcEventStreams) StartMethod() string {
	return "ptx_subscribe"
}

func (es *rpcEventStreams) LifecycleMethods() []string {
	return []string{"ptx_unsubscribe", "ptx_ack", "ptx_nack"}
}

type rpcAckNack struct {
	ack bool
}

type receiptListenerSubscription struct {
	es        *rpcEventStreams
	rrc       components.ReceiptReceiverCloser
	ctrl      rpcserver.RPCAsyncControl
	acksNacks chan *rpcAckNack
}

func (es *rpcEventStreams) HandleStart(ctx context.Context, req *rpcclient.RPCRequest, ctrl rpcserver.RPCAsyncControl) (rpcserver.RPCAsyncInstance, *rpcclient.RPCResponse) {
	es.subLock.Lock()
	defer es.subLock.Unlock()

	var eventType tktypes.Enum[pldapi.PTXEventType]
	if len(req.Params) >= 1 {
		eventType = tktypes.Enum[pldapi.PTXEventType](req.Params[0].AsString())
	}
	if _, err := eventType.Validate(); err != nil {
		return nil, rpcclient.NewRPCErrorResponse(err, req.ID, rpcclient.RPCCodeInvalidRequest)
	}

	// Only one type right now
	if len(req.Params) < 2 {
		return nil, rpcclient.NewRPCErrorResponse(i18n.NewError(ctx, msgs.MsgTxMgrListenerNameRequired), req.ID, rpcclient.RPCCodeInvalidRequest)
	}
	sub := &receiptListenerSubscription{
		es:        es,
		ctrl:      ctrl,
		acksNacks: make(chan *rpcAckNack, 1),
	}
	es.receiptSubs[ctrl.ID()] = sub
	var err error
	sub.rrc, err = es.tm.AddReceiptReceiver(ctx, req.Params[1].AsString(), sub)
	if err != nil {
		return nil, rpcclient.NewRPCErrorResponse(err, req.ID, rpcclient.RPCCodeInvalidRequest)
	}

	return sub, &rpcclient.RPCResponse{
		JSONRpc: "2.0",
		ID:      req.ID,
		Result:  fftypes.JSONAnyPtrBytes(tktypes.JSONString(ctrl.ID())),
	}
}

func (es *rpcEventStreams) popSubForUnsubscribe(subID string) *receiptListenerSubscription {
	es.subLock.Lock()
	defer es.subLock.Unlock()

	sub := es.receiptSubs[subID]
	if sub != nil {
		delete(es.receiptSubs, subID)
		return sub
	}

	return nil
}

func (es *rpcEventStreams) HandleLifecycle(ctx context.Context, req *rpcclient.RPCRequest) *rpcclient.RPCResponse {

	if len(req.Params) < 1 {
		return rpcclient.NewRPCErrorResponse(i18n.NewError(ctx, msgs.MsgTxMgrSubIDRequired), req.ID, rpcclient.RPCCodeInvalidRequest)
	}
	subID := req.Params[0].AsString()
	sub := es.popSubForUnsubscribe(subID)
	switch req.Method {
	case "ptx_ack", "ptx_nack":
		if sub != nil {
			select {
			case sub.acksNacks <- &rpcAckNack{ack: req.Method == "ptx_ack"}:
				log.L(ctx).Infof("ack/nack received for subID %s ack=%t", subID, req.Method == "ptx_ack")
			default:
			}
		}
		return nil // no reply to acks/nacks - we just send more messages
	case "ptx_unsubscribe":
		if sub != nil {
			sub.ctrl.Closed()
		}
		return &rpcclient.RPCResponse{
			JSONRpc: "2.0",
			ID:      req.ID,
			Result:  fftypes.JSONAnyPtrBytes(tktypes.JSONString(sub != nil)),
		}
	default:
		return rpcclient.NewRPCErrorResponse(i18n.NewError(ctx, msgs.MsgTxMgrLifecycleMethodUnknown, req.Method), req.ID, rpcclient.RPCCodeInvalidRequest)
	}

}

func (sub *receiptListenerSubscription) DeliverReceiptBatch(ctx context.Context, batchID uint64, receipts []*pldapi.TransactionReceiptFull) error {
	log.L(ctx).Infof("Delivering receipt batch %d to subscription %s over JSON/RPC", batchID, sub.ctrl.ID())
	sub.ctrl.Send("ptx_receiptBatch", receipts)
	ackNack, ok := <-sub.acksNacks
	if !ok {
		return i18n.NewError(ctx, msgs.MsgTxMgrJSONRPCSubscriptionClosed, sub.ctrl.ID())
	}
	if !ackNack.ack {
		log.L(ctx).Warnf("Batch %d negatively acknowledged by subscription %s over JSON/RPC", batchID, sub.ctrl.ID())
		return i18n.NewError(ctx, msgs.MsgTxMgrJSONRPCSubscriptionNack, sub.ctrl.ID())
	}
	log.L(ctx).Infof("Batch %d acknowledged by subscription %s over JSON/RPC", batchID, sub.ctrl.ID())
	return nil
}

func (sub *receiptListenerSubscription) ConnectionClosed() {
	sub.es.cleanupSub(sub)
}

func (es *rpcEventStreams) cleanupSub(sub *receiptListenerSubscription) {
	es.subLock.Lock()
	defer es.subLock.Unlock()

	close(sub.acksNacks) // cancels any DeliverReceiptBatch() in-flight
	sub.rrc.Close()
	delete(es.receiptSubs, sub.ctrl.ID())
}
