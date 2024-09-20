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

package privatetxnmgr

import (
	"context"

	"github.com/kaleido-io/paladin/core/internal/components"
	pb "github.com/kaleido-io/paladin/core/pkg/proto/sequence"
	"github.com/kaleido-io/paladin/toolkit/pkg/log"
	"google.golang.org/protobuf/proto"
)

func NewTransportWriter(nodeID string, transportManager components.TransportManager) *transportWriter {
	return &transportWriter{
		nodeID:           nodeID,
		transportManager: transportManager,
	}
}

type transportWriter struct {
	nodeID           string
	transportManager components.TransportManager
}

func (tw *transportWriter) SendDelegateTransactionMessage(ctx context.Context, transactionId string, delegateNodeId string) error {
	delegationMessage := &pb.DelegateTransaction{
		TransactionId:    transactionId,
		DelegatingNodeId: tw.nodeID,
		DelegateNodeId:   delegateNodeId,
	}
	delegationMessageBytes, err := proto.Marshal(delegationMessage)
	if err != nil {
		log.L(ctx).Errorf("Error marshalling delegate transaction message: %s", err)
		return err
	}

	if err = tw.transportManager.Send(ctx, &components.TransportMessage{
		MessageType: "DelegateTransaction",
		Payload:     delegationMessageBytes,
	}); err != nil {
		return err
	}
	return nil
}
