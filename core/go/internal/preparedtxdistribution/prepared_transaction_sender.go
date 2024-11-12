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

package preparedtxdistribution

import (
	"context"
	"time"

	"github.com/kaleido-io/paladin/core/internal/components"
	pb "github.com/kaleido-io/paladin/core/pkg/proto/engine"
	"github.com/kaleido-io/paladin/toolkit/pkg/log"
	"github.com/kaleido-io/paladin/toolkit/pkg/tktypes"
	"google.golang.org/protobuf/proto"
)

func (sd *preparedTransactionDistributer) DistributePreparedTransactions(ctx context.Context, preparedTxnDistributions []*PreparedTxnDistribution) {
	log.L(ctx).Debugf("preparedTransactionDistributer:DistributePreparedTransactions %d prepared transaction distributions", len(preparedTxnDistributions))
	for _, preparedTxnDistribution := range preparedTxnDistributions {
		sd.inputChan <- preparedTxnDistribution
	}
}

func (sd *preparedTransactionDistributer) sendPreparedTransaction(ctx context.Context, preparedTxnDistribution *PreparedTxnDistribution) {
	log.L(ctx).Debugf("preparedTransactionDistributer:sendPreparedTransaction Domain: %s, ContractAddress: %s, PreparedTxnID: %s, IdentityLocator: %s, ID: %s",
		preparedTxnDistribution.Domain,
		preparedTxnDistribution.ContractAddress,
		preparedTxnDistribution.PreparedTxnID,
		preparedTxnDistribution.IdentityLocator,
		preparedTxnDistribution.ID)

	preparedTransactionMessage := &pb.PreparedTransactionMessage{
		DomainName:              preparedTxnDistribution.Domain,
		ContractAddress:         preparedTxnDistribution.ContractAddress,
		PreparedTxnId:           preparedTxnDistribution.PreparedTxnID,
		Party:                   preparedTxnDistribution.IdentityLocator,
		DistributionId:          preparedTxnDistribution.ID,
		PreparedTransactionJson: preparedTxnDistribution.PreparedTransactionJSON,
	}
	preparedTransactionMessageBytes, err := proto.Marshal(preparedTransactionMessage)
	if err != nil {
		log.L(ctx).Errorf("Error marshalling delegate transaction message: %s", err)
		return
	}

	targetNode, err := tktypes.PrivateIdentityLocator(preparedTxnDistribution.IdentityLocator).Node(ctx, false)
	if err != nil {
		log.L(ctx).Errorf("Error getting node for party %s", preparedTxnDistribution.IdentityLocator)
		return
	}

	err = sd.transportManager.Send(ctx, &components.TransportMessage{
		MessageType: "PreparedTransactionMessage",
		Payload:     preparedTransactionMessageBytes,
		Node:        targetNode,
		Component:   PREPARED_TRANSACTION_DISTRIBUTER_DESTINATION,
		ReplyTo:     sd.nodeID,
	})
	if err != nil {
		log.L(ctx).Errorf("Error sending prepared transaction produced event: %s", err)
		return
	}

	go func() {
		time.Sleep(RETRY_TIMEOUT)
		sd.retryChan <- preparedTxnDistribution.ID
	}()

}
