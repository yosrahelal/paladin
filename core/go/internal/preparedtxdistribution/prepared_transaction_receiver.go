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

	"github.com/kaleido-io/paladin/core/internal/components"
	pb "github.com/kaleido-io/paladin/core/pkg/proto/engine"
	"github.com/kaleido-io/paladin/toolkit/pkg/log"
	"google.golang.org/protobuf/proto"
)

func (sd *preparedTransactionDistributer) sendPreparedTransactionAcknowledgement(ctx context.Context, domainName string, contractAddress string, preparedTxnId string, receivingParty string, distributingNode string, distributionID string) error {
	log.L(ctx).Debugf("preparedTransactionDistributer:sendPreparedTransactionAcknowledgement domainName=%s contractAddress=%s preparedTxnId=%s receivingParty=%s distributingNode=%s distributionID=%s", domainName, contractAddress, preparedTxnId, receivingParty, distributingNode, distributionID)
	preparedTransactionAcknowledgedMessage := &pb.PreparedTransactionAcknowledgedMessage{
		DomainName:      domainName,
		ContractAddress: contractAddress,
		PreparedTxnId:   preparedTxnId,
		Party:           receivingParty,
		DistributionId:  distributionID,
	}
	preparedTransactionAcknowledgedMessageBytes, err := proto.Marshal(preparedTransactionAcknowledgedMessage)
	if err != nil {
		log.L(ctx).Errorf("Error marshalling prepared transaction acknowledgment event: %s", err)
		return err
	}

	err = sd.transportManager.Send(ctx, &components.TransportMessage{
		MessageType: "PreparedTransactionAcknowledgedMessage",
		Payload:     preparedTransactionAcknowledgedMessageBytes,
		Node:        distributingNode,
		Component:   PREPARED_TRANSACTION_DISTRIBUTER_DESTINATION,
		ReplyTo:     sd.nodeID,
	})
	if err != nil {
		log.L(ctx).Errorf("Error sending prepared transaction produced event: %s", err)
		return err
	}

	return nil
}
