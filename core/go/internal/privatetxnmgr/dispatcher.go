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
	"sync"

	"github.com/google/uuid"
	"github.com/kaleido-io/paladin/core/internal/privatetxnmgr/ptmgrtypes"
	"github.com/kaleido-io/paladin/toolkit/pkg/log"
)

func NewDispatcher(contractAddress string, publisher ptmgrtypes.Publisher) ptmgrtypes.Dispatcher {
	return &dispatcher{
		publisher:       publisher,
		contractAddress: contractAddress,
		nextNonce:       0,
	}
}

type dispatcher struct {
	sequencedTransactions []uuid.UUID
	publisher             ptmgrtypes.Publisher
	contractAddress       string
	nextNonce             uint64
	nextNonceLock         sync.Mutex
}

func (p *dispatcher) NextNonce() uint64 {
	p.nextNonceLock.Lock()
	defer p.nextNonceLock.Unlock()
	nextNonce := p.nextNonce
	p.nextNonce++
	return nextNonce
}

// Dispatch implements ptmgrtypes.Dispatcher.
func (p *dispatcher) Dispatch(ctx context.Context, transactionIDs []uuid.UUID) error {
	//Placeholder for actual interface to hand over to dispatcher
	p.sequencedTransactions = append(p.sequencedTransactions, transactionIDs...)
	for _, transactionID := range transactionIDs {
		err := p.publisher.PublishStageEvent(ctx, &ptmgrtypes.StageEvent{
			Stage:           "gather_endorsements",
			ContractAddress: p.contractAddress,
			TxID:            transactionID.String(),
			Data:            &TransactionDispatched{},
		})
		if err != nil {
			//TODO think about how best to handle this error
			log.L(ctx).Errorf("Error publishing stage event: %s", err)
			return err
		}
		err = p.publisher.PublishEvent(ctx, &ptmgrtypes.TransactionDispatchedEvent{
			TransactionID:  transactionID.String(),
			Nonce:          p.NextNonce(),
			SigningAddress: "0x1234567890abcdef",
		})
		if err != nil {
			//TODO think about how best to handle this error
			log.L(ctx).Errorf("Error publishing event: %s", err)
			return err
		}
	}

	return nil
}
