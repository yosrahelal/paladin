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

	"github.com/kaleido-io/paladin/config/pkg/pldconf"
	"github.com/kaleido-io/paladin/core/internal/components"
	"github.com/kaleido-io/paladin/core/internal/flushwriter"
	"github.com/kaleido-io/paladin/core/pkg/persistence"
	"github.com/kaleido-io/paladin/toolkit/pkg/log"
	"github.com/kaleido-io/paladin/toolkit/pkg/tktypes"
	"gorm.io/gorm"
)

type receivedPreparedTransactionWriterNoResult struct{}

type receivedPreparedTransactionWriteOperation struct {
	DomainName          string
	ContractAddress     tktypes.EthAddress
	PreparedTransaction *components.PrepareTransactionWithRefs
}

type receivedPreparedTransactionWriter struct {
	flushWriter flushwriter.Writer[*receivedPreparedTransactionWriteOperation, *receivedPreparedTransactionWriterNoResult]
	txMgr       components.TXManager
}

func NewReceivedPreparedTransactionWriter(ctx context.Context, txMgr components.TXManager, persistence persistence.Persistence, conf *pldconf.FlushWriterConfig) *receivedPreparedTransactionWriter {
	rsw := &receivedPreparedTransactionWriter{
		txMgr: txMgr,
	}
	rsw.flushWriter = flushwriter.NewWriter(ctx, rsw.runBatch, persistence, conf, &pldconf.DistributerWriterConfigDefaults)
	return rsw
}

func (wo *receivedPreparedTransactionWriteOperation) WriteKey() string {
	return wo.DomainName
}

func (rsw *receivedPreparedTransactionWriter) runBatch(ctx context.Context, dbTX *gorm.DB, values []*receivedPreparedTransactionWriteOperation) (func(error), []flushwriter.Result[*receivedPreparedTransactionWriterNoResult], error) {
	log.L(ctx).Debugf("receivedPreparedTransactionWriter:runBatch %d acknowledgements", len(values))

	if len(values) == 0 {
		return nil, nil, nil
	}

	preparedTransactions := make([]*components.PrepareTransactionWithRefs, len(values))
	for i, receivedPreparedTransactionWriteOperation := range values {

		preparedTransactions[i] = receivedPreparedTransactionWriteOperation.PreparedTransaction
	}
	if err := rsw.txMgr.WritePreparedTransactions(ctx, dbTX, preparedTransactions); err != nil {
		log.L(ctx).Errorf("Error persisting prepared transactions: %s", err)
		return nil, nil, err
	}
	// We don't actually provide any result, so just build an array of nil results
	return nil, make([]flushwriter.Result[*receivedPreparedTransactionWriterNoResult], len(values)), nil

}

func (rsw *receivedPreparedTransactionWriter) Start() {
	rsw.flushWriter.Start()
}

func (rsw *receivedPreparedTransactionWriter) Stop() {
	rsw.flushWriter.Shutdown()
}

func (rsw *receivedPreparedTransactionWriter) QueueAndWait(ctx context.Context, domainName string, contractAddress tktypes.EthAddress, receivedTransaction *components.PrepareTransactionWithRefs) error {
	log.L(ctx).Debugf("receivedPreparedTransactionWriter:QueueAndWait %s %s ", domainName, contractAddress)

	op := rsw.flushWriter.Queue(ctx, &receivedPreparedTransactionWriteOperation{
		DomainName:          domainName,
		ContractAddress:     contractAddress,
		PreparedTransaction: receivedTransaction,
	})
	_, err := op.WaitFlushed(ctx)
	if err != nil {
		log.L(ctx).Errorf("Error waiting for prepared transaction distribution write: %s", err)
	}
	return err
}
