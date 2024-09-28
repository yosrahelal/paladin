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

/*
Test Kata component with no mocking of any internal units.
Starts the GRPC server and drives the internal functions via GRPC messages
*/
package componenttest

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/hyperledger/firefly-signer/pkg/abi"
	"github.com/hyperledger/firefly-signer/pkg/ethtypes"
	"github.com/kaleido-io/paladin/core/componenttest/domains"
	"github.com/kaleido-io/paladin/core/internal/componentmgr"
	"github.com/kaleido-io/paladin/core/pkg/blockindexer"
	"github.com/kaleido-io/paladin/core/pkg/ethclient"
	"github.com/kaleido-io/paladin/core/pkg/persistence"
	"github.com/kaleido-io/paladin/toolkit/pkg/ptxapi"
	"github.com/kaleido-io/paladin/toolkit/pkg/query"
	"github.com/kaleido-io/paladin/toolkit/pkg/tktypes"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
	"gorm.io/gorm"
)

func TestRunSimpleStorageEthTransaction(t *testing.T) {
	ctx := context.Background()
	logrus.SetLevel(logrus.DebugLevel)

	var testConfig componentmgr.Config

	err := yaml.Unmarshal([]byte(`
db:
  type: sqlite
  sqlite:
    uri:           ":memory:"
    autoMigrate:   true
    migrationsDir: ../db/migrations/sqlite
    debugQueries:  true
blockchain:
  http:
    url: http://localhost:8545
  ws:
    url: ws://localhost:8546
    initialConnectAttempts: 25
signer:
    keyDerivation:
      type: bip32
    keyStore:
      type: static
      static:
        keys:
          seed:
            encoding: none
            inline: polar mechanic crouch jungle field room dry sure machine brisk seed bulk student total ethics
`), &testConfig)
	require.NoError(t, err)

	p, err := persistence.NewPersistence(ctx, &testConfig.DB)
	require.NoError(t, err)
	defer p.Close()

	indexer, err := blockindexer.NewBlockIndexer(ctx, &blockindexer.Config{
		FromBlock: tktypes.RawJSON(`"latest"`), // don't want earlier events
	}, &testConfig.Blockchain.WS, p)
	require.NoError(t, err)

	type solBuild struct {
		ABI      abi.ABI                   `json:"abi"`
		Bytecode ethtypes.HexBytes0xPrefix `json:"bytecode"`
	}
	var simpleStorageBuild solBuild
	err = json.Unmarshal(simpleStorageBuildJSON, &simpleStorageBuild)
	require.NoError(t, err)

	eventStreamEvents := make(chan *blockindexer.EventWithData, 2 /* all the events we exepct */)
	err = indexer.Start(&blockindexer.InternalEventStream{
		Handler: func(ctx context.Context, tx *gorm.DB, batch *blockindexer.EventDeliveryBatch) (blockindexer.PostCommit, error) {
			// With SQLite we cannot hang in here with a DB TX - as there's only one per process.
			for _, e := range batch.Events {
				select {
				case eventStreamEvents <- e:
				default:
					assert.Fail(t, "more than expected number of events received")
				}
			}
			return nil, nil
		},
		Definition: &blockindexer.EventStream{
			Name: "unittest",
			ABI:  abi.ABI{simpleStorageBuild.ABI.Events()["Changed"]},
		},
	})
	require.NoError(t, err)
	defer indexer.Stop()

	keyMgr, err := ethclient.NewSimpleTestKeyManager(ctx, &testConfig.Signer)
	require.NoError(t, err)

	ecf, err := ethclient.NewEthClientFactory(ctx, keyMgr, &testConfig.Blockchain)
	require.NoError(t, err)
	err = ecf.Start()
	require.NoError(t, err)
	defer ecf.Stop()
	ethClient := ecf.HTTPClient()

	simpleStorage, err := ethClient.ABI(ctx, simpleStorageBuild.ABI)
	require.NoError(t, err)

	txHash1, err := simpleStorage.MustConstructor(tktypes.HexBytes(simpleStorageBuild.Bytecode)).R(ctx).
		Signer("key1").Input(`{"x":11223344}`).SignAndSend()
	require.NoError(t, err)
	deployTX, err := indexer.WaitForTransactionSuccess(ctx, *txHash1, simpleStorageBuild.ABI)
	require.NoError(t, err)
	contractAddr := deployTX.ContractAddress.Address0xHex()

	getX1, err := simpleStorage.MustFunction("get").R(ctx).To(contractAddr).CallResult()
	require.NoError(t, err)
	assert.JSONEq(t, `{"x":"11223344"}`, getX1.JSON())

	txHash2, err := simpleStorage.MustFunction("set").R(ctx).
		Signer("key1").To(contractAddr).Input(`{"_x":99887766}`).SignAndSend()
	require.NoError(t, err)
	_, err = indexer.WaitForTransactionSuccess(ctx, *txHash2, simpleStorageBuild.ABI)
	require.NoError(t, err)

	getX2, err := simpleStorage.MustFunction("get").R(ctx).To(contractAddr).CallResult()
	require.NoError(t, err)
	assert.JSONEq(t, `{"x":"99887766"}`, getX2.JSON())

	// Expect our event listener to be queued up with two Changed events
	event1 := <-eventStreamEvents
	assert.JSONEq(t, `{"x":"11223344"}`, string(event1.Data))
	event2 := <-eventStreamEvents
	assert.JSONEq(t, `{"x":"99887766"}`, string(event2.Data))

}

func TestSimplePrivateContract(t *testing.T) {
	// Coarse grained black box test of the core component manager
	// no mocking although it does use a simple domain implementation that exists solely for testing
	// and is loaded directly through go function calls via the unit test plugin loader
	// (as opposed to compiling as a sepraate shared library)
	// Even though the domain is a fake, the test does deploy a real contract to the blockchain and the domain
	// manager does communicate with it via the grpc inteface.
	// The bootstrap code that is the entry point to the java side is not tested here, we bootstrap the component manager by hand

	ctx := context.Background()
	rpcClient := newInstanceForComponentTesting(t, deplyDomainRegistry(t), "test-instance")

	// Check there are no transactions before we start
	var txns []*ptxapi.TransactionFull
	err := rpcClient.CallRPC(ctx, &txns, "ptx_queryTransactions", query.NewQueryBuilder().Limit(1).Query(), true)
	require.NoError(t, err)
	assert.Len(t, txns, 0)

	var dplyTxID uuid.UUID
	err = rpcClient.CallRPC(ctx, &dplyTxID, "ptx_sendTransaction", &ptxapi.TransactionInput{
		ABI: *domains.SimpleTokenConstructorABI(),
		//Bytecode:  ...,
		Transaction: ptxapi.Transaction{
			IdempotencyKey: "deploy1",
			Type:           ptxapi.TransactionTypePrivate.Enum(),
			Domain:         "domain1",
			From:           "wallets.org1.aaaaaa",
			Data: tktypes.RawJSON(`{
					"notary": "domain1.contract1.notary",
					"name": "FakeToken1",
					"symbol": "FT1"
				}`),
		},
	})
	require.NoError(t, err)
	assert.Eventually(t,
		transactionReceiptCondition(t, ctx, dplyTxID, rpcClient, true),
		timeTillDeadline(t),
		1*time.Second,
		"Deploy transaction did not receive a receipt",
	)

	var dplyTxFull ptxapi.TransactionFull
	err = rpcClient.CallRPC(ctx, &dplyTxFull, "ptx_getTransaction", dplyTxID, true)
	require.NoError(t, err)
	require.True(t, dplyTxFull.Receipt.Success)
	require.NotNil(t, dplyTxFull.Receipt.ContractAddress)
	contractAddress := dplyTxFull.Receipt.ContractAddress

	var receiptData ptxapi.TransactionReceiptData
	err = rpcClient.CallRPC(ctx, &receiptData, "ptx_getTransactionReceipt", dplyTxID)
	assert.NoError(t, err)
	assert.True(t, receiptData.Success)
	assert.Equal(t, contractAddress, receiptData.ContractAddress)

	// Start a private transaction
	var tx1ID uuid.UUID
	err = rpcClient.CallRPC(ctx, &tx1ID, "ptx_sendTransaction", &ptxapi.TransactionInput{
		ABI: *domains.SimpleTokenTransferABI(),
		Transaction: ptxapi.Transaction{
			To:             contractAddress,
			Domain:         "domain1", //TODO comments say that this is inferred from `to` for invoke
			IdempotencyKey: "tx1",
			Type:           ptxapi.TransactionTypePrivate.Enum(),
			From:           "wallets.org1.aaaaaa",
			Data: tktypes.RawJSON(`{
				"from": "",
				"to": "wallets.org1.aaaaaa",
				"amount": "123000000000000000000"
			}`),
		},
	})

	require.NoError(t, err)
	assert.NotEqual(t, uuid.UUID{}, tx1ID)
	assert.Eventually(t,
		transactionReceiptCondition(t, ctx, tx1ID, rpcClient, false),
		timeTillDeadline(t),
		1*time.Second,
		"Transaction did not receive a receipt",
	)

	err = rpcClient.CallRPC(ctx, &txns, "ptx_queryTransactions", query.NewQueryBuilder().Limit(1).Query(), true)
	require.NoError(t, err)
	assert.Len(t, txns, 2)

	txFull := ptxapi.TransactionFull{}
	err = rpcClient.CallRPC(ctx, &txFull, "ptx_getTransaction", tx1ID, true)
	require.NoError(t, err)

	require.NotNil(t, txFull.Receipt)
	assert.True(t, txFull.Receipt.Success)

}
