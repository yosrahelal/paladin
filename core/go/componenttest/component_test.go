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
	_ "embed"
	"encoding/json"
	"testing"
	"time"

	"github.com/hyperledger/firefly-signer/pkg/abi"
	"github.com/hyperledger/firefly-signer/pkg/ethtypes"
	"github.com/kaleido-io/paladin/core/internal/componentmgr"
	"github.com/kaleido-io/paladin/core/pkg/blockindexer"
	"github.com/kaleido-io/paladin/core/pkg/ethclient"
	"github.com/kaleido-io/paladin/core/pkg/persistence"
	pb "github.com/kaleido-io/paladin/core/pkg/proto"
	"github.com/kaleido-io/paladin/toolkit/pkg/tktypes"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"gopkg.in/yaml.v3"
	"gorm.io/gorm"
)

//go:embed abis/SimpleStorage.json
var simpleStorageBuildJSON []byte // From "gradle copyTestSolidityBuild"

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

	getX1, err := simpleStorage.MustFunction("get").R(ctx).To(contractAddr).CallJSON()
	require.NoError(t, err)
	assert.JSONEq(t, `{"x":"11223344"}`, string(getX1))

	txHash2, err := simpleStorage.MustFunction("set").R(ctx).
		Signer("key1").To(contractAddr).Input(`{"_x":99887766}`).SignAndSend()
	require.NoError(t, err)
	_, err = indexer.WaitForTransactionSuccess(ctx, *txHash2, simpleStorageBuild.ABI)
	require.NoError(t, err)

	getX2, err := simpleStorage.MustFunction("get").R(ctx).To(contractAddr).CallJSON()
	require.NoError(t, err)
	assert.JSONEq(t, `{"x":"99887766"}`, string(getX2))

	// Expect our event listener to be queued up with two Changed events
	event1 := <-eventStreamEvents
	assert.JSONEq(t, `{"x":"11223344"}`, string(event1.Data))
	event2 := <-eventStreamEvents
	assert.JSONEq(t, `{"x":"99887766"}`, string(event2.Data))

}

func newClientForTesting(ctx context.Context, t *testing.T, socketAddress string) (pb.KataMessageServiceClient, func()) {
	// Create a gRPC client connection
	conn, err := grpc.NewClient("unix:"+socketAddress, grpc.WithTransportCredentials(insecure.NewCredentials()))
	require.NoError(t, err)
	// Create a new instance of the gRPC client
	client := pb.NewKataMessageServiceClient(conn)
	status, err := client.Status(ctx, &pb.StatusRequest{})

	delay := 0
	for !status.GetOk() {
		time.Sleep(time.Second)
		delay++
		status, err = client.Status(ctx, &pb.StatusRequest{})
		require.Less(t, delay, 5, "Server did not start in expected time")
	}
	require.NoError(t, err)
	assert.True(t, status.GetOk())
	return client, func() {
		conn.Close()
	}
}
