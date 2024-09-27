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
	"net"
	"os"
	"strconv"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/hyperledger/firefly-signer/pkg/abi"
	"github.com/hyperledger/firefly-signer/pkg/ethtypes"
	"github.com/kaleido-io/paladin/core/componenttest/domains"
	"github.com/kaleido-io/paladin/core/internal/componentmgr"
	"github.com/kaleido-io/paladin/core/internal/components"
	"github.com/kaleido-io/paladin/core/internal/domainmgr"
	"github.com/kaleido-io/paladin/core/internal/plugins"
	"github.com/kaleido-io/paladin/core/pkg/blockindexer"
	"github.com/kaleido-io/paladin/core/pkg/ethclient"
	"github.com/kaleido-io/paladin/core/pkg/persistence"
	"github.com/kaleido-io/paladin/toolkit/pkg/confutil"
	"github.com/kaleido-io/paladin/toolkit/pkg/log"
	"github.com/kaleido-io/paladin/toolkit/pkg/plugintk"
	"github.com/kaleido-io/paladin/toolkit/pkg/ptxapi"
	"github.com/kaleido-io/paladin/toolkit/pkg/query"
	"github.com/kaleido-io/paladin/toolkit/pkg/rpcclient"
	"github.com/kaleido-io/paladin/toolkit/pkg/tktypes"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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

func transactionReceiptCondition(t *testing.T, ctx context.Context, txID uuid.UUID, rpcClient rpcclient.Client, isDeploy bool) func() bool {
	//for the given transaction ID, return a function that can be used in an assert.Eventually to check if the transaction has a receipt
	return func() bool {
		txFull := ptxapi.TransactionFull{}
		err := rpcClient.CallRPC(ctx, &txFull, "ptx_getTransaction", txID, true)
		require.NoError(t, err)
		return txFull.Receipt != nil && (!isDeploy || txFull.Receipt.ContractAddress != nil)
	}

}

func TestCoreGoComponent(t *testing.T) {
	// Coarse grained black box test of the core component manager
	// no mocking although it does use a simple domain implementation that exists solely for testing
	// and is loaded directly through go function calls via the unit test plugin loader
	// (as opposed to compiling as a sepraate shared library)
	// Even though the domain is a fake, the test does deploy a real contract to the blockchain and the domain
	// manager does communicate with it via the grpc inteface.
	// The bootstrap code that is the entry point to the java side is not tested here, we bootstrap the component manager by hand

	ctx := context.Background()
	instance, _ := newInstanceForComponentTesting(t)

	// send JSON RPC message to check the status of the server
	rpcClient, err := rpcclient.NewHTTPClient(ctx, &rpcclient.HTTPConfig{URL: "http://localhost:" + strconv.Itoa(*instance.conf.RPCServer.HTTP.Port)})
	require.NoError(t, err)

	// Check there are no transactions before we start
	var txns []*ptxapi.TransactionFull
	err = rpcClient.CallRPC(ctx, &txns, "ptx_queryTransactions", query.NewQueryBuilder().Limit(1).Query(), true)
	require.NoError(t, err)
	assert.Len(t, txns, 0)

	var dplyTxID uuid.UUID
	err = rpcClient.CallRPC(ctx, &dplyTxID, "ptx_sendTransaction", &ptxapi.TransactionInput{
		ABI: *domains.FakeCoinConstructorABI(),
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
		ABI: *domains.FakeCoinTransferABI(),
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

func timeTillDeadline(t *testing.T) time.Duration {
	deadline, ok := t.Deadline()
	if !ok {
		//there was no -timeout flag, default to a long time becuase this is most likely a debug session
		deadline = time.Now().Add(10 * time.Hour)
	}
	timeRemaining := time.Until(deadline)
	//Need to leave some time to ensure that polling assertions fail before the test itself timesout
	//otherwise we don't see diagnostic info for things like GoExit called by mocks etc
	if timeRemaining < 100*time.Millisecond {
		return 0
	}
	return timeRemaining - 100*time.Millisecond
}

type componentTestInstance struct {
	grpcTarget string
	engineName string
	id         uuid.UUID
	conf       *componentmgr.Config
	ctx        context.Context
	cancelCtx  context.CancelFunc
}

func newInstanceForComponentTesting(t *testing.T) (*componentTestInstance, componentmgr.ComponentManager) {
	f, err := os.CreateTemp("", "component-test.*.sock")
	require.NoError(t, err)

	grpcTarget := f.Name()

	err = f.Close()
	require.NoError(t, err)

	err = os.Remove(grpcTarget)
	require.NoError(t, err)

	//Little bit of a chicken and egg situation here.
	// We need an engine so that we can deploy the base ledger contract for the domain
	// and then we need the address of that contract for the config file we use to iniitialize the engine
	//Actually in the first instance, we only need a bare bones engine that is capable of deploying the base ledger contracts
	// could make do with assembling some core components like key manager, eth client factory, block indexer, persistence and any other dependencies they pull in
	// but is easier to just create a throwaway component manager with no domains

	i := &componentTestInstance{
		grpcTarget: grpcTarget,
		id:         uuid.New(),
		conf:       testConfig(t),
		engineName: "",
	}
	i.ctx, i.cancelCtx = context.WithCancel(log.WithLogField(context.Background(), "pid", strconv.Itoa(os.Getpid())))

	tmpConf := testConfig(t)
	cmTmp := componentmgr.NewComponentManager(i.ctx, i.grpcTarget, i.id, tmpConf, &componentTestEngine{})
	err = cmTmp.Init()
	require.NoError(t, err)
	err = cmTmp.StartComponents()
	require.NoError(t, err)
	domainRegistryAddress := domains.DeploySmartContract(t, cmTmp.BlockIndexer(), cmTmp.EthClientFactory())

	cmTmp.Stop()

	i.conf.DomainManagerConfig.Domains = make(map[string]*domainmgr.DomainConfig, 1)
	i.conf.DomainManagerConfig.Domains["domain1"] = &domainmgr.DomainConfig{
		Plugin: components.PluginConfig{
			Type:    components.LibraryTypeCShared.Enum(),
			Library: "loaded/via/unit/test/loader",
		},
		Config:          map[string]any{"some": "config"},
		RegistryAddress: domainRegistryAddress.String(),
	}

	var pl plugins.UnitTestPluginLoader

	cm := componentmgr.NewComponentManager(i.ctx, i.grpcTarget, i.id, i.conf, &componentTestEngine{})
	// Start it up
	err = cm.Init()
	require.NoError(t, err)

	err = cm.StartComponents()
	require.NoError(t, err)

	err = cm.StartManagers()
	require.NoError(t, err)

	loaderMap := map[string]plugintk.Plugin{
		"domain1": domains.FakeCoinDomain(t, i.ctx),
	}
	pc := cm.PluginManager()
	pl, err = plugins.NewUnitTestPluginLoader(pc.GRPCTargetURL(), pc.LoaderID().String(), loaderMap)
	require.NoError(t, err)
	go pl.Run()

	err = cm.CompleteStart()
	require.NoError(t, err)

	t.Cleanup(func() {
		pl.Stop()
		cm.Stop()
	})

	return i, cm

}

// TODO should not need an engine at all. It is only in the component manager interface to enable the testbed to integrate with domain manager etc
// need to make this optional in the component manager interface or re-write the testbed to integrate with components
// in a different way
type componentTestEngine struct {
}

// EngineName implements components.Engine.
func (c *componentTestEngine) EngineName() string {
	return "component-test-engine"
}

// Init implements components.Engine.
func (c *componentTestEngine) Init(components.PreInitComponentsAndManagers) (*components.ManagerInitResult, error) {
	return &components.ManagerInitResult{}, nil
}

// ReceiveTransportMessage implements components.Engine.
func (c *componentTestEngine) ReceiveTransportMessage(context.Context, *components.TransportMessage) {
	panic("unimplemented")
}

// Start implements components.Engine.
func (c *componentTestEngine) Start() error {
	return nil
}

// Stop implements components.Engine.
func (c *componentTestEngine) Stop() {

}

func testConfig(t *testing.T) *componentmgr.Config {
	ctx := context.Background()
	log.SetLevel("debug")

	var conf *componentmgr.Config
	err := componentmgr.ReadAndParseYAMLFile(ctx, "../test/config/sqlite.memory.config.yaml", &conf)
	assert.NoError(t, err)

	// For running in this unit test the dirs are different to the sample config
	conf.DB.SQLite.MigrationsDir = "../db/migrations/sqlite"
	conf.DB.Postgres.MigrationsDir = "../db/migrations/postgres"

	port, err := getFreePort()
	require.NoError(t, err, "Error finding a free port")
	conf.RPCServer.HTTP.Port = &port
	conf.RPCServer.HTTP.Address = confutil.P("127.0.0.1")

	return conf

}

// getFreePort finds an available TCP port and returns it.
func getFreePort() (int, error) {
	listener, err := net.Listen("tcp", ":0")
	if err != nil {
		return 0, err
	}
	defer listener.Close()

	port := listener.Addr().(*net.TCPAddr).Port
	return port, nil
}
