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

package componenttest

import (
	_ "embed"

	"context"
	"net"
	"os"
	"strconv"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/kaleido-io/paladin/core/componenttest/domains"
	"github.com/kaleido-io/paladin/core/internal/componentmgr"
	"github.com/kaleido-io/paladin/core/internal/components"
	"github.com/kaleido-io/paladin/core/internal/domainmgr"
	"github.com/kaleido-io/paladin/core/internal/plugins"
	"github.com/kaleido-io/paladin/core/pkg/signer/api"
	"github.com/kaleido-io/paladin/toolkit/pkg/algorithms"
	"github.com/kaleido-io/paladin/toolkit/pkg/confutil"
	"github.com/kaleido-io/paladin/toolkit/pkg/log"
	"github.com/kaleido-io/paladin/toolkit/pkg/plugintk"
	"github.com/kaleido-io/paladin/toolkit/pkg/ptxapi"
	"github.com/kaleido-io/paladin/toolkit/pkg/rpcclient"
	"github.com/kaleido-io/paladin/toolkit/pkg/tktypes"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/tyler-smith/go-bip39"
)

//go:embed abis/SimpleStorage.json
var simpleStorageBuildJSON []byte // From "gradle copyTestSolidityBuild"

func transactionReceiptCondition(t *testing.T, ctx context.Context, txID uuid.UUID, rpcClient rpcclient.Client, isDeploy bool) func() bool {
	//for the given transaction ID, return a function that can be used in an assert.Eventually to check if the transaction has a receipt
	return func() bool {
		txFull := ptxapi.TransactionFull{}
		err := rpcClient.CallRPC(ctx, &txFull, "ptx_getTransaction", txID, true)
		require.NoError(t, err)
		return txFull.Receipt != nil && (!isDeploy || txFull.Receipt.ContractAddress != nil)
	}

}

func transactionLatencyThreshold(t *testing.T) time.Duration {
	// normally we would expect a transaction to be confirmed within a couple of seconds but
	// if we are in a debug session, we want to give it much longer
	threshold := 2 * time.Second

	deadline, ok := t.Deadline()
	if !ok {
		//there was no -timeout flag, default to a long time becuase this is most likely a debug session
		threshold = time.Hour
	} else {
		timeRemaining := time.Until(deadline)

		//Need to leave some time to ensure that polling assertions fail before the test itself timesout
		//otherwise we don't see diagnostic info for things like GoExit called by mocks etc
		timeRemaining = timeRemaining - 100*time.Millisecond

		if timeRemaining < threshold {
			threshold = timeRemaining - 100*time.Millisecond
		}
	}
	t.Logf("Using transaction latency threshold of %v", threshold)

	return threshold
}

type componentTestInstance struct {
	grpcTarget             string
	id                     uuid.UUID
	conf                   *componentmgr.Config
	ctx                    context.Context
	client                 rpcclient.Client
	resolveEthereumAddress func(identity string) string
}

func deplyDomainRegistry(t *testing.T) *tktypes.EthAddress {
	// We need an engine so that we can deploy the base ledger contract for the domain
	//Actually, we only need a bare bones engine that is capable of deploying the base ledger contracts
	// could make do with assembling some core components like key manager, eth client factory, block indexer, persistence and any other dependencies they pull in
	// but is easier to just create a throwaway component manager with no domains
	tmpConf := testConfig(t)
	// wouldn't need to do this if we just created the core coponents directly
	f, err := os.CreateTemp("", "component-test.*.sock")
	require.NoError(t, err)

	grpcTarget := f.Name()

	err = f.Close()
	require.NoError(t, err)

	err = os.Remove(grpcTarget)
	require.NoError(t, err)

	cmTmp := componentmgr.NewComponentManager(context.Background(), grpcTarget, uuid.New(), tmpConf, &componentTestEngine{})
	err = cmTmp.Init()
	require.NoError(t, err)
	err = cmTmp.StartComponents()
	require.NoError(t, err)
	domainRegistryAddress := domains.DeploySmartContract(t, cmTmp.BlockIndexer(), cmTmp.EthClientFactory())

	cmTmp.Stop()
	return domainRegistryAddress

}

func newInstanceForComponentTesting(t *testing.T, domainRegistryAddress *tktypes.EthAddress, instanceName string) *componentTestInstance {
	f, err := os.CreateTemp("", "component-test.*.sock")
	require.NoError(t, err)

	grpcTarget := f.Name()

	err = f.Close()
	require.NoError(t, err)

	err = os.Remove(grpcTarget)
	require.NoError(t, err)

	i := &componentTestInstance{
		grpcTarget: grpcTarget,
		id:         uuid.New(),
		conf:       testConfig(t),
	}
	i.ctx = log.WithLogField(context.Background(), "instance", instanceName)

	i.conf.Log.Level = confutil.P("trace")
	i.conf.DomainManagerConfig.Domains = make(map[string]*domainmgr.DomainConfig, 1)
	i.conf.DomainManagerConfig.Domains["domain1"] = &domainmgr.DomainConfig{
		Plugin: components.PluginConfig{
			Type:    components.LibraryTypeCShared.Enum(),
			Library: "loaded/via/unit/test/loader",
		},
		Config:          map[string]any{"some": "config"},
		RegistryAddress: domainRegistryAddress.String(),
	}
	entropy, _ := bip39.NewEntropy(256)
	mnemonic, _ := bip39.NewMnemonic(entropy)

	i.conf.Signer.KeyStore.Static.Keys = map[string]api.StaticKeyEntryConfig{
		"seed": {
			Encoding: "none",
			Inline:   mnemonic,
		},
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
		"domain1": domains.SimpleTokenDomain(t, i.ctx),
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

	client, err := rpcclient.NewHTTPClient(log.WithLogField(context.Background(), "client-for", instanceName), &rpcclient.HTTPConfig{URL: "http://localhost:" + strconv.Itoa(*i.conf.RPCServer.HTTP.Port)})
	require.NoError(t, err)
	i.client = client

	i.resolveEthereumAddress = func(identity string) string {
		_, address, err := cm.KeyManager().ResolveKey(i.ctx, identity, algorithms.ECDSA_SECP256K1_PLAINBYTES)
		require.NoError(t, err)
		return address
	}

	return i

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
