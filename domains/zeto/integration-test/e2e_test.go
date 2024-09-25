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

package integration_test

import (
	"context"
	_ "embed"
	"encoding/json"
	"math/big"
	"os"
	"testing"

	"github.com/go-resty/resty/v2"
	"github.com/hyperledger-labs/zeto/go-sdk/pkg/sparse-merkle-tree/core"
	"github.com/hyperledger-labs/zeto/go-sdk/pkg/sparse-merkle-tree/node"
	"github.com/hyperledger/firefly-signer/pkg/ethtypes"
	"github.com/hyperledger/firefly-signer/pkg/rpcbackend"
	"github.com/kaleido-io/paladin/core/pkg/persistence"
	"github.com/kaleido-io/paladin/core/pkg/testbed"
	internalZeto "github.com/kaleido-io/paladin/domains/zeto/internal/zeto"
	"github.com/kaleido-io/paladin/domains/zeto/internal/zeto/smt"
	"github.com/kaleido-io/paladin/domains/zeto/pkg/types"
	"github.com/kaleido-io/paladin/domains/zeto/pkg/zeto"
	"github.com/kaleido-io/paladin/toolkit/pkg/log"
	"github.com/kaleido-io/paladin/toolkit/pkg/plugintk"
	"github.com/kaleido-io/paladin/toolkit/pkg/tktypes"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
	"gopkg.in/yaml.v3"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

var (
	controllerName = "controller"
	recipient1Name = "recipient1"
)

//go:embed config-for-deploy.yaml
var testZetoConfigYaml []byte

func toJSON(t *testing.T, v any) []byte {
	result, err := json.Marshal(v)
	require.NoError(t, err)
	return result
}

func mapConfig(t *testing.T, config *types.DomainFactoryConfig) (m map[string]any) {
	configJSON, err := json.Marshal(&config)
	require.NoError(t, err)
	err = json.Unmarshal(configJSON, &m)
	require.NoError(t, err)
	return m
}

func prepareDomainConfig(t *testing.T, domainContracts *zetoDomainContracts) *types.DomainFactoryConfig {
	config := types.DomainFactoryConfig{
		DomainContracts: types.DomainConfigContracts{
			Factory: &types.DomainContract{
				ContractAddress: domainContracts.factoryAddress.String(),
			},
		},
	}

	var impls []*types.DomainContract
	for name, implContract := range domainContracts.cloneableContracts {
		abiJSON, err := json.Marshal(domainContracts.deployedContractAbis[name])
		require.NoError(t, err)
		contract := types.DomainContract{
			Name:            name,
			CircuitId:       implContract.circuitId,
			ContractAddress: domainContracts.deployedContracts[name].String(),
			Abi:             tktypes.RawJSON(abiJSON).String(),
		}
		impls = append(impls, &contract)
	}
	config.DomainContracts.Implementations = impls

	factoryAbiJSON, err := json.Marshal(domainContracts.factoryAbi)
	assert.NoError(t, err)
	config.DomainContracts.Factory.Abi = tktypes.RawJSON(factoryAbiJSON).String()
	config.FactoryAddress = domainContracts.factoryAddress.String()
	return &config
}

func deployZetoContracts(t *testing.T) *zetoDomainContracts {
	ctx := context.Background()
	log.L(ctx).Infof("Deploy Zeto Contracts")

	tb := testbed.NewTestBed()
	url, done, err := tb.StartForTest("./testbed.config.yaml", map[string]*testbed.TestbedDomain{})
	bi := tb.Components().BlockIndexer()
	ec := tb.Components().EthClientFactory().HTTPClient()
	assert.NoError(t, err)
	defer done()
	rpc := rpcbackend.NewRPCClient(resty.New().SetBaseURL(url))

	var config domainConfig
	err = yaml.Unmarshal(testZetoConfigYaml, &config)
	assert.NoError(t, err)

	deployedContracts, err := deployDomainContracts(ctx, rpc, controllerName, &config)
	assert.NoError(t, err)

	err = configureFactoryContract(ctx, ec, bi, controllerName, deployedContracts)
	assert.NoError(t, err)

	return deployedContracts
}

func newZetoDomain(t *testing.T, config *types.DomainFactoryConfig) (zeto.Zeto, *testbed.TestbedDomain) {
	var domain internalZeto.Zeto
	return &domain, &testbed.TestbedDomain{
		Config: mapConfig(t, config),
		Plugin: plugintk.NewDomain(func(callbacks plugintk.DomainCallbacks) plugintk.DomainAPI {
			domain.Callbacks = callbacks
			return &domain
		}),
		RegistryAddress: tktypes.MustEthAddress(config.FactoryAddress),
	}
}

func newTestbed(t *testing.T, domains map[string]*testbed.TestbedDomain) (context.CancelFunc, testbed.Testbed, rpcbackend.Backend) {
	tb := testbed.NewTestBed()
	url, done, err := tb.StartForTest("./testbed.config.yaml", domains)
	assert.NoError(t, err)
	rpc := rpcbackend.NewRPCClient(resty.New().SetBaseURL(url))
	return done, tb, rpc
}

type testSqlProvider struct {
	db *gorm.DB
}

func (s *testSqlProvider) DB() *gorm.DB {
	return s.db
}

func (s *testSqlProvider) Close() {}

func newTestPersistence(t *testing.T) (persistence.Persistence, *gorm.DB, *os.File) {
	dbfile, err := os.CreateTemp("", "gorm.db")
	assert.NoError(t, err)
	db, err := gorm.Open(sqlite.Open(dbfile.Name()), &gorm.Config{})
	assert.NoError(t, err)
	err = db.Table(core.TreeRootsTable).AutoMigrate(&core.SMTRoot{})
	assert.NoError(t, err)

	provider := &testSqlProvider{db: db}
	return provider, db, dbfile
}

type zetoDomainTestSuite struct {
	suite.Suite
	deployedContracts *zetoDomainContracts
	domainName        string
	domain            zeto.Zeto
	rpc               rpcbackend.Backend
	done              func()
	p                 persistence.Persistence
	dbfile            *os.File
	gormDB            *gorm.DB
}

func (s *zetoDomainTestSuite) SetupSuite() {
	domainContracts := deployZetoContracts(s.T())
	s.deployedContracts = domainContracts
	ctx := context.Background()
	domainName := "zeto_" + tktypes.RandHex(8)
	log.L(ctx).Infof("Domain name = %s", domainName)
	config := prepareDomainConfig(s.T(), s.deployedContracts)
	p, db, dbfile := newTestPersistence(s.T())
	zeto, zetoTestbed := newZetoDomain(s.T(), config)
	zeto.(*internalZeto.Zeto).SmtStorage = p
	done, _, rpc := newTestbed(s.T(), map[string]*testbed.TestbedDomain{
		domainName: zetoTestbed,
	})
	s.domainName = domainName
	s.domain = zeto
	s.rpc = rpc
	s.done = done
	s.p = p
	s.gormDB = db
	s.dbfile = dbfile
}

func (s *zetoDomainTestSuite) TearDownSuite() {
	s.done()
	os.Remove(s.dbfile.Name())
}

func (s *zetoDomainTestSuite) TestZeto_Anon() {
	s.testZetoFungible(s.T(), "Zeto_Anon")
}

func (s *zetoDomainTestSuite) TestZeto_AnonEnc() {
	s.testZetoFungible(s.T(), "Zeto_AnonEnc")
}

func (s *zetoDomainTestSuite) TestZeto_AnonNullifier() {
	s.testZetoFungible(s.T(), "Zeto_AnonNullifier")
}

func (s *zetoDomainTestSuite) testZetoFungible(t *testing.T, tokenName string) {
	ctx := context.Background()
	log.L(ctx).Infof("Deploying an instance of the %s token", tokenName)
	var zetoAddress ethtypes.Address0xHex
	rpcerr := s.rpc.CallRPC(ctx, &zetoAddress, "testbed_deploy",
		s.domainName, &types.InitializerParams{
			From:      controllerName,
			TokenName: tokenName,
		})
	if rpcerr != nil {
		require.NoError(t, rpcerr.Error())
	}
	log.L(ctx).Infof("Zeto instance deployed to %s", zetoAddress)

	// TODO: temporary until we have an interface to the state DB
	smtName := smt.MerkleTreeName(tokenName, ethtypes.MustNewAddress(zetoAddress.String()))
	err := s.gormDB.Table(core.NodesTablePrefix + smtName).AutoMigrate(&core.SMTNode{})
	assert.NoError(t, err)

	log.L(ctx).Infof("Mint 10 from controller to controller")
	var boolResult bool
	rpcerr = s.rpc.CallRPC(ctx, &boolResult, "testbed_invoke", &tktypes.PrivateContractInvoke{
		From:     controllerName,
		To:       tktypes.EthAddress(zetoAddress),
		Function: *types.ZetoABI.Functions()["mint"],
		Inputs: toJSON(t, &types.MintParams{
			To:     controllerName,
			Amount: tktypes.NewHexInteger(big.NewInt(10)),
		}),
	}, false)
	if rpcerr != nil {
		require.NoError(t, rpcerr.Error())
	}
	assert.True(t, boolResult)

	coins, err := s.domain.FindCoins(ctx, zetoAddress, "{}")
	require.NoError(t, err)
	require.Len(t, coins, 1)
	assert.Equal(t, int64(10), coins[0].Amount.Int64())
	assert.Equal(t, controllerName, coins[0].Owner)

	log.L(ctx).Infof("Mint 20 from controller to controller")
	rpcerr = s.rpc.CallRPC(ctx, &boolResult, "testbed_invoke", &tktypes.PrivateContractInvoke{
		From:     controllerName,
		To:       tktypes.EthAddress(zetoAddress),
		Function: *types.ZetoABI.Functions()["mint"],
		Inputs: toJSON(t, &types.MintParams{
			To:     controllerName,
			Amount: tktypes.NewHexInteger(big.NewInt(20)),
		}),
	}, false)
	if rpcerr != nil {
		require.NoError(t, rpcerr.Error())
	}
	assert.True(t, boolResult)

	coins, err = s.domain.FindCoins(ctx, zetoAddress, "{}")
	require.NoError(t, err)
	require.Len(t, coins, 2)
	assert.Equal(t, int64(10), coins[0].Amount.Int64())
	assert.Equal(t, controllerName, coins[0].Owner)
	assert.Equal(t, int64(20), coins[1].Amount.Int64())
	assert.Equal(t, controllerName, coins[1].Owner)

	// TODO: replace with handling in the event indexer
	tree, err := smt.New(s.p, smtName)
	require.NoError(t, err)
	for _, coin := range coins {
		idx, err := node.NewNodeIndexFromBigInt(coin.Hash.BigInt())
		assert.NoError(t, err)
		n := node.NewIndexOnly(idx)
		leaf, err := node.NewLeafNode(n)
		assert.NoError(t, err)
		err = tree.AddLeaf(leaf)
		assert.NoError(t, err)
	}

	log.L(ctx).Infof("Attempt mint from non-controller (should fail)")
	rpcerr = s.rpc.CallRPC(ctx, &boolResult, "testbed_invoke", &tktypes.PrivateContractInvoke{
		From:     recipient1Name,
		To:       tktypes.EthAddress(zetoAddress),
		Function: *types.ZetoABI.Functions()["mint"],
		Inputs: toJSON(t, &types.MintParams{
			To:     recipient1Name,
			Amount: tktypes.NewHexInteger(big.NewInt(10)),
		}),
	}, false)
	require.NotNil(t, rpcerr)
	assert.Regexp(t, "failed to send base ledger transaction: PD011513: Reverted: 0x118cdaa.*", rpcerr.Error())
	assert.True(t, boolResult)

	log.L(ctx).Infof("Transfer 25 from controller to recipient1")
	rpcerr = s.rpc.CallRPC(ctx, &boolResult, "testbed_invoke", &tktypes.PrivateContractInvoke{
		From:     controllerName,
		To:       tktypes.EthAddress(zetoAddress),
		Function: *types.ZetoABI.Functions()["transfer"],
		Inputs: toJSON(t, &types.TransferParams{
			To:     recipient1Name,
			Amount: tktypes.NewHexInteger(big.NewInt(25)),
		}),
	}, true)
	if rpcerr != nil {
		require.NoError(t, rpcerr.Error())
	}

	// check that we now only have one unspent coin, of value 5
	coins, err = s.domain.FindCoins(ctx, zetoAddress, "{}")
	require.NoError(t, err)
	// one for the controller from the failed transaction
	// one for the controller from the successful transaction as change (value=5)
	// one for the recipient (value=25)
	require.Len(t, coins, 3)
	assert.Equal(t, int64(10), coins[0].Amount.Int64())
	assert.Equal(t, recipient1Name, coins[0].Owner)
	assert.Equal(t, int64(25), coins[1].Amount.Int64())
	assert.Equal(t, recipient1Name, coins[1].Owner)
	assert.Equal(t, int64(5), coins[2].Amount.Int64())
	assert.Equal(t, controllerName, coins[2].Owner)
}

func TestZetoDomainTestSuite(t *testing.T) {
	suite.Run(t, new(zetoDomainTestSuite))
}
