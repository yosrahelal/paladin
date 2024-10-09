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
	"testing"

	"github.com/go-resty/resty/v2"
	"github.com/hyperledger/firefly-signer/pkg/rpcbackend"
	"github.com/kaleido-io/paladin/core/pkg/testbed"
	testZeto "github.com/kaleido-io/paladin/domains/integration-test/zeto"
	internalZeto "github.com/kaleido-io/paladin/domains/zeto/internal/zeto"
	"github.com/kaleido-io/paladin/domains/zeto/pkg/constants"
	"github.com/kaleido-io/paladin/domains/zeto/pkg/types"
	"github.com/kaleido-io/paladin/domains/zeto/pkg/zeto"
	"github.com/kaleido-io/paladin/toolkit/pkg/log"
	"github.com/kaleido-io/paladin/toolkit/pkg/plugintk"
	"github.com/kaleido-io/paladin/toolkit/pkg/query"
	"github.com/kaleido-io/paladin/toolkit/pkg/tktypes"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
)

var (
	controllerName = "controller"
	recipient1Name = "recipient1"
)

type zetoDomainTestSuite struct {
	suite.Suite
	hdWalletSeed      *testbed.UTInitFunction
	deployedContracts *testZeto.ZetoDomainContracts
	domainName        string
	domain            zeto.Zeto
	rpc               rpcbackend.Backend
	done              func()
}

func (s *zetoDomainTestSuite) SetupSuite() {
	s.hdWalletSeed = testbed.HDWalletSeedScopedToTest()
	domainContracts := testZeto.DeployZetoContracts(s.T(), s.hdWalletSeed, "./config-for-deploy.yaml", controllerName)
	s.deployedContracts = domainContracts
	ctx := context.Background()
	domainName := "zeto_" + tktypes.RandHex(8)
	log.L(ctx).Infof("Domain name = %s", domainName)
	config := testZeto.PrepareZetoConfig(s.T(), s.deployedContracts, "../zkp")
	zeto, zetoTestbed := newZetoDomain(s.T(), config)
	done, _, rpc := newTestbed(s.T(), s.hdWalletSeed, map[string]*testbed.TestbedDomain{
		domainName: zetoTestbed,
	})
	s.domainName = domainName
	s.domain = zeto
	s.rpc = rpc
	s.done = done
}

func (s *zetoDomainTestSuite) TearDownSuite() {
	s.done()
}

func (s *zetoDomainTestSuite) TestZeto_Anon() {
	s.testZetoFungible(s.T(), constants.TOKEN_ANON)
}

func (s *zetoDomainTestSuite) TestZeto_AnonEnc() {
	s.testZetoFungible(s.T(), constants.TOKEN_ANON_ENC)
}

func (s *zetoDomainTestSuite) TestZeto_AnonNullifier() {
	s.testZetoFungible(s.T(), constants.TOKEN_ANON_NULLIFIER)
}

func (s *zetoDomainTestSuite) testZetoFungible(t *testing.T, tokenName string) {
	ctx := context.Background()
	log.L(ctx).Infof("Deploying an instance of the %s token", tokenName)
	var zetoAddress tktypes.EthAddress
	rpcerr := s.rpc.CallRPC(ctx, &zetoAddress, "testbed_deploy",
		s.domainName, &types.InitializerParams{
			From:      controllerName,
			TokenName: tokenName,
		})
	if rpcerr != nil {
		require.NoError(t, rpcerr.Error())
	}
	log.L(ctx).Infof("Zeto instance deployed to %s", zetoAddress)

	log.L(ctx).Infof("Mint 10 from controller to controller")
	var invokeResult tktypes.PrivateContractTransaction
	rpcerr = s.rpc.CallRPC(ctx, &invokeResult, "testbed_invoke", &tktypes.PrivateContractInvoke{
		From:     controllerName,
		To:       tktypes.EthAddress(zetoAddress),
		Function: *types.ZetoABI.Functions()["mint"],
		Inputs: toJSON(t, &types.MintParams{
			To:     controllerName,
			Amount: tktypes.Int64ToInt256(10),
		}),
	}, true)
	if rpcerr != nil {
		require.NoError(t, rpcerr.Error())
	}

	coins := findAvailableCoins(t, ctx, s.rpc, s.domain, zetoAddress, nil)
	require.Len(t, coins, 1)
	assert.Equal(t, int64(10), coins[0].Data.Amount.Int().Int64())
	assert.Equal(t, controllerName, coins[0].Data.Owner)

	log.L(ctx).Infof("Mint 20 from controller to controller")
	rpcerr = s.rpc.CallRPC(ctx, &invokeResult, "testbed_invoke", &tktypes.PrivateContractInvoke{
		From:     controllerName,
		To:       tktypes.EthAddress(zetoAddress),
		Function: *types.ZetoABI.Functions()["mint"],
		Inputs: toJSON(t, &types.MintParams{
			To:     controllerName,
			Amount: tktypes.Int64ToInt256(20),
		}),
	}, true)
	if rpcerr != nil {
		require.NoError(t, rpcerr.Error())
	}

	coins = findAvailableCoins(t, ctx, s.rpc, s.domain, zetoAddress, nil)
	require.Len(t, coins, 2)
	assert.Equal(t, int64(10), coins[0].Data.Amount.Int().Int64())
	assert.Equal(t, controllerName, coins[0].Data.Owner)
	assert.Equal(t, int64(20), coins[1].Data.Amount.Int().Int64())
	assert.Equal(t, controllerName, coins[1].Data.Owner)

	log.L(ctx).Infof("Attempt mint from non-controller (should fail)")
	rpcerr = s.rpc.CallRPC(ctx, &invokeResult, "testbed_invoke", &tktypes.PrivateContractInvoke{
		From:     recipient1Name,
		To:       tktypes.EthAddress(zetoAddress),
		Function: *types.ZetoABI.Functions()["mint"],
		Inputs: toJSON(t, &types.MintParams{
			To:     recipient1Name,
			Amount: tktypes.Int64ToInt256(10),
		}),
	}, false)
	require.NotNil(t, rpcerr)
	assert.Regexp(t, "failed to send base ledger transaction: PD011513: Reverted: 0x118cdaa.*", rpcerr.Error())

	log.L(ctx).Infof("Transfer 25 from controller to recipient1")
	rpcerr = s.rpc.CallRPC(ctx, &invokeResult, "testbed_invoke", &tktypes.PrivateContractInvoke{
		From:     controllerName,
		To:       tktypes.EthAddress(zetoAddress),
		Function: *types.ZetoABI.Functions()["transfer"],
		Inputs: toJSON(t, &types.TransferParams{
			To:     recipient1Name,
			Amount: tktypes.Int64ToInt256(25),
		}),
	}, true)
	if rpcerr != nil {
		require.NoError(t, rpcerr.Error())
	}

	// check that we now only have one unspent coin, of value 5
	// coins = findAvailableCoins(t, ctx, s.rpc, s.domain, zetoAddress, nil)
	// one for the controller from the failed transaction
	// one for the controller from the successful transaction as change (value=5)
	// one for the recipient (value=25)
	// TODO: re-enable this test after the nullifiers handling is sorted
	// require.Len(t, coins, 3)
	// assert.Equal(t, int64(10), coins[0].Amount.Int64())
	// assert.Equal(t, recipient1Name, coins[0].Owner)
	// assert.Equal(t, int64(25), coins[1].Amount.Int64())
	// assert.Equal(t, recipient1Name, coins[1].Owner)
	// assert.Equal(t, int64(5), coins[2].Amount.Int64())
	// assert.Equal(t, controllerName, coins[2].Owner)
}

func TestZetoDomainTestSuite(t *testing.T) {
	suite.Run(t, new(zetoDomainTestSuite))
}

func findAvailableCoins(t *testing.T, ctx context.Context, rpc rpcbackend.Backend, zeto zeto.Zeto, address tktypes.EthAddress, jq *query.QueryJSON) []*types.ZetoCoinState {
	if jq == nil {
		jq = query.NewQueryBuilder().Limit(100).Query()
	}
	var zetoCoins []*types.ZetoCoinState
	rpcerr := rpc.CallRPC(ctx, &zetoCoins, "pstate_queryStates",
		zeto.Name(),
		address,
		zeto.CoinSchemaID(),
		jq,
		"available")
	if rpcerr != nil {
		require.NoError(t, rpcerr.Error())
	}
	return zetoCoins
}

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

func newZetoDomain(t *testing.T, config *types.DomainFactoryConfig) (zeto.Zeto, *testbed.TestbedDomain) {
	var domain internalZeto.Zeto
	return &domain, &testbed.TestbedDomain{
		Config: mapConfig(t, config),
		Plugin: plugintk.NewDomain(func(callbacks plugintk.DomainCallbacks) plugintk.DomainAPI {
			domain.Callbacks = callbacks
			return &domain
		}),
		RegistryAddress: tktypes.MustEthAddress(config.FactoryAddress),
		AllowSigning:    true,
	}
}

func newTestbed(t *testing.T, hdWalletSeed *testbed.UTInitFunction, domains map[string]*testbed.TestbedDomain) (context.CancelFunc, testbed.Testbed, rpcbackend.Backend) {
	tb := testbed.NewTestBed()
	url, done, err := tb.StartForTest("./testbed.config.yaml", domains, hdWalletSeed)
	assert.NoError(t, err)
	rpc := rpcbackend.NewRPCClient(resty.New().SetBaseURL(url))
	return done, tb, rpc
}
