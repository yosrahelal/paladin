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

package integrationtest

import (
	"context"
	_ "embed"
	"testing"

	"github.com/hyperledger/firefly-common/pkg/log"
	"github.com/hyperledger/firefly-signer/pkg/ethtypes"
	"github.com/kaleido-io/paladin/core/pkg/testbed"
	"github.com/kaleido-io/paladin/domains/integration-test/helpers"
	"github.com/kaleido-io/paladin/domains/noto/pkg/types"
	"github.com/kaleido-io/paladin/toolkit/pkg/algorithms"
	"github.com/kaleido-io/paladin/toolkit/pkg/domain"
	"github.com/kaleido-io/paladin/toolkit/pkg/tktypes"
	"github.com/stretchr/testify/require"
)

//go:embed abis/NotoFactory.json
var notoFactoryJSON []byte // From "gradle copySolidity"

//go:embed abis/AtomFactory.json
var atomFactoryJSON []byte // From "gradle copySolidity"

//go:embed abis/Atom.json
var atomJSON []byte // From "gradle copySolidity"

//go:embed abis/Swap.json
var swapJSON []byte // From "gradle copySolidity"

var (
	notary = "notary"
	alice  = "alice"
	bob    = "bob"
)

func TestPvP(t *testing.T) {
	ctx := context.Background()
	log.L(ctx).Infof("TestPvP")
	domainName := "noto_" + tktypes.RandHex(8)
	log.L(ctx).Infof("Domain name = %s", domainName)

	log.L(ctx).Infof("Deploying factories")
	contractSource := map[string][]byte{
		"noto": notoFactoryJSON,
		"atom": atomFactoryJSON,
	}
	contracts := deployContracts(ctx, t, notary, contractSource)
	for name, address := range contracts {
		log.L(ctx).Infof("%s deployed to %s", name, address)
	}

	_, notoTestbed := newNotoDomain(t, &types.DomainConfig{
		FactoryAddress: contracts["noto"],
	})
	done, tb, rpc := newTestbed(t, map[string]*testbed.TestbedDomain{
		domainName: notoTestbed,
	})
	defer done()

	_, aliceKey, err := tb.Components().KeyManager().ResolveKey(ctx, alice, algorithms.ECDSA_SECP256K1_PLAINBYTES)
	require.NoError(t, err)
	_, bobKey, err := tb.Components().KeyManager().ResolveKey(ctx, bob, algorithms.ECDSA_SECP256K1_PLAINBYTES)
	require.NoError(t, err)

	atomFactory := helpers.InitAtom(t, tb, rpc, contracts["atom"], domain.LoadBuild(atomFactoryJSON).ABI, domain.LoadBuild(atomJSON).ABI)

	log.L(ctx).Infof("Deploying 2 instances of Noto")
	notoGold := helpers.DeployNoto(ctx, t, rpc, domainName, notary)
	notoSilver := helpers.DeployNoto(ctx, t, rpc, domainName, notary)
	log.L(ctx).Infof("Noto gold deployed to %s", notoGold.Address)
	log.L(ctx).Infof("Noto silver deployed to %s", notoSilver.Address)

	log.L(ctx).Infof("Mint 10 gold to Alice")
	notoGold.Mint(ctx, alice, 10).SignAndSend(notary).Wait()
	log.L(ctx).Infof("Mint 100 silver to Bob")
	notoSilver.Mint(ctx, bob, 100).SignAndSend(notary).Wait()

	// TODO: this should be a Pente private contract, instead of a base ledger contract
	log.L(ctx).Infof("Propose a trade of 1 gold for 10 silver")
	swap := helpers.DeploySwap(ctx, t, tb, domain.LoadBuild(swapJSON), alice, &helpers.TradeRequestInput{
		Holder1:       aliceKey,
		TokenAddress1: notoGold.Address,
		TokenValue1:   ethtypes.NewHexInteger64(1),

		Holder2:       bobKey,
		TokenAddress2: notoSilver.Address,
		TokenValue2:   ethtypes.NewHexInteger64(10),
	})

	log.L(ctx).Infof("Prepare the transfers")
	transferGold := notoGold.ApprovedTransfer(ctx, bob, 1).Prepare(alice)
	transferSilver := notoSilver.ApprovedTransfer(ctx, alice, 10).Prepare(bob)

	// TODO: this should actually be a Pente state transition
	log.L(ctx).Infof("Prepare the trade execute")
	encodedExecute := swap.Execute(ctx).Prepare()

	log.L(ctx).Infof("Record the prepared transfers")
	swap.Prepare(ctx, &helpers.StateData{
		Inputs:  transferGold.InputStates,
		Outputs: transferGold.OutputStates,
	}).SignAndSend(alice).Wait()
	swap.Prepare(ctx, &helpers.StateData{
		Inputs:  transferSilver.InputStates,
		Outputs: transferSilver.OutputStates,
	}).SignAndSend(bob).Wait()

	log.L(ctx).Infof("Create Atom instance")
	transferAtom := atomFactory.Create(ctx, alice, []*helpers.AtomOperation{
		{
			ContractAddress: notoGold.Address,
			CallData:        transferGold.EncodedCall,
		},
		{
			ContractAddress: notoSilver.Address,
			CallData:        transferSilver.EncodedCall,
		},
		{
			ContractAddress: swap.Address,
			CallData:        encodedExecute,
		},
	})

	// TODO: all parties should verify the Atom against the original proposed trade
	// If any party found a discrepancy at this point, they could cancel the swap (last chance to back out)

	log.L(ctx).Infof("Approve both Noto transactions")
	notoGold.Approve(ctx, transferAtom.Address, transferGold.EncodedCall).SignAndSend(alice).Wait()
	notoSilver.Approve(ctx, transferAtom.Address, transferSilver.EncodedCall).SignAndSend(bob).Wait()

	log.L(ctx).Infof("Execute the atomic operation")
	transferAtom.Execute(ctx).SignAndSend(alice).Wait()
}
