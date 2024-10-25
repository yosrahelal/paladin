// Copyright © 2024 Kaleido, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with
// the License. You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on
// an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the
// specific language governing permissions and limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0
//

//go:build componenttestlong
// +build componenttestlong

/*
Test core go component with no mocking of any internal units.
The tests in this file take longer to run because they are testing longevity under load so this file has a componenttestlong build tag to avoid running by default
*/
package componenttest

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/kaleido-io/paladin/core/componenttest/domains"
	"github.com/kaleido-io/paladin/toolkit/pkg/pldapi"
	"github.com/kaleido-io/paladin/toolkit/pkg/tktypes"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPrivateTransactions100PercentEndorsementBetter(t *testing.T) {
	// This test is intended to emulate the pente domain where all transactions must be endorsed by all parties in the predefined privacy group
	// in this case, we have 3 nodes, each representing a different party in the privacy group
	// and we expect that all transactions must be endorsed by all 3 nodes and that all output states are distributed to all 3 nodes
	// Unlike the coin based domains, this is a "world state" based domain so there is only ever one available state at any one time and each
	// transaction spends that state and creates a new one.  So there is contention between parties
	ctx := context.Background()
	domainRegistryAddress := deployDomainRegistry(t)

	alice := newPartyForTesting(t, "alice", domainRegistryAddress)
	bob := newPartyForTesting(t, "bob", domainRegistryAddress)
	carol := newPartyForTesting(t, "carol", domainRegistryAddress)

	alice.peer(bob.nodeConfig, carol.nodeConfig)
	bob.peer(alice.nodeConfig, carol.nodeConfig)
	carol.peer(alice.nodeConfig, bob.nodeConfig)

	domainConfig := domains.SimpleStorageDomainConfig{
		SubmitMode: domains.ONE_TIME_USE_KEYS,
	}
	alice.start(t, domainConfig)
	bob.start(t, domainConfig)
	carol.start(t, domainConfig)

	endorsementSet := []string{alice.identityLocator, bob.identityLocator, carol.identityLocator}

	constructorParameters := &domains.SimpleStorageConstructorParameters{
		EndorsementSet:  endorsementSet,
		Name:            "FakeToken1",
		EndorsementMode: domains.PrivacyGroupEndorsement,
	}
	// send JSON RPC message to node 1 to deploy a private contract
	contractAddress := alice.deploySimpleStorageDomainInstanceContract(t, domains.PrivacyGroupEndorsement, constructorParameters)

	// Start a private transaction on alice's node
	// this should require endorsement from bob and carol
	var aliceTxID uuid.UUID
	err := alice.client.CallRPC(ctx, &aliceTxID, "ptx_sendTransaction", &pldapi.TransactionInput{
		ABI: *domains.SimpleStorageSetABI(),
		Transaction: pldapi.Transaction{
			To:             contractAddress,
			Domain:         "domain1",
			IdempotencyKey: "tx1-alice",
			Type:           pldapi.TransactionTypePrivate.Enum(),
			From:           alice.identity,
			Data: tktypes.RawJSON(`{
                    "key": "foo",
					"value": "bar"
                }`),
		},
	})

	require.NoError(t, err)
	assert.NotEqual(t, uuid.UUID{}, aliceTxID)
	assert.Eventually(t,
		transactionReceiptCondition(t, ctx, aliceTxID, alice.client, false),
		transactionLatencyThreshold(t),
		100*time.Millisecond,
		"Transaction did not receive a receipt",
	)

	// Start a private transaction on alice's node
	// this should require endorsement from bob and carol
	var bobTxID uuid.UUID
	err = bob.client.CallRPC(ctx, &bobTxID, "ptx_sendTransaction", &pldapi.TransactionInput{
		ABI: *domains.SimpleStorageSetABI(),
		Transaction: pldapi.Transaction{
			To:             contractAddress,
			Domain:         "domain1",
			IdempotencyKey: "tx1-bob",
			Type:           pldapi.TransactionTypePrivate.Enum(),
			From:           bob.identity,
			Data: tktypes.RawJSON(`{
                    "key": "foo",
					"value": "quz"
                }`),
		},
	})

	require.NoError(t, err)
	assert.NotEqual(t, uuid.UUID{}, bobTxID)
	assert.Eventually(t,
		transactionReceiptCondition(t, ctx, bobTxID, bob.client, false),
		transactionLatencyThreshold(t),
		100*time.Millisecond,
		"Transaction did not receive a receipt",
	)

	err = bob.client.CallRPC(ctx, &bobTxID, "ptx_sendTransaction", &pldapi.TransactionInput{
		ABI: *domains.SimpleStorageSetABI(),
		Transaction: pldapi.Transaction{
			To:             contractAddress,
			Domain:         "domain1",
			IdempotencyKey: "tx1-bob",
			Type:           pldapi.TransactionTypePrivate.Enum(),
			From:           bob.identity,
			Data: tktypes.RawJSON(`{
                    "key": "foo",
					"value": "quz"
                }`),
		},
	})

	var schemas []*pldapi.Schema
	err = bob.client.CallRPC(ctx, &schemas, "pstate_listSchemas", "simpleStorageDomain")
	require.NoError(t, err)
	require.Len(t, schemas, 1)

	var states []*pldapi.State
	err = bob.client.CallRPC(ctx, &states, "pstate_queryContractStates", "simpleStorageDomain", contractAddress.String(), schemas[0].ID, tktypes.RawJSON(`{}`), "available")
	require.NoError(t, err)
	require.Len(t, states, 1)
	stateData := make(map[string]string)
	storage := make(map[string]string)
	jsonErr := json.Unmarshal(states[0].Data.Bytes(), &stateData)
	require.NoError(t, jsonErr)

	jsonErr = json.Unmarshal([]byte(stateData["records"]), &storage)
	require.NoError(t, jsonErr)

	assert.Equal(t, "quz", storage["foo"])

}

func TestPrivateTransactions100PercentEndorsementConcurrent(t *testing.T) {
	// This test is intended to emulate the pente domain where all transactions must be endorsed by all parties in the predefined privacy group
	// in this case, we have 3 nodes, each representing a different party in the privacy group
	// and we expect that all transactions must be endorsed by all 3 nodes and that all output states are distributed to all 3 nodes
	// Unlike the coin based domains, this is a "world state" based domain so there is only ever one available state at any one time and each
	// transaction spends that state and creates a new one.  So there is contention between parties
	ctx := context.Background()
	domainRegistryAddress := deployDomainRegistry(t)

	alice := newPartyForTesting(t, "alice", domainRegistryAddress)
	bob := newPartyForTesting(t, "bob", domainRegistryAddress)
	carol := newPartyForTesting(t, "carol", domainRegistryAddress)

	alice.peer(bob.nodeConfig, carol.nodeConfig)
	bob.peer(alice.nodeConfig, carol.nodeConfig)
	carol.peer(alice.nodeConfig, bob.nodeConfig)

	domainConfig := domains.SimpleStorageDomainConfig{
		SubmitMode: domains.ONE_TIME_USE_KEYS,
	}
	alice.start(t, domainConfig)
	bob.start(t, domainConfig)
	carol.start(t, domainConfig)

	endorsementSet := []string{alice.identityLocator, bob.identityLocator, carol.identityLocator}

	constructorParameters := &domains.SimpleStorageConstructorParameters{
		EndorsementSet:  endorsementSet,
		Name:            "FakeToken1",
		EndorsementMode: domains.PrivacyGroupEndorsement,
	}
	// send JSON RPC message to node 1 to deploy a private contract
	contractAddress := alice.deploySimpleStorageDomainInstanceContract(t, domains.PrivacyGroupEndorsement, constructorParameters)
	for i := 0; i < 1; i++ {

		// Start a private transaction on alice's node
		// this should require endorsement from bob and carol
		var aliceTxID uuid.UUID
		err := alice.client.CallRPC(ctx, &aliceTxID, "ptx_sendTransaction", &pldapi.TransactionInput{
			ABI: *domains.SimpleStorageSetABI(),
			Transaction: pldapi.Transaction{
				To:             contractAddress,
				Domain:         "domain1",
				IdempotencyKey: fmt.Sprintf("tx1-alice0-%d", i),
				Type:           pldapi.TransactionTypePrivate.Enum(),
				From:           alice.identity,
				Data: tktypes.RawJSON(fmt.Sprintf(`{
                    "key": "alice_%d",
					"value": "hello_%d"
                }`, i, i)),
			},
		})
		require.NoError(t, err)
		assert.NotEqual(t, uuid.UUID{}, aliceTxID)

		// Start a private transaction on alice's node
		// this should require endorsement from bob and carol
		var bobTxID uuid.UUID
		err = bob.client.CallRPC(ctx, &bobTxID, "ptx_sendTransaction", &pldapi.TransactionInput{
			ABI: *domains.SimpleStorageSetABI(),
			Transaction: pldapi.Transaction{
				To:             contractAddress,
				Domain:         "domain1",
				IdempotencyKey: fmt.Sprintf("tx1-bob-%d", i),
				Type:           pldapi.TransactionTypePrivate.Enum(),
				From:           bob.identity,
				Data: tktypes.RawJSON(fmt.Sprintf(`{
                    "key": "bob_%d",
					"value": "bonjour_%d"
                }`, i, i)),
			},
		})
		require.NoError(t, err)
		assert.NotEqual(t, uuid.UUID{}, bobTxID)

		assert.Eventually(t,
			transactionReceiptCondition(t, ctx, aliceTxID, alice.client, false),
			transactionLatencyThreshold(t),
			100*time.Millisecond,
			"Transaction did not receive a receipt",
		)

		assert.Eventually(t,
			transactionReceiptCondition(t, ctx, bobTxID, bob.client, false),
			transactionLatencyThreshold(t),
			100*time.Millisecond,
			"Transaction did not receive a receipt",
		)
	}

	var schemas []*pldapi.Schema

	err := alice.client.CallRPC(ctx, &schemas, "pstate_listSchemas", "simpleStorageDomain")
	require.NoError(t, err)
	require.Len(t, schemas, 1)

	err = bob.client.CallRPC(ctx, &schemas, "pstate_listSchemas", "simpleStorageDomain")
	require.NoError(t, err)
	require.Len(t, schemas, 1)

	var states []*pldapi.State
	err = bob.client.CallRPC(ctx, &states, "pstate_queryContractStates", "simpleStorageDomain", contractAddress.String(), schemas[0].ID, tktypes.RawJSON(`{}`), "available")
	require.NoError(t, err)
	require.Len(t, states, 1)
	stateData := make(map[string]string)
	storage := make(map[string]string)
	jsonErr := json.Unmarshal(states[0].Data.Bytes(), &stateData)
	require.NoError(t, jsonErr)

	jsonErr = json.Unmarshal([]byte(stateData["records"]), &storage)
	require.NoError(t, jsonErr)

	assert.Equal(t, "bonjour", storage["bob"])
	assert.Equal(t, "hello", storage["alice"])

}

/*func TestPrivateTransactionsTransfersConcurrent(t *testing.T) {
	ctx := context.Background()
	domainRegistryAddress := deployDomainRegistry(t)

	alice := newPartyForTesting(t, "alice", domainRegistryAddress)
	bob := newPartyForTesting(t, "bob", domainRegistryAddress)
	carol := newPartyForTesting(t, "carol", domainRegistryAddress)

	alice.peer(bob.nodeConfig, carol.nodeConfig)
	bob.peer(alice.nodeConfig, carol.nodeConfig)
	carol.peer(alice.nodeConfig, bob.nodeConfig)

	domainConfig := domains.SimpleDomainConfig{
		SubmitMode: domains.ONE_TIME_USE_KEYS,
	}
	alice.start(t, domainConfig)
	bob.start(t, domainConfig)
	carol.start(t, domainConfig)

	endorsementSet := []string{alice.identityLocator, bob.identityLocator, carol.identityLocator}

	constructorParameters := &domains.ConstructorParameters{
		EndorsementSet:  endorsementSet,
		Name:            "FakeToken1",
		Symbol:          "FT1",
		EndorsementMode: domains.PrivacyGroupEndorsement,
	}
	// send JSON RPC message to node 1 to deploy a private contract
	contractAddress := alice.deploySimpleDomainInstanceContract(t, domains.PrivacyGroupEndorsement, constructorParameters)

	// mint some tokens to each party
	// start 3 go routines where each party transfers tokens to the other other 2 parties.
	// take regular checkpoints to ensure that one party is not lagging behind or running ahead
	// no party should ever reach zero balance
	// at any point in time, the total balance of all parties should be the same

	// Start a private transaction on alice's node
	// this should require endorsement from bob and carol
	var mintToAliceTxID uuid.UUID
	err := alice.client.CallRPC(ctx, &mintToAliceTxID, "ptx_sendTransaction", &pldapi.TransactionInput{
		ABI: *domains.SimpleTokenTransferABI(),
		Transaction: pldapi.Transaction{
			To:             contractAddress,
			Domain:         "domain1",
			IdempotencyKey: "tx-mint-alice",
			Type:           pldapi.TransactionTypePrivate.Enum(),
			From:           alice.identity,
			Data: tktypes.RawJSON(`{
                    "from": "",
                    "to": "` + alice.identityLocator + `",
                    "amount": "1000"
                }`),
		},
	})
	require.NoError(t, err)
	assert.NotEqual(t, uuid.UUID{}, mintToAliceTxID)
	assert.Eventually(t,
		transactionReceiptCondition(t, ctx, mintToAliceTxID, alice.client, false),
		transactionLatencyThreshold(t),
		100*time.Millisecond,
		"Transaction did not receive a receipt",
	)

	var mintToBobTxID uuid.UUID
	err = alice.client.CallRPC(ctx, &mintToBobTxID, "ptx_sendTransaction", &pldapi.TransactionInput{
		ABI: *domains.SimpleTokenTransferABI(),
		Transaction: pldapi.Transaction{
			To:             contractAddress,
			Domain:         "domain1",
			IdempotencyKey: "tx-mint-bob",
			Type:           pldapi.TransactionTypePrivate.Enum(),
			From:           alice.identity,
			Data: tktypes.RawJSON(`{
                    "from": "",
                    "to": "` + bob.identityLocator + `",
                    "amount": "1000"
                }`),
		},
	})
	require.NoError(t, err)
	assert.NotEqual(t, uuid.UUID{}, mintToBobTxID)
	assert.Eventually(t,
		transactionReceiptCondition(t, ctx, mintToBobTxID, alice.client, false),
		transactionLatencyThreshold(t),
		100*time.Millisecond,
		"Transaction did not receive a receipt",
	)

	var mintToCarolTxID uuid.UUID
	err = alice.client.CallRPC(ctx, &mintToCarolTxID, "ptx_sendTransaction", &pldapi.TransactionInput{
		ABI: *domains.SimpleTokenTransferABI(),
		Transaction: pldapi.Transaction{
			To:             contractAddress,
			Domain:         "domain1",
			IdempotencyKey: "tx-mint-carol",
			Type:           pldapi.TransactionTypePrivate.Enum(),
			From:           alice.identity,
			Data: tktypes.RawJSON(`{
                    "from": "",
                    "to": "` + carol.identityLocator + `",
                    "amount": "1000"
                }`),
		},
	})
	require.NoError(t, err)
	assert.NotEqual(t, uuid.UUID{}, mintToCarolTxID)
	assert.Eventually(t,
		transactionReceiptCondition(t, ctx, mintToCarolTxID, alice.client, false),
		transactionLatencyThreshold(t),
		100*time.Millisecond,
		"Transaction did not receive a receipt",
	)

	runner := func(t *testing.T, party partyForTesting, peers []*partyForTesting) (func(), func()) {
		stopChannel := make(chan struct{})
		run := func() {
			count := 0
			for _, peer := range peers {
				var txID uuid.UUID
				err := party.client.CallRPC(ctx, &txID, "ptx_sendTransaction", &pldapi.TransactionInput{
					ABI: *domains.SimpleTokenTransferABI(),
					Transaction: pldapi.Transaction{
						To:             contractAddress,
						Domain:         "domain1",
						IdempotencyKey: "tx-transfer-" + from + "-" + to,
						Type:           pldapi.TransactionTypePrivate.Enum(),
						From:           from,
						Data: tktypes.RawJSON(`{
					"from": "",
					"to": "` + to + `",
					"amount": "` + amount + `"
				}`),
					},
				})
				require.NoError(t, err)
				assert.NotEqual(t, uuid.UUID{}, txID)
				assert.Eventually(t,
					transactionReceiptCondition(t, ctx, txID, client, false),
					transactionLatencyThreshold(t),
					100*time.Millisecond,
					"Transaction did not receive a receipt",
				)

				count++
			}

		}
		stop := func() {
			stopChannel <- struct{}{}
		}
		return run, stop
	}
	runAlice, stopAlice := runner(t, alice)
	runBob, stopBob := runner(t, bob)
	runCarol, stopCarol := runner(t, carol)
	go runAlice(t, bob)
	go runBob(t, alice)
	go runCarol(t, carol)

	time.Sleep(60 * time.Second)
	stopAlice()
	stopBob()
	stopCarol()

}
*/
