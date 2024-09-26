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

package publictxmgr

import (
	"context"
	"crypto/rand"
	"database/sql/driver"
	"fmt"
	"math/big"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/google/uuid"
	"github.com/hyperledger/firefly-signer/pkg/ethsigner"
	"github.com/hyperledger/firefly-signer/pkg/ethtypes"
	"github.com/kaleido-io/paladin/core/internal/components"
	"github.com/kaleido-io/paladin/core/internal/flushwriter"
	"github.com/kaleido-io/paladin/core/mocks/componentmocks"
	"github.com/kaleido-io/paladin/core/pkg/blockindexer"
	"github.com/kaleido-io/paladin/core/pkg/ethclient"
	"github.com/kaleido-io/paladin/core/pkg/persistence"
	"github.com/kaleido-io/paladin/core/pkg/persistence/mockpersistence"
	"github.com/kaleido-io/paladin/core/pkg/signer/api"
	"github.com/kaleido-io/paladin/toolkit/pkg/algorithms"
	"github.com/kaleido-io/paladin/toolkit/pkg/confutil"
	"github.com/kaleido-io/paladin/toolkit/pkg/log"
	"github.com/kaleido-io/paladin/toolkit/pkg/ptxapi"
	"github.com/kaleido-io/paladin/toolkit/pkg/query"
	"github.com/kaleido-io/paladin/toolkit/pkg/retry"
	"github.com/kaleido-io/paladin/toolkit/pkg/tktypes"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
)

type dependencyMocks struct {
	allComponents    *componentmocks.AllComponents
	db               sqlmock.Sqlmock // unless realDB
	keyManager       ethclient.KeyManager
	ethClientFactory *componentmocks.EthClientFactory
	ethClient        *componentmocks.EthClient
	blockIndexer     *componentmocks.BlockIndexer
	txManager        *componentmocks.TXManager
}

// const testDestAddress = "0x6cee73cf4d5b0ac66ce2d1c0617bec4bedd09f39"

// const testMainSigningAddress = testDestAddress

func baseMocks(t *testing.T) *dependencyMocks {
	mocks := &dependencyMocks{
		allComponents:    componentmocks.NewAllComponents(t),
		ethClientFactory: componentmocks.NewEthClientFactory(t),
		ethClient:        componentmocks.NewEthClient(t),
		blockIndexer:     componentmocks.NewBlockIndexer(t),
		txManager:        componentmocks.NewTXManager(t),
	}
	mocks.allComponents.On("EthClientFactory").Return(mocks.ethClientFactory).Maybe()
	mocks.ethClientFactory.On("SharedWS").Return(mocks.ethClient).Maybe()
	mocks.ethClientFactory.On("HTTPClient").Return(mocks.ethClient).Maybe()
	mocks.allComponents.On("BlockIndexer").Return(mocks.blockIndexer).Maybe()
	mocks.allComponents.On("TxManager").Return(mocks.txManager).Maybe()
	return mocks
}

func newTestPublicTxManager(t *testing.T, realDBAndSigner bool, extraSetup ...func(mocks *dependencyMocks, conf *Config)) (context.Context, *pubTxManager, *dependencyMocks, func()) {
	log.SetLevel("debug")
	ctx := context.Background()
	conf := &Config{
		Manager: ManagerConfig{
			Interval:                 confutil.P("1h"),
			MaxInFlightOrchestrators: confutil.P(1),
			SubmissionWriter: flushwriter.Config{
				WorkerCount: confutil.P(1),
			},
		},
		Orchestrator: OrchestratorConfig{
			Interval: confutil.P("1h"),
			SubmissionRetry: retry.ConfigWithMax{
				MaxAttempts: confutil.P(0),
			},
		},
	}

	mocks := baseMocks(t)

	var dbClose func()
	var p persistence.Persistence
	if realDBAndSigner {
		var err error
		p, dbClose, err = persistence.NewUnitTestPersistence(ctx)
		require.NoError(t, err)

		mocks.keyManager, err = ethclient.NewSimpleTestKeyManager(ctx, &api.Config{
			KeyStore: api.StoreConfig{
				Type: api.KeyStoreTypeStatic,
				Static: api.StaticKeyStorageConfig{
					Keys: map[string]api.StaticKeyEntryConfig{
						"seed": {
							Encoding: "hex",
							Inline:   tktypes.Bytes32(tktypes.RandBytes(32)).String(),
						},
					},
				},
			},
			KeyDerivation: api.KeyDerivationConfig{
				Type: api.KeyDerivationTypeBIP32,
			},
		})
		require.NoError(t, err)
	} else {
		mp, err := mockpersistence.NewSQLMockProvider()
		require.NoError(t, err)
		p = mp.P
		mocks.db = mp.Mock
		dbClose = func() {}
		mocks.keyManager = componentmocks.NewKeyManager(t)
	}
	mocks.allComponents.On("Persistence").Return(p).Maybe()
	mocks.allComponents.On("KeyManager").Return(mocks.keyManager).Maybe()

	// Run any extra functions before we create the manager
	for _, setup := range extraSetup {
		setup(mocks, conf)
	}

	pmgr := NewPublicTransactionManager(ctx, conf).(*pubTxManager)
	ir, err := pmgr.PreInit(mocks.allComponents)
	require.NoError(t, err)
	assert.NotNil(t, ir)

	err = pmgr.PostInit(mocks.allComponents)
	require.NoError(t, err)

	return pmgr.ctx, pmgr, mocks, func() {
		pmgr.Stop()
		dbClose()
	}
}

func passthroughBuildRawTransactionNoResolve(m *dependencyMocks, chainID int64) {
	mbt := m.ethClient.On("BuildRawTransactionNoResolve", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything)
	mbt.Run(func(args mock.Arguments) {
		var callOpts []ethclient.CallOption
		for _, a := range args[4:] {
			callOpts = append(callOpts, a.(ethclient.CallOption))
		}
		r, err := ethclient.NewUnconnectedRPCClient(context.Background(), m.keyManager, &ethclient.Config{}, chainID).BuildRawTransactionNoResolve(
			args[0].(context.Context),
			args[1].(ethclient.EthTXVersion),
			args[2].(*ethclient.ResolvedSigner),
			args[3].(*ethsigner.Transaction),
			callOpts...,
		)
		mbt.Return(r, err)
	})
}

func TestNewEngineErrors(t *testing.T) {
	mocks := baseMocks(t)

	mocks.keyManager = componentmocks.NewKeyManager(t)
	mocks.allComponents.On("KeyManager").Return(mocks.keyManager)
	pmgr := NewPublicTransactionManager(context.Background(), &Config{
		BalanceManager: BalanceManagerConfig{
			AutoFueling: AutoFuelingConfig{
				SourceAddress: confutil.P("bad address"),
			},
		},
	})
	err := pmgr.PostInit(mocks.allComponents)
	assert.Regexp(t, "bad address", err)
}

func TestInit(t *testing.T) {
	_, _, _, done := newTestPublicTxManager(t, false)
	defer done()
}

func TestTransactionLifecycleRealKeyMgrAndDB(t *testing.T) {
	ctx, ble, m, done := newTestPublicTxManager(t, true, func(mocks *dependencyMocks, conf *Config) {
		conf.Manager.Interval = confutil.P("50ms")
		conf.Orchestrator.Interval = confutil.P("50ms")
		conf.Manager.OrchestratorIdleTimeout = confutil.P("1ms")
	})
	defer done()

	err := ble.Start()
	require.NoError(t, err)

	// Mock a gas price
	chainID, _ := rand.Int(rand.Reader, big.NewInt(100000000000000))
	m.ethClient.On("GasPrice", mock.Anything).Return(tktypes.MustParseHexUint256("1000000000000000"), nil)
	m.ethClient.On("ChainID").Return(chainID.Int64())

	// When we create the transaction, it will be a real one
	passthroughBuildRawTransactionNoResolve(m, chainID.Int64())

	// Resolve the key ourselves for comparison
	_, resolvedKeyStr, err := m.keyManager.ResolveKey(ctx, "signer1", algorithms.ECDSA_SECP256K1_PLAINBYTES)
	require.NoError(t, err)
	resolvedKey := tktypes.MustEthAddress(resolvedKeyStr)

	// create some transactions that are successfully added
	const transactionCount = 10
	txIDs := make([]uuid.UUID, transactionCount)
	txs := make([]*components.PublicTxSubmission, transactionCount)
	for i := range txIDs {
		txIDs[i] = uuid.New()

		// We do the public TX manager's job for it in this test
		fakeTxManagerInsert(t, ble.p.DB(), txIDs[i], "signer1")

		txs[i] = &components.PublicTxSubmission{
			Bindings: []*components.PaladinTXReference{
				{TransactionID: txIDs[i], TransactionType: ptxapi.TransactionTypePrivate.Enum()},
			},
			PublicTxInput: ptxapi.PublicTxInput{
				From: "signer1",
				Data: []byte(fmt.Sprintf("data %d", i)),
			},
		}

	}

	// gas estimate and nonce should be cached - so are once'd
	m.ethClient.On("EstimateGasNoResolve", mock.Anything, mock.Anything, mock.Anything).
		Return(ethclient.EstimateGasResult{GasLimit: tktypes.HexUint64(10)}, nil)
	baseNonce := uint64(11223000)
	m.ethClient.On("GetTransactionCount", mock.Anything, mock.Anything).
		Return(confutil.P(tktypes.HexUint64(baseNonce)), nil).Once()

	// For the first one we do a one-off
	_, err = ble.SingleTransactionSubmit(ctx, txs[0])
	require.NoError(t, err)

	// The rest we submit as as batch
	batch, err := ble.PrepareSubmissionBatch(ctx, txs[1:])
	require.NoError(t, err)
	assert.Empty(t, batch.Rejected())
	assert.Len(t, batch.Accepted(), len(txs)-1)
	err = ble.p.DB().Transaction(func(dbTX *gorm.DB) error {
		return batch.Submit(ctx, dbTX)
	})
	require.NoError(t, err)
	batch.Completed(ctx, true) // would normally be in a defer

	// Record activity on one TX
	for i := range txs {
		ble.addActivityRecord(fmt.Sprintf("%s:%d", resolvedKey, int(baseNonce)+i), fmt.Sprintf("activity %d", i))
	}

	// Query to check we now have all of these
	queryTxs, err := ble.QueryPublicTxWithBindings(ctx, ble.p.DB(),
		query.NewQueryBuilder().Sort("nonce").Query())
	require.NoError(t, err)
	assert.Len(t, queryTxs, len(txs))
	for i, qTX := range queryTxs {
		// We don't include the bindings on these queries
		assert.Equal(t, *resolvedKey, qTX.From)
		assert.Equal(t, uint64(i)+baseNonce, qTX.Nonce.Uint64())
		assert.Equal(t, txs[i].Data, qTX.Data)
		require.Greater(t, len(qTX.Activity), 0)
	}

	// Query scoped to one TX
	byTxn, err := ble.QueryPublicTxForTransactions(ctx, ble.p.DB(), txIDs, nil)
	require.NoError(t, err)
	for i, tx := range txs {
		queryTxs := byTxn[tx.Bindings[0].TransactionID]
		require.Len(t, queryTxs, 1)
		assert.Equal(t, baseNonce+uint64(i), queryTxs[0].Nonce.Uint64())
	}

	// Check we can select to just see confirmed (which this isn't yet)
	byTxn, err = ble.QueryPublicTxForTransactions(ctx, ble.p.DB(), txIDs,
		query.NewQueryBuilder().NotNull("transactionHash").Query())
	require.NoError(t, err)
	for _, tx := range txs {
		queryTxs := byTxn[tx.Bindings[0].TransactionID]
		require.Empty(t, queryTxs, 1)
	}

	// Wait for a submission to happen
	calculatedConfirmations := make(chan *blockindexer.IndexedTransactionNotify, len(txIDs))
	srtx := m.ethClient.On("SendRawTransaction", mock.Anything, mock.Anything)
	srtx.Run(func(args mock.Arguments) {
		signedMessage := args[1].(tktypes.HexBytes)

		signer, ethTx, err := ethsigner.RecoverRawTransaction(ctx, ethtypes.HexBytes0xPrefix(signedMessage), m.ethClient.ChainID())
		require.NoError(t, err)
		assert.Equal(t, *resolvedKey, tktypes.EthAddress(*signer))

		// We need to decode the TX to find the nonce
		txHash := calculateTransactionHash(signedMessage)
		confirmation := &blockindexer.IndexedTransactionNotify{
			IndexedTransaction: blockindexer.IndexedTransaction{
				Hash:             *txHash,
				BlockNumber:      11223344,
				TransactionIndex: 10,
				From:             resolvedKey,
				To:               (*tktypes.EthAddress)(ethTx.To),
				Nonce:            ethTx.Nonce.Uint64(),
				Result:           blockindexer.TXResult_SUCCESS.Enum(),
			},
		}
		calculatedConfirmations <- confirmation

		srtx.Return(&confirmation.Hash, nil)
	})

	// Wait for all the confirmations to be calculated
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	gatheredConfirmations := []*blockindexer.IndexedTransactionNotify{}
	for len(gatheredConfirmations) < len(txs) {
		select {
		case confirmation := <-calculatedConfirmations:
			gatheredConfirmations = append(gatheredConfirmations, confirmation)

			// Check we can query the public txn by this submission (even before the confirm)
			ptxQuery, err := ble.GetPublicTransactionForHash(ctx, ble.p.DB(), confirmation.Hash)
			require.NoError(t, err)
			require.NotNil(t, ptxQuery)
			require.Len(t, ptxQuery.Submissions, 1)
			require.Equal(t, ptxQuery.Nonce.Uint64(), confirmation.Nonce)
		case <-ticker.C:
			if t.Failed() {
				return
			}
		}
	}

	// Simulate detection of the receipt by the blockexplorer - phase 1 in the DB Transaction
	var allMatches []*components.PublicTxMatch
	confirmationsMatched := make(map[uuid.UUID]*components.PublicTxMatch)
	for _, confirmation := range gatheredConfirmations {
		matches, err := ble.MatchUpdateConfirmedTransactions(ctx, ble.p.DB(), []*blockindexer.IndexedTransactionNotify{confirmation})
		require.NoError(t, err)
		// NOTE: This is a good test that we definitely persist _before_ we submit as
		// otherwise we could miss notifying users of their transactions completing.
		// Either because we crashed without finishing our DB commit, or because (like this
		// test simulates) the blockchain confirms to us before we submit.
		allMatches = append(allMatches, matches...)
		assert.Len(t, matches, 1)
		confirmationsMatched[matches[0].TransactionID] = matches[0]
	}
	for _, tx := range txs {
		assert.NotNil(t, confirmationsMatched[tx.Bindings[0].TransactionID])
	}

	// Check we can select to just see just unconfirmed
	byTxn, err = ble.QueryPublicTxForTransactions(ctx, ble.p.DB(), txIDs,
		query.NewQueryBuilder().Null("transactionHash").Query())
	require.NoError(t, err)
	for _, tx := range txs {
		queryTxs := byTxn[tx.Bindings[0].TransactionID]
		require.Empty(t, queryTxs, 1)
	}

	// phase 2 of the update, happens after the DB TX commits, so we can wake up the
	// orchestrators to remove the in-flight TXns
	ble.NotifyConfirmPersisted(ctx, allMatches)

	// Now the inflights should all exit, so we wait for the orchestrator to exit
	for ble.getOrchestratorCount() > 0 {
		<-ticker.C
		if t.Failed() {
			return
		}
	}
	ticker.Stop()

}

func fakeTxManagerInsert(t *testing.T, db *gorm.DB, txID uuid.UUID, fromStr string) {
	// Yes, there is a slight smell of un-partitioned DB responsibilities between components
	// here. But the saving is critical path avoidance of one extra DB query for every block
	// that is mined. So it's currently considered worth this limited quirk.
	fakeABI := tktypes.Bytes32(tktypes.RandBytes(32))
	err := db.Exec(`INSERT INTO "abis" ("hash","abi","created") VALUES (?, ?, ?)`,
		fakeABI, `[]`, tktypes.TimestampNow()).
		Error
	require.NoError(t, err)
	err = db.Exec(`INSERT INTO "transactions" ("id", "created", "type", "abi_ref", "from") VALUES (?, ?, ?, ?, ?)`,
		txID, tktypes.TimestampNow(), ptxapi.TransactionTypePrivate.Enum(), fakeABI, fromStr).
		Error
	require.NoError(t, err)
}

func TestResolveFail(t *testing.T) {
	ctx, ble, m, done := newTestPublicTxManager(t, false)
	defer done()

	keyManager := m.keyManager.(*componentmocks.KeyManager)

	// resolve key failure
	keyManager.On("ResolveKey", ctx, "signer1", algorithms.ECDSA_SECP256K1_PLAINBYTES).Return("", "", fmt.Errorf("resolve err")).Once()
	_, err := ble.SingleTransactionSubmit(ctx, &components.PublicTxSubmission{
		PublicTxInput: ptxapi.PublicTxInput{
			From: "signer1",
		},
	})
	assert.Regexp(t, "resolve err", err)

	resolvedKey := tktypes.EthAddress(tktypes.RandBytes(20))
	keyManager.On("ResolveKey", ctx, "signer1", algorithms.ECDSA_SECP256K1_PLAINBYTES).Return("keyhandle1", resolvedKey.String(), nil)
}

func TestSubmitFailures(t *testing.T) {
	ctx, ble, m, done := newTestPublicTxManager(t, false)
	defer done()

	resolvedKey := tktypes.EthAddress(tktypes.RandBytes(20))
	keyManager := m.keyManager.(*componentmocks.KeyManager)
	keyManager.On("ResolveKey", ctx, "signer1", algorithms.ECDSA_SECP256K1_PLAINBYTES).Return("", resolvedKey.String(), nil)

	// estimation failure - for non-revert
	m.ethClient.On("EstimateGasNoResolve", mock.Anything, mock.Anything, mock.Anything).
		Return(ethclient.EstimateGasResult{}, fmt.Errorf("GasEstimate error")).Once()
	_, err := ble.SingleTransactionSubmit(ctx, &components.PublicTxSubmission{
		PublicTxInput: ptxapi.PublicTxInput{
			From: "signer1",
		},
	})
	assert.Regexp(t, "GasEstimate error", err)

	// estimation failure - for revert
	sampleRevertData := tktypes.HexBytes("some data")
	m.txManager.On("CalculateRevertError", mock.Anything, mock.Anything, sampleRevertData).Return(fmt.Errorf("mapped revert error"))
	m.ethClient.On("EstimateGasNoResolve", mock.Anything, mock.Anything, mock.Anything).
		Return(ethclient.EstimateGasResult{
			RevertData: sampleRevertData,
		}, fmt.Errorf("execution reverted")).Once()
	_, err = ble.SingleTransactionSubmit(ctx, &components.PublicTxSubmission{
		PublicTxInput: ptxapi.PublicTxInput{
			From: "signer1",
		},
	})
	assert.Regexp(t, "mapped revert error", err)

	// insert transaction next nonce error
	m.ethClient.On("EstimateGasNoResolve", mock.Anything, mock.Anything, mock.Anything).
		Return(ethclient.EstimateGasResult{GasLimit: tktypes.HexUint64(10)}, nil)
	m.ethClient.On("GetTransactionCount", mock.Anything, mock.Anything).
		Return(nil, fmt.Errorf("pop")).Once()
	_, err = ble.SingleTransactionSubmit(ctx, &components.PublicTxSubmission{
		PublicTxInput: ptxapi.PublicTxInput{
			From: "signer1",
		},
	})
	assert.NotNil(t, err)
	assert.Regexp(t, "pop", err)
}

func TestAddActivityDisabled(t *testing.T) {
	_, ble, _, done := newTestPublicTxManager(t, false, func(mocks *dependencyMocks, conf *Config) {
		conf.Manager.ActivityRecords.RecordsPerTransaction = confutil.P(0)
	})
	defer done()

	ble.addActivityRecord("signer1:nonce", "message")

	assert.Empty(t, ble.getActivityRecords("signer1:nonce"))
}

func TestAddActivityWrap(t *testing.T) {
	_, ble, _, done := newTestPublicTxManager(t, false)
	defer done()

	signerNonce := "signer1:nonce"
	for i := 0; i < 100; i++ {
		ble.addActivityRecord(signerNonce, fmt.Sprintf("message %.2d", i))
	}

	activityRecords := ble.getActivityRecords(signerNonce)
	assert.Equal(t, "message 99", activityRecords[0].Message)
	assert.Equal(t, "message 98", activityRecords[1].Message)
	assert.Len(t, activityRecords, ble.maxActivityRecordsPerTx)

}

func mockForSubmitSuccess(mocks *dependencyMocks, conf *Config) {
	signingKey := tktypes.EthAddress(tktypes.RandBytes(20))
	mockKeyManager := mocks.keyManager.(*componentmocks.KeyManager)
	mockKeyManager.On("ResolveKey", mock.Anything, "signer1", algorithms.ECDSA_SECP256K1_PLAINBYTES).Return("", signingKey.String(), nil)
	mocks.ethClient.On("GetTransactionCount", mock.Anything, mock.Anything).
		Return(confutil.P(tktypes.HexUint64(1122334455)), nil).Once()
	mocks.db.ExpectBegin()
	mocks.db.ExpectExec("INSERT.*public_txns").WillReturnResult(driver.ResultNoRows)
	mocks.db.ExpectCommit()
}

func TestHandleNewTransactionTransferOnlyWithProvideGas(t *testing.T) {
	ctx := context.Background()
	_, ble, _, done := newTestPublicTxManager(t, false, mockForSubmitSuccess)
	defer done()

	// create transaction succeeded
	tx, err := ble.SingleTransactionSubmit(ctx, &components.PublicTxSubmission{
		PublicTxInput: ptxapi.PublicTxInput{
			From: "signer1",
			To:   tktypes.MustEthAddress(tktypes.RandHex(20)),
			PublicTxOptions: ptxapi.PublicTxOptions{
				Gas:   confutil.P(tktypes.HexUint64(1223451)),
				Value: tktypes.Uint64ToUint256(100),
			},
		},
	})
	assert.NoError(t, err)
	assert.NotNil(t, tx.PublicTx().From)
	assert.Equal(t, uint64(1223451), tx.PublicTx().Gas.Uint64())

}

func TestEngineSuspendResumeRealDB(t *testing.T) {

	ctx, ble, m, done := newTestPublicTxManager(t, true, func(mocks *dependencyMocks, conf *Config) {
		conf.Manager.Interval = confutil.P("50ms")
		conf.Orchestrator.Interval = confutil.P("50ms")
		conf.Manager.OrchestratorIdleTimeout = confutil.P("1ms")
		conf.Orchestrator.StageRetryTime = confutil.P("0ms") // without this we stick in the stage for 10s before we look to suspend
	})
	defer done()

	err := ble.Start()
	require.NoError(t, err)

	// Mock a gas price
	chainID, _ := rand.Int(rand.Reader, big.NewInt(100000000000000))
	m.ethClient.On("GasPrice", mock.Anything).Return(tktypes.MustParseHexUint256("1000000000000000"), nil)

	// When we create the transaction, it will be a real one
	passthroughBuildRawTransactionNoResolve(m, chainID.Int64())

	pubTx := &components.PublicTxSubmission{
		PublicTxInput: ptxapi.PublicTxInput{
			From: "signer1",
			PublicTxOptions: ptxapi.PublicTxOptions{
				Gas: confutil.P(tktypes.HexUint64(1223451)),
			},
		},
	}

	// We can get the nonce
	m.ethClient.On("GetTransactionCount", mock.Anything, mock.Anything).Return(confutil.P(tktypes.HexUint64(1122334455)), nil)
	// ... but attempting to get it onto the chain is going to block failing
	m.ethClient.On("SendRawTransaction", mock.Anything, mock.Anything).Return(nil, fmt.Errorf("pop")).Maybe()

	_, err = ble.SingleTransactionSubmit(ctx, pubTx)
	require.NoError(t, err)

	ticker := time.NewTicker(50 * time.Millisecond)
	defer ticker.Stop()

	// Resolve the key ourselves for comparison
	_, resolvedKeyStr, err := m.keyManager.ResolveKey(ctx, "signer1", algorithms.ECDSA_SECP256K1_PLAINBYTES)
	require.NoError(t, err)
	resolvedKey := *tktypes.MustEthAddress(resolvedKeyStr)

	// Wait for the orchestrator to kick off and pick this TX up
	getIFT := func() *InFlightTransactionStageController {
		var o *orchestrator
		var ift *InFlightTransactionStageController
		for ift == nil {
			<-ticker.C
			if t.Failed() {
				panic("test failed")
			}
			o = ble.getOrchestratorForAddress(resolvedKey)
			if o != nil {
				ift = o.getFirstInFlight()
			}
		}
		return ift
	}
	txNonce := getIFT().stateManager.GetNonce()

	// suspend the TX
	err = ble.SuspendTransaction(ctx, resolvedKey, txNonce)
	require.NoError(t, err)

	// wait to flush out the whole orchestrator as this is the only thing in flight
	for ble.getOrchestratorCount() > 0 {
		<-ticker.C
		if t.Failed() {
			return
		}
	}

	// resume the txn
	err = ble.ResumeTransaction(ctx, resolvedKey, txNonce)
	require.NoError(t, err)

	// check the orchestrator comes back
	newNonce := getIFT().stateManager.GetNonce()
	assert.Equal(t, txNonce, newNonce)

}
