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
	"fmt"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/kaleido-io/paladin/core/internal/components"
	"github.com/kaleido-io/paladin/core/mocks/componentmocks"
	"github.com/kaleido-io/paladin/core/pkg/ethclient"
	"github.com/kaleido-io/paladin/core/pkg/persistence"
	"github.com/kaleido-io/paladin/core/pkg/persistence/mockpersistence"
	"github.com/kaleido-io/paladin/toolkit/pkg/algorithms"
	"github.com/kaleido-io/paladin/toolkit/pkg/confutil"
	"github.com/kaleido-io/paladin/toolkit/pkg/ptxapi"
	"github.com/kaleido-io/paladin/toolkit/pkg/retry"
	"github.com/kaleido-io/paladin/toolkit/pkg/tktypes"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

type dependencyMocks struct {
	allComponents    *componentmocks.AllComponents
	db               sqlmock.Sqlmock // unless realDB
	keyManager       *componentmocks.KeyManager
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
		keyManager:       componentmocks.NewKeyManager(t),
		ethClientFactory: componentmocks.NewEthClientFactory(t),
		ethClient:        componentmocks.NewEthClient(t),
		blockIndexer:     componentmocks.NewBlockIndexer(t),
		txManager:        componentmocks.NewTXManager(t),
	}
	mocks.allComponents.On("KeyManager").Return(mocks.keyManager).Maybe()
	mocks.allComponents.On("EthClientFactory").Return(mocks.ethClientFactory).Maybe()
	mocks.ethClientFactory.On("SharedWS").Return(mocks.ethClient).Maybe()
	mocks.allComponents.On("BlockIndexer").Return(mocks.blockIndexer).Maybe()
	mocks.allComponents.On("TxManager").Return(mocks.txManager).Maybe()
	return mocks
}

func NewTestPublicTxManager(t *testing.T, realDB bool, extraSetup ...func(mocks *dependencyMocks, conf *Config)) (context.Context, *pubTxManager, *dependencyMocks, func()) {
	ctx := context.Background()
	conf := &Config{
		Manager: ManagerConfig{
			Interval:                 confutil.P("1h"),
			MaxInFlightOrchestrators: confutil.P(1),
		},
		Orchestrator: OrchestratorConfig{
			Interval:    confutil.P("1h"),
			MaxInFlight: confutil.P(0),
			SubmissionRetry: retry.ConfigWithMax{
				MaxAttempts: confutil.P(0),
			},
		},
	}

	mocks := baseMocks(t)

	var dbClose func()
	var p persistence.Persistence
	if realDB {
		var err error
		p, dbClose, err = persistence.NewUnitTestPersistence(ctx)
		require.NoError(t, err)
	} else {
		mp, err := mockpersistence.NewSQLMockProvider()
		require.NoError(t, err)
		p = mp.P
		mocks.db = mp.Mock
		dbClose = func() {}
	}
	mocks.allComponents.On("Persistence").Return(p).Maybe()

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

	return ctx, pmgr, mocks, func() {
		pmgr.Stop()
		dbClose()
	}
}

func TestNewEngineErrors(t *testing.T) {
	mocks := baseMocks(t)

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
	_, _, _, done := NewTestPublicTxManager(t, false)
	defer done()
}

func TestSingleTransactionSubmitRealDB(t *testing.T) {
	ctx, ble, m, done := NewTestPublicTxManager(t, true)
	defer done()

	err := ble.Start()
	require.NoError(t, err)

	// resolve key failure
	m.keyManager.On("ResolveKey", ctx, "signer1", algorithms.ECDSA_SECP256K1_PLAINBYTES).Return("", "", fmt.Errorf("resolve err")).Once()
	_, err = ble.SingleTransactionSubmit(ctx, &components.PublicTxSubmission{
		PublicTxInput: ptxapi.PublicTxInput{
			From: "signer1",
		},
	})
	assert.Regexp(t, "resolve err", err)

	resolvedKey := tktypes.EthAddress(tktypes.RandBytes(20))
	m.keyManager.On("ResolveKey", ctx, "signer1", algorithms.ECDSA_SECP256K1_PLAINBYTES).Return("keyhandle1", resolvedKey.String(), nil)

	// estimation failure - for non-revert
	m.ethClient.On("EstimateGasNoResolve", mock.Anything, mock.Anything, mock.Anything).
		Return(ethclient.EstimateGasResult{}, fmt.Errorf("GasEstimate error")).Once()
	_, err = ble.SingleTransactionSubmit(ctx, &components.PublicTxSubmission{
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

	// create transaction succeeded
	// gas estimate should be cached
	m.ethClient.On("EstimateGasNoResolve", mock.Anything, mock.Anything, mock.Anything).
		Return(ethclient.EstimateGasResult{GasLimit: tktypes.HexUint64(10)}, nil)
	m.ethClient.On("GetTransactionCount", mock.Anything, mock.Anything).
		Return(confutil.P(tktypes.HexUint64(1)), nil).Once()
	_, err = ble.SingleTransactionSubmit(ctx, &components.PublicTxSubmission{
		PublicTxInput: ptxapi.PublicTxInput{
			From: "signer1",
		},
	})
	assert.NoError(t, err)

	// TODO: Query status

}

func TestAddActivityDisabled(t *testing.T) {
	_, ble, _, done := NewTestPublicTxManager(t, false, func(mocks *dependencyMocks, conf *Config) {
		conf.Manager.ActivityRecords.RecordsPerTransaction = confutil.P(0)
	})
	defer done()

	ble.addActivityRecord("signer1:nonce", "message")

	assert.Empty(t, ble.getActivityRecords("signer1:nonce"))
}

func TestAddActivityWrap(t *testing.T) {
	_, ble, _, done := NewTestPublicTxManager(t, false)
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

// func TestHandleNewTransactionTransferOnlyWithProvideGas(t *testing.T) {
// 	ctx := context.Background()
// 	ble, _ := NewTestPublicTxManager(t)
// 	mTS := componentmocks.NewPublicTransactionStore(t)
// 	mBI := componentmocks.NewBlockIndexer(t)
// 	mEN := componentmocks.NewPublicTxEventNotifier(t)
// 	mEC := componentmocks.NewEthClient(t)
// 	mKM := componentmocks.NewKeyManager(t)
// 	mKM.On("ResolveKey", ctx, testAutoFuelingSourceAddress, algorithms.ECDSA_SECP256K1_PLAINBYTES).Return("", testAutoFuelingSourceAddress, nil)
// 	// fall back to connector when get call failed
// 	ble.gasPriceClient = NewTestNodeGasPriceClient(t, mEC)
// 	ble.Init(ctx, mEC, mKM, mTS, mEN, mBI)
// 	testEthTxInput := &ethsigner.Transaction{
// 		From:     []byte(testAutoFuelingSourceAddress),
// 		To:       ethtypes.MustNewAddress(testDestAddress),
// 		GasLimit: tktypes.Uint64ToUint256(1223451),
// 		Value:    tktypes.Uint64ToUint256(100),
// 	}
// 	// create transaction succeeded
// 	// gas estimate should be cached
// 	insertMock := mTS.On("InsertTransaction", ctx, mock.Anything, mock.Anything)
// 	mEC.On("GetTransactionCount", mock.Anything, mock.Anything).
// 		Return(confutil.P(ethtypes.HexUint64(1)), nil).Once()
// 	insertMock.Run(func(args mock.Arguments) {
// 		mtx := args[2].(*ptxapi.PublicTx)
// 		assert.Equal(t, "1223451", mtx.GasLimit.BigInt().String())
// 		assert.Nil(t, mtx.GasPrice)
// 		insertMock.Return(nil)
// 	}).Once()
// 	txID := uuid.New()
// 	mTS.On("UpdateSubStatus", ctx, txID.String(), PubTxSubStatusReceived, BaseTxActionAssignNonce, mock.Anything, mock.Anything, mock.Anything).Return(nil)

// 	_, _, err := ble.HandleNewTransaction(ctx, &components.RequestOptions{
// 		ID:       &txID,
// 		SignerID: string(testEthTxInput.From),
// 		GasLimit: testEthTxInput.GasLimit,
// 	}, &components.EthTransfer{
// 		To:    *tktypes.MustEthAddress(testEthTxInput.To.String()),
// 		Value: testEthTxInput.Value,
// 	})
// 	require.NoError(t, err)
// 	mEC.AssertNotCalled(t, "GasEstimate")
// }

// func TestHandleNewTransactionTransferAndInvalidType(t *testing.T) {
// 	ctx := context.Background()
// 	ble, _ := NewTestPublicTxManager(t)
// 	ble.gasPriceClient = NewTestZeroGasPriceChainClient(t)
// 	mTS := componentmocks.NewPublicTransactionStore(t)
// 	mBI := componentmocks.NewBlockIndexer(t)
// 	mEN := componentmocks.NewPublicTxEventNotifier(t)
// 	mEC := componentmocks.NewEthClient(t)
// 	mKM := componentmocks.NewKeyManager(t)
// 	mKM.On("ResolveKey", ctx, testAutoFuelingSourceAddress, algorithms.ECDSA_SECP256K1_PLAINBYTES).Return("", testAutoFuelingSourceAddress, nil)
// 	ble.Init(ctx, mEC, mKM, mTS, mEN, mBI)
// 	testEthTxInput := &ethsigner.Transaction{
// 		From:     []byte(testAutoFuelingSourceAddress),
// 		To:       ethtypes.MustNewAddress(testDestAddress),
// 		GasLimit: tktypes.Uint64ToUint256(1223451),
// 		Value:    tktypes.Uint64ToUint256(100),
// 	}
// 	// create transaction succeeded
// 	// gas estimate should be cached
// 	insertMock := mTS.On("InsertTransaction", ctx, mock.Anything, mock.Anything)
// 	mEC.On("GetTransactionCount", mock.Anything, mock.Anything).
// 		Return(confutil.P(ethtypes.HexUint64(1)), nil).Once()
// 	insertMock.Run(func(args mock.Arguments) {
// 		mtx := args[2].(*ptxapi.PublicTx)
// 		assert.Equal(t, "1223451", mtx.GasLimit.BigInt().String())
// 		assert.Equal(t, "0", mtx.GasPrice.BigInt().String())
// 		insertMock.Return(nil)
// 	}).Once()
// 	txID := uuid.New()
// 	mTS.On("UpdateSubStatus", ctx, txID.String(), PubTxSubStatusReceived, BaseTxActionAssignNonce, mock.Anything, mock.Anything, mock.Anything).Return(nil)

// 	_, _, err := ble.HandleNewTransaction(ctx, &components.RequestOptions{
// 		ID:       &txID,
// 		SignerID: string(testEthTxInput.From),
// 		GasLimit: testEthTxInput.GasLimit,
// 	}, &components.EthTransfer{
// 		To:    *tktypes.MustEthAddress(testEthTxInput.To.String()),
// 		Value: testEthTxInput.Value,
// 	})
// 	require.NoError(t, err)
// 	mEC.AssertNotCalled(t, "GasEstimate")

// 	_, submissionRejected, err := ble.HandleNewTransaction(ctx, &components.RequestOptions{
// 		ID:       &txID,
// 		SignerID: string(testEthTxInput.From),
// 		GasLimit: testEthTxInput.GasLimit,
// 	}, "not a valid object")
// 	assert.Regexp(t, "PD011929", err)
// 	assert.True(t, submissionRejected)
// 	mEC.AssertNotCalled(t, "GasEstimate")
// }

// func TestHandleNewTransaction(t *testing.T) {
// 	ctx := context.Background()
// 	ble, _ := NewTestPublicTxManager(t)
// 	ble.gasPriceClient = NewTestFixedPriceGasPriceClient(t)
// 	mTS := componentmocks.NewPublicTransactionStore(t)
// 	mBI := componentmocks.NewBlockIndexer(t)
// 	mEN := componentmocks.NewPublicTxEventNotifier(t)
// 	mEC := componentmocks.NewEthClient(t)
// 	mKM := componentmocks.NewKeyManager(t)
// 	mKM.On("ResolveKey", ctx, testDestAddress, algorithms.ECDSA_SECP256K1_PLAINBYTES).Return("", testDestAddress, nil)
// 	ble.Init(ctx, mEC, mKM, mTS, mEN, mBI)
// 	testEthTxInput := &ethsigner.Transaction{
// 		From:  []byte(testMainSigningAddress),
// 		To:    ethtypes.MustNewAddress(testDestAddress),
// 		Value: tktypes.Uint64ToUint256(100),
// 		Data:  ethtypes.MustNewHexBytes0xPrefix(""),
// 	}
// 	// missing transaction ID
// 	_, submissionRejected, err := ble.HandleNewTransaction(ctx, &components.RequestOptions{
// 		SignerID: string(testEthTxInput.From),
// 		GasLimit: testEthTxInput.GasLimit,
// 	}, &components.EthTransaction{
// 		To:          *tktypes.MustEthAddress(testEthTxInput.To.String()),
// 		FunctionABI: &abi.Entry{},
// 		Inputs:      &abi.ComponentValue{},
// 	})
// 	assert.NotNil(t, err)
// 	assert.True(t, submissionRejected)
// 	assert.Regexp(t, "PD011910", err)

// 	txID := uuid.New()
// 	// Parse API failure
// 	mEC.On("ABIFunction", ctx, mock.Anything).Return(nil, fmt.Errorf("ABI function parsing error")).Once()
// 	_, submissionRejected, err = ble.HandleNewTransaction(ctx, &components.RequestOptions{
// 		ID:       &txID,
// 		SignerID: string(testEthTxInput.From),
// 		GasLimit: testEthTxInput.GasLimit,
// 	}, &components.EthTransaction{
// 		To:          *tktypes.MustEthAddress(testEthTxInput.To.String()),
// 		FunctionABI: nil,
// 		Inputs:      nil,
// 	})
// 	assert.NotNil(t, err)
// 	assert.False(t, submissionRejected)
// 	assert.Regexp(t, "ABI function parsing error", err)

// 	// Build call data failure
// 	mABIBuilder := componentmocks.NewABIFunctionRequestBuilder(t)
// 	mABIBuilder.On("BuildCallData").Return(fmt.Errorf("Build data error")).Once()
// 	mABIF := componentmocks.NewABIFunctionClient(t)
// 	mABIF.On("R", ctx).Return(mABIBuilder).Once()
// 	mABIBuilder.On("To", ethtypes.MustNewAddress(testEthTxInput.To.String())).Return(mABIBuilder).Once()
// 	mABIBuilder.On("Input", mock.Anything).Return(mABIBuilder).Once()
// 	mEC.On("ABIFunction", ctx, mock.Anything).Return(mABIF, nil).Once()
// 	_, submissionRejected, err = ble.HandleNewTransaction(ctx, &components.RequestOptions{
// 		ID:       &txID,
// 		SignerID: string(testEthTxInput.From),
// 		GasLimit: testEthTxInput.GasLimit,
// 	}, &components.EthTransaction{
// 		To:          *tktypes.MustEthAddress(testEthTxInput.To.String()),
// 		FunctionABI: nil,
// 		Inputs:      nil,
// 	})
// 	assert.NotNil(t, err)
// 	assert.False(t, submissionRejected)
// 	assert.Regexp(t, "Build data error", err)

// 	// Gas estimate failure - non-revert
// 	mEC.On("GasEstimate", mock.Anything, testEthTxInput, mock.Anything).Return(nil, fmt.Errorf("something else")).Once()
// 	mABIBuilder.On("BuildCallData").Return(nil).Once()
// 	mABIF.On("R", ctx).Return(mABIBuilder).Once()
// 	mABIBuilder.On("To", ethtypes.MustNewAddress(testEthTxInput.To.String())).Return(mABIBuilder).Once()
// 	mABIBuilder.On("Input", mock.Anything).Return(mABIBuilder).Once()
// 	mABIBuilder.On("TX", mock.Anything).Return(testEthTxInput).Once()
// 	mEC.On("ABIFunction", ctx, mock.Anything).Return(mABIF, nil).Once()
// 	_, submissionRejected, err = ble.HandleNewTransaction(ctx, &components.RequestOptions{
// 		ID:       &txID,
// 		SignerID: string(testEthTxInput.From),
// 		GasLimit: testEthTxInput.GasLimit,
// 	}, &components.EthTransaction{
// 		To:          *tktypes.MustEthAddress(testEthTxInput.To.String()),
// 		FunctionABI: nil,
// 		Inputs:      nil,
// 	})
// 	assert.NotNil(t, err)
// 	assert.False(t, submissionRejected)
// 	assert.Regexp(t, "something else", err)

// 	// Gas estimate failure - revert
// 	mEC.On("GasEstimate", mock.Anything, testEthTxInput, mock.Anything).Return(nil, fmt.Errorf("execution reverted")).Once()
// 	mABIBuilder.On("BuildCallData").Return(nil).Once()
// 	mABIF.On("R", ctx).Return(mABIBuilder).Once()
// 	mABIBuilder.On("To", ethtypes.MustNewAddress(testEthTxInput.To.String())).Return(mABIBuilder).Once()
// 	mABIBuilder.On("Input", mock.Anything).Return(mABIBuilder).Once()
// 	mABIBuilder.On("TX", mock.Anything).Return(testEthTxInput).Once()
// 	mEC.On("ABIFunction", ctx, mock.Anything).Return(mABIF, nil).Once()
// 	_, submissionRejected, err = ble.HandleNewTransaction(ctx, &components.RequestOptions{
// 		ID:       &txID,
// 		SignerID: string(testEthTxInput.From),
// 		GasLimit: testEthTxInput.GasLimit,
// 	}, &components.EthTransaction{
// 		To:          *tktypes.MustEthAddress(testEthTxInput.To.String()),
// 		FunctionABI: nil,
// 		Inputs:      nil,
// 	})
// 	assert.NotNil(t, err)
// 	assert.True(t, submissionRejected)
// 	assert.Regexp(t, "execution reverted", err)

// 	// create transaction succeeded
// 	mEC.On("GasEstimate", mock.Anything, testEthTxInput, mock.Anything).Return(tktypes.Uint64ToUint256(200), nil).Once()
// 	mABIBuilder.On("BuildCallData").Return(nil).Once()
// 	mABIF.On("R", ctx).Return(mABIBuilder).Once()
// 	mABIBuilder.On("To", ethtypes.MustNewAddress(testEthTxInput.To.String())).Return(mABIBuilder).Once()
// 	mABIBuilder.On("Input", mock.Anything).Return(mABIBuilder).Once()
// 	mABIBuilder.On("TX", mock.Anything).Return(testEthTxInput).Once()
// 	mEC.On("ABIFunction", ctx, mock.Anything).Return(mABIF, nil).Once()
// 	insertMock := mTS.On("InsertTransaction", ctx, mock.Anything, mock.Anything)
// 	mEC.On("GetTransactionCount", mock.Anything, mock.Anything).
// 		Return(confutil.P(ethtypes.HexUint64(1)), nil).Once()
// 	insertMock.Run(func(args mock.Arguments) {
// 		mtx := args[2].(*ptxapi.PublicTx)
// 		assert.Equal(t, big.NewInt(200), mtx.GasLimit.BigInt())
// 		insertMock.Return(nil)
// 	}).Once()
// 	mTS.On("UpdateSubStatus", ctx, txID.String(), PubTxSubStatusReceived, BaseTxActionAssignNonce, mock.Anything, mock.Anything, mock.Anything).Return(nil)
// 	_, _, err = ble.HandleNewTransaction(ctx, &components.RequestOptions{
// 		ID:       &txID,
// 		SignerID: string(testEthTxInput.From),
// 		GasLimit: testEthTxInput.GasLimit,
// 	}, &components.EthTransaction{
// 		To:          *tktypes.MustEthAddress(testEthTxInput.To.String()),
// 		FunctionABI: nil,
// 		Inputs:      nil,
// 	})
// 	require.NoError(t, err)
// }

// func TestHandleNewDeployment(t *testing.T) {
// 	ctx := context.Background()
// 	ble, _ := NewTestPublicTxManager(t)
// 	ble.gasPriceClient = NewTestFixedPriceGasPriceClient(t)
// 	mTS := componentmocks.NewPublicTransactionStore(t)
// 	mBI := componentmocks.NewBlockIndexer(t)
// 	mEN := componentmocks.NewPublicTxEventNotifier(t)
// 	mEC := componentmocks.NewEthClient(t)
// 	mKM := componentmocks.NewKeyManager(t)
// 	mKM.On("ResolveKey", ctx, testDestAddress, algorithms.ECDSA_SECP256K1_PLAINBYTES).Return("", testDestAddress, nil)
// 	ble.Init(ctx, mEC, mKM, mTS, mEN, mBI)
// 	testEthTxInput := &ethsigner.Transaction{
// 		From: []byte(testMainSigningAddress),
// 		Data: ethtypes.MustNewHexBytes0xPrefix(""),
// 	}
// 	txID := uuid.New()
// 	// Parse API failure
// 	mEC.On("ABIConstructor", ctx, mock.Anything, mock.Anything).Return(nil, fmt.Errorf("ABI function parsing error")).Once()
// 	_, submissionRejected, err := ble.HandleNewTransaction(ctx, &components.RequestOptions{
// 		ID:       &txID,
// 		SignerID: string(testEthTxInput.From),
// 		GasLimit: testEthTxInput.GasLimit,
// 	}, &components.EthDeployTransaction{
// 		ConstructorABI: nil,
// 		Bytecode:       nil,
// 		Inputs:         nil,
// 	})
// 	assert.NotNil(t, err)
// 	assert.False(t, submissionRejected)
// 	assert.Regexp(t, "ABI function parsing error", err)

// 	// Build call data failure
// 	mABIBuilder := componentmocks.NewABIFunctionRequestBuilder(t)
// 	mABIBuilder.On("BuildCallData").Return(fmt.Errorf("Build data error")).Once()
// 	mABIF := componentmocks.NewABIFunctionClient(t)
// 	mABIF.On("R", ctx).Return(mABIBuilder).Once()
// 	mABIBuilder.On("Input", mock.Anything).Return(mABIBuilder).Once()
// 	mEC.On("ABIConstructor", ctx, mock.Anything, mock.Anything).Return(mABIF, nil).Once()
// 	_, submissionRejected, err = ble.HandleNewTransaction(ctx, &components.RequestOptions{
// 		ID:       &txID,
// 		SignerID: string(testEthTxInput.From),
// 		GasLimit: testEthTxInput.GasLimit,
// 	}, &components.EthDeployTransaction{
// 		ConstructorABI: nil,
// 		Bytecode:       tktypes.HexBytes(testTransactionData),
// 		Inputs:         nil,
// 	})
// 	assert.NotNil(t, err)
// 	assert.False(t, submissionRejected)
// 	assert.Regexp(t, "Build data error", err)

// 	// Gas estimate failure - non-revert
// 	mEC.On("GasEstimate", mock.Anything, testEthTxInput, mock.Anything).Return(nil, fmt.Errorf("something else")).Once()
// 	mABIBuilder.On("BuildCallData").Return(nil).Once()
// 	mABIF.On("R", ctx).Return(mABIBuilder).Once()
// 	mABIBuilder.On("Input", mock.Anything).Return(mABIBuilder).Once()
// 	mABIBuilder.On("TX", mock.Anything).Return(testEthTxInput).Once()
// 	mEC.On("ABIConstructor", ctx, mock.Anything, mock.Anything).Return(mABIF, nil).Once()
// 	_, submissionRejected, err = ble.HandleNewTransaction(ctx, &components.RequestOptions{
// 		ID:       &txID,
// 		SignerID: string(testEthTxInput.From),
// 		GasLimit: testEthTxInput.GasLimit,
// 	}, &components.EthDeployTransaction{
// 		ConstructorABI: nil,
// 		Bytecode:       tktypes.HexBytes(testTransactionData),
// 		Inputs:         nil,
// 	})
// 	assert.NotNil(t, err)
// 	assert.False(t, submissionRejected)
// 	assert.Regexp(t, "something else", err)

// 	// Gas estimate failure - revert
// 	mEC.On("GasEstimate", mock.Anything, testEthTxInput, mock.Anything).Return(nil, fmt.Errorf("execution reverted")).Once()
// 	mABIBuilder.On("BuildCallData").Return(nil).Once()
// 	mABIF.On("R", ctx).Return(mABIBuilder).Once()
// 	mABIBuilder.On("Input", mock.Anything).Return(mABIBuilder).Once()
// 	mABIBuilder.On("TX", mock.Anything).Return(testEthTxInput).Once()
// 	mEC.On("ABIConstructor", ctx, mock.Anything, mock.Anything).Return(mABIF, nil).Once()
// 	_, submissionRejected, err = ble.HandleNewTransaction(ctx, &components.RequestOptions{
// 		ID:       &txID,
// 		SignerID: string(testEthTxInput.From),
// 		GasLimit: testEthTxInput.GasLimit,
// 	}, &components.EthDeployTransaction{
// 		ConstructorABI: nil,
// 		Bytecode:       tktypes.HexBytes(testTransactionData),
// 		Inputs:         nil,
// 	})
// 	assert.NotNil(t, err)
// 	assert.True(t, submissionRejected)
// 	assert.Regexp(t, "execution reverted", err)

// 	// create transaction succeeded
// 	mEC.On("GasEstimate", mock.Anything, testEthTxInput, mock.Anything).Return(tktypes.Uint64ToUint256(200), nil).Once()
// 	mABIBuilder.On("BuildCallData").Return(nil).Once()
// 	mABIF.On("R", ctx).Return(mABIBuilder).Once()
// 	mABIBuilder.On("Input", mock.Anything).Return(mABIBuilder).Once()
// 	mABIBuilder.On("TX", mock.Anything).Return(testEthTxInput).Once()
// 	mEC.On("ABIConstructor", ctx, mock.Anything, mock.Anything).Return(mABIF, nil).Once()
// 	insertMock := mTS.On("InsertTransaction", ctx, mock.Anything, mock.Anything)
// 	mEC.On("GetTransactionCount", mock.Anything, mock.Anything).
// 		Return(confutil.P(ethtypes.HexUint64(1)), nil).Once()
// 	insertMock.Run(func(args mock.Arguments) {
// 		mtx := args[2].(*ptxapi.PublicTx)
// 		assert.Equal(t, big.NewInt(200), mtx.GasLimit.BigInt())
// 		insertMock.Return(nil)
// 	}).Once()
// 	mTS.On("UpdateSubStatus", ctx, txID.String(), PubTxSubStatusReceived, BaseTxActionAssignNonce, mock.Anything, mock.Anything, mock.Anything).Return(nil)
// 	_, _, err = ble.HandleNewTransaction(ctx, &components.RequestOptions{
// 		ID:       &txID,
// 		SignerID: string(testEthTxInput.From),
// 		GasLimit: testEthTxInput.GasLimit,
// 	}, &components.EthDeployTransaction{
// 		ConstructorABI: nil,
// 		Bytecode:       tktypes.HexBytes(testTransactionData),
// 		Inputs:         nil,
// 	})
// 	require.NoError(t, err)
// }

// func TestEngineSuspend(t *testing.T) {
// 	ctx := context.Background()
// 	ble, _ := NewTestPublicTxManager(t)
// 	ble.gasPriceClient = NewTestFixedPriceGasPriceClient(t)

// 	mTS := componentmocks.NewPublicTransactionStore(t)
// 	mBI := componentmocks.NewBlockIndexer(t)
// 	mEN := componentmocks.NewPublicTxEventNotifier(t)

// 	mEC := componentmocks.NewEthClient(t)
// 	mKM := componentmocks.NewKeyManager(t)
// 	ble.Init(ctx, mEC, mKM, mTS, mEN, mBI)

// 	imtxs := NewTestInMemoryTxState(t)
// 	mtx := imtxs.GetTx()

// 	// errored
// 	mTS.On("GetTransactionByID", ctx, mtx.ID.String()).Return(nil, fmt.Errorf("get error")).Once()
// 	_, err := ble.HandleSuspendTransaction(ctx, mtx.ID.String())
// 	assert.Regexp(t, "get error", err)

// 	// engine update error
// 	suspendedStatus := PubTxStatusSuspended
// 	mTS.On("GetTransactionByID", ctx, mtx.ID.String()).Return(mtx, nil).Once()
// 	mTS.On("UpdateTransaction", ctx, mtx.ID.String(), &BaseTXUpdates{
// 		Status: &suspendedStatus,
// 	}).Return(fmt.Errorf("update error")).Once()
// 	_, err = ble.HandleSuspendTransaction(ctx, mtx.ID.String())
// 	assert.Regexp(t, "update error", err)

// 	// engine update success
// 	mtx.Status = PubTxStatusPending
// 	mTS.On("GetTransactionByID", ctx, mtx.ID.String()).Return(mtx, nil).Once()
// 	mTS.On("UpdateTransaction", ctx, mtx.ID.String(), &BaseTXUpdates{
// 		Status: &suspendedStatus,
// 	}).Return(nil).Once()
// 	tx, err := ble.HandleSuspendTransaction(ctx, mtx.ID.String())
// 	require.NoError(t, err)
// 	assert.Equal(t, suspendedStatus, tx.Status)

// 	// orchestrator handler tests
// 	ble.InFlightOrchestrators = make(map[string]*orchestrator)
// 	ble.InFlightOrchestrators[string(mtx.From)] = &orchestrator{
// 		pubTxManager:                 ble,
// 		orchestratorPollingInterval:  ble.enginePollingInterval,
// 		state:                        OrchestratorStateIdle,
// 		stateEntryTime:               time.Now().Add(-ble.maxOrchestratorIdle).Add(-1 * time.Minute),
// 		InFlightTxsStale:             make(chan bool, 1),
// 		stopProcess:                  make(chan bool, 1),
// 		transactionIDsInStatusUpdate: []string{"randomID"},
// 		txStore:                      mTS,
// 		ethClient:                    mEC,
// 		publicTXEventNotifier:        mEN,
// 		bIndexer:                     mBI,
// 	}
// 	// orchestrator update error
// 	mTS.On("GetTransactionByID", ctx, mtx.ID.String()).Return(mtx, nil).Once()
// 	mTS.On("UpdateTransaction", ctx, mtx.ID.String(), &BaseTXUpdates{
// 		Status: &suspendedStatus,
// 	}).Return(fmt.Errorf("update error")).Once()
// 	_, err = ble.HandleSuspendTransaction(ctx, mtx.ID.String())
// 	assert.Regexp(t, "update error", err)

// 	// orchestrator update success
// 	mtx.Status = PubTxStatusPending
// 	mTS.On("GetTransactionByID", ctx, mtx.ID.String()).Return(mtx, nil).Once()
// 	mTS.On("UpdateTransaction", ctx, mtx.ID.String(), &BaseTXUpdates{
// 		Status: &suspendedStatus,
// 	}).Return(nil).Once()
// 	tx, err = ble.HandleSuspendTransaction(ctx, mtx.ID.String())
// 	require.NoError(t, err)
// 	assert.Equal(t, suspendedStatus, tx.Status)

// 	// in flight tx test
// 	testInFlightTransactionStateManagerWithMocks := NewTestInFlightTransactionWithMocks(t)
// 	it := testInFlightTransactionStateManagerWithMocks.it
// 	mtx = it.stateManager.GetTx()
// 	ble.InFlightOrchestrators[string(mtx.From)].InFlightTxs = []*InFlightTransactionStageController{
// 		it,
// 	}

// 	// async status update queued
// 	mtx.Status = PubTxStatusPending
// 	mTS.On("GetTransactionByID", ctx, mtx.ID.String()).Return(mtx, nil).Once()
// 	tx, err = ble.HandleSuspendTransaction(ctx, mtx.ID.String())
// 	require.NoError(t, err)
// 	assert.Equal(t, PubTxStatusPending, tx.Status)

// 	// already on the target status
// 	mtx.Status = PubTxStatusSuspended
// 	mTS.On("GetTransactionByID", ctx, mtx.ID.String()).Return(mtx, nil).Once()
// 	tx, err = ble.HandleSuspendTransaction(ctx, mtx.ID.String())
// 	require.NoError(t, err)
// 	assert.Equal(t, PubTxStatusSuspended, tx.Status)

// 	// error when try to update the status of a completed tx
// 	mtx.Status = PubTxStatusFailed
// 	mTS.On("GetTransactionByID", ctx, mtx.ID.String()).Return(mtx, nil).Once()
// 	_, err = ble.HandleSuspendTransaction(ctx, mtx.ID.String())
// 	assert.Regexp(t, "PD011921", err)
// }

// func TestEngineResume(t *testing.T) {
// 	ctx := context.Background()

// 	ble, _ := NewTestPublicTxManager(t)
// 	ble.gasPriceClient = NewTestFixedPriceGasPriceClient(t)

// 	mTS := componentmocks.NewPublicTransactionStore(t)
// 	mBI := componentmocks.NewBlockIndexer(t)
// 	mEN := componentmocks.NewPublicTxEventNotifier(t)

// 	mEC := componentmocks.NewEthClient(t)
// 	mKM := componentmocks.NewKeyManager(t)
// 	ble.Init(ctx, mEC, mKM, mTS, mEN, mBI)

// 	imtxs := NewTestInMemoryTxState(t)
// 	mtx := imtxs.GetTx()

// 	// errored
// 	mTS.On("GetTransactionByID", ctx, mtx.ID.String()).Return(nil, fmt.Errorf("get error")).Once()
// 	_, err := ble.HandleResumeTransaction(ctx, mtx.ID.String())
// 	assert.Regexp(t, "get error", err)

// 	// engine update error
// 	pendingStatus := PubTxStatusPending
// 	mTS.On("GetTransactionByID", ctx, mtx.ID.String()).Return(mtx, nil).Once()
// 	mTS.On("UpdateTransaction", ctx, mtx.ID.String(), &BaseTXUpdates{
// 		Status: &pendingStatus,
// 	}).Return(fmt.Errorf("update error")).Once()
// 	_, err = ble.HandleResumeTransaction(ctx, mtx.ID.String())
// 	assert.Regexp(t, "update error", err)

// 	// engine update success
// 	mtx.Status = PubTxStatusSuspended
// 	mTS.On("GetTransactionByID", ctx, mtx.ID.String()).Return(mtx, nil).Once()
// 	mTS.On("UpdateTransaction", ctx, mtx.ID.String(), &BaseTXUpdates{
// 		Status: &pendingStatus,
// 	}).Return(nil).Once()
// 	tx, err := ble.HandleResumeTransaction(ctx, mtx.ID.String())
// 	require.NoError(t, err)
// 	assert.Equal(t, pendingStatus, tx.Status)

// 	// orchestrator handler tests
// 	ble.InFlightOrchestrators = make(map[string]*orchestrator)
// 	ble.InFlightOrchestrators[string(mtx.From)] = &orchestrator{
// 		pubTxManager:                 ble,
// 		orchestratorPollingInterval:  ble.enginePollingInterval,
// 		state:                        OrchestratorStateIdle,
// 		stateEntryTime:               time.Now().Add(-ble.maxOrchestratorIdle).Add(-1 * time.Minute),
// 		InFlightTxsStale:             make(chan bool, 1),
// 		stopProcess:                  make(chan bool, 1),
// 		transactionIDsInStatusUpdate: []string{"randomID"},
// 		txStore:                      mTS,
// 		ethClient:                    mEC,
// 		publicTXEventNotifier:        mEN,
// 		bIndexer:                     mBI,
// 	}
// 	// orchestrator update error
// 	mTS.On("GetTransactionByID", ctx, mtx.ID.String()).Return(mtx, nil).Once()
// 	mTS.On("UpdateTransaction", ctx, mtx.ID.String(), &BaseTXUpdates{
// 		Status: &pendingStatus,
// 	}).Return(fmt.Errorf("update error")).Once()
// 	_, err = ble.HandleResumeTransaction(ctx, mtx.ID.String())
// 	assert.Regexp(t, "update error", err)

// 	// orchestrator update success
// 	mtx.Status = PubTxStatusSuspended
// 	mTS.On("GetTransactionByID", ctx, mtx.ID.String()).Return(mtx, nil).Once()
// 	mTS.On("UpdateTransaction", ctx, mtx.ID.String(), &BaseTXUpdates{
// 		Status: &pendingStatus,
// 	}).Return(nil).Once()
// 	tx, err = ble.HandleResumeTransaction(ctx, mtx.ID.String())
// 	require.NoError(t, err)
// 	assert.Equal(t, pendingStatus, tx.Status)

// 	// in flight tx test
// 	testInFlightTransactionStateManagerWithMocks := NewTestInFlightTransactionWithMocks(t)
// 	it := testInFlightTransactionStateManagerWithMocks.it
// 	mtx = it.stateManager.GetTx()
// 	ble.InFlightOrchestrators[string(mtx.From)].InFlightTxs = []*InFlightTransactionStageController{
// 		it,
// 	}

// 	// async status update queued
// 	mtx.Status = PubTxStatusSuspended
// 	mTS.On("GetTransactionByID", ctx, mtx.ID.String()).Return(mtx, nil).Once()
// 	tx, err = ble.HandleResumeTransaction(ctx, mtx.ID.String())
// 	require.NoError(t, err)
// 	assert.Equal(t, PubTxStatusSuspended, tx.Status)

// 	// already on the target status
// 	mtx.Status = PubTxStatusPending
// 	mTS.On("GetTransactionByID", ctx, mtx.ID.String()).Return(mtx, nil).Once()
// 	tx, err = ble.HandleResumeTransaction(ctx, mtx.ID.String())
// 	require.NoError(t, err)
// 	assert.Equal(t, PubTxStatusPending, tx.Status)

// 	// error when try to update the status of a completed tx
// 	mtx.Status = PubTxStatusFailed
// 	mTS.On("GetTransactionByID", ctx, mtx.ID.String()).Return(mtx, nil).Once()
// 	_, err = ble.HandleResumeTransaction(ctx, mtx.ID.String())
// 	assert.Regexp(t, "PD011921", err)
// }

// func TestEngineCanceledContext(t *testing.T) {
// 	ctx, cancelCtx := context.WithCancel(context.Background())

// 	ble, _ := NewTestPublicTxManager(t)
// 	ble.gasPriceClient = NewTestFixedPriceGasPriceClient(t)

// 	mTS := componentmocks.NewPublicTransactionStore(t)
// 	mBI := componentmocks.NewBlockIndexer(t)
// 	mEN := componentmocks.NewPublicTxEventNotifier(t)

// 	mEC := componentmocks.NewEthClient(t)
// 	mKM := componentmocks.NewKeyManager(t)
// 	ble.Init(ctx, mEC, mKM, mTS, mEN, mBI)

// 	imtxs := NewTestInMemoryTxState(t)
// 	mtx := imtxs.GetTx()
// 	mTS.On("UpdateTransaction", ctx, mtx.ID.String(), mock.Anything).Return(nil).Maybe()

// 	// Suspend
// 	mTS.On("GetTransactionByID", ctx, mtx.ID.String()).Return(mtx, nil).Run(func(args mock.Arguments) {
// 		cancelCtx()
// 	}).Once()
// 	_, err := ble.HandleSuspendTransaction(ctx, mtx.ID.String())
// 	assert.Regexp(t, "PD011926", err)

// 	// Resume
// 	mTS.On("GetTransactionByID", ctx, mtx.ID.String()).Return(mtx, nil).Run(func(args mock.Arguments) {
// 		cancelCtx()
// 	}).Once()
// 	_, err = ble.HandleResumeTransaction(ctx, mtx.ID.String())
// 	assert.Regexp(t, "PD011926", err)
// }

// func TestEngineHandleConfirmedTransactionEvents(t *testing.T) {
// 	ctx, cancelCtx := context.WithCancel(context.Background())

// 	ble, _ := NewTestPublicTxManager(t)
// 	ble.gasPriceClient = NewTestFixedPriceGasPriceClient(t)

// 	mTS := componentmocks.NewPublicTransactionStore(t)
// 	mBI := componentmocks.NewBlockIndexer(t)
// 	mEN := componentmocks.NewPublicTxEventNotifier(t)

// 	mEC := componentmocks.NewEthClient(t)
// 	mKM := componentmocks.NewKeyManager(t)
// 	ble.Init(ctx, mEC, mKM, mTS, mEN, mBI)

// 	imtxs := NewTestInMemoryTxState(t)
// 	mtx := imtxs.GetTx()

// 	mockManagedTx0 := &ptxapi.PublicTx{
// 		Transaction: &ethsigner.Transaction{
// 			From:  json.RawMessage(string(mtx.From)),
// 			Nonce: tktypes.Uint64ToUint256(4),
// 		},
// 	}
// 	mockManagedTx1 := &ptxapi.PublicTx{
// 		Transaction: &ethsigner.Transaction{
// 			From:  json.RawMessage(string(mtx.From)),
// 			Nonce: tktypes.Uint64ToUint256(5),
// 		},
// 	}
// 	mockManagedTx2 := &ptxapi.PublicTx{
// 		Transaction: &ethsigner.Transaction{
// 			From:  json.RawMessage("0x12345f6e918321dd47c86e7a077b4ab0e7411234"),
// 			Nonce: tktypes.Uint64ToUint256(6),
// 		},
// 	}
// 	mockManagedTx3 := &ptxapi.PublicTx{
// 		Transaction: &ethsigner.Transaction{
// 			From:  json.RawMessage("0x43215f6e918321dd47c86e7a077b4ab0e7414321"),
// 			Nonce: tktypes.Uint64ToUint256(7),
// 		},
// 	}

// 	ble.InFlightOrchestrators = make(map[string]*orchestrator)
// 	ble.InFlightOrchestrators[string(mtx.From)] = &orchestrator{
// 		pubTxManager:                 ble,
// 		orchestratorPollingInterval:  ble.enginePollingInterval,
// 		state:                        OrchestratorStateIdle,
// 		stateEntryTime:               time.Now().Add(-ble.maxOrchestratorIdle).Add(-1 * time.Minute),
// 		InFlightTxsStale:             make(chan bool, 1),
// 		stopProcess:                  make(chan bool, 1),
// 		transactionIDsInStatusUpdate: []string{"randomID"},
// 		txStore:                      mTS,
// 		ethClient:                    mEC,
// 		publicTXEventNotifier:        mEN,
// 		bIndexer:                     mBI,
// 	}
// 	// in flight tx test
// 	testInFlightTransactionStateManagerWithMocks := NewTestInFlightTransactionWithMocks(t)
// 	it := testInFlightTransactionStateManagerWithMocks.it
// 	mtx = it.stateManager.GetTx()
// 	ble.InFlightOrchestrators[string(mtx.From)].InFlightTxs = []*InFlightTransactionStageController{
// 		it,
// 	}
// 	ble.maxInFlightOrchestrators = 2
// 	ble.ctx = ctx

// 	assert.Equal(t, 1, len(ble.InFlightOrchestrators))
// 	err := ble.HandleConfirmedTransactions(ctx, []*blockindexer.IndexedTransaction{
// 		{
// 			BlockNumber:      int64(1233),
// 			TransactionIndex: int64(23),
// 			Hash:             tktypes.Bytes32Keccak([]byte("0x00001")),
// 			Result:           blockindexer.TXResult_SUCCESS.Enum(),
// 			Nonce:            mtx.Nonce.Uint64(),
// 			From:             tktypes.MustEthAddress(string(mtx.From)),
// 		},
// 		{
// 			BlockNumber:      int64(1233),
// 			TransactionIndex: int64(23),
// 			Hash:             tktypes.Bytes32Keccak([]byte("0x00002")),
// 			Result:           blockindexer.TXResult_SUCCESS.Enum(),
// 			Nonce:            mockManagedTx0.Nonce.Uint64(),
// 			From:             tktypes.MustEthAddress(string(mockManagedTx0.From)),
// 		},
// 		{
// 			BlockNumber:      int64(1233),
// 			TransactionIndex: int64(23),
// 			Hash:             tktypes.Bytes32Keccak([]byte("0x00002")),
// 			Result:           blockindexer.TXResult_SUCCESS.Enum(),
// 			Nonce:            mockManagedTx1.Nonce.Uint64(),
// 			From:             tktypes.MustEthAddress(string(mockManagedTx1.From)),
// 		},
// 		{
// 			BlockNumber:      int64(1233),
// 			TransactionIndex: int64(23),
// 			Hash:             tktypes.Bytes32Keccak([]byte("0x00002")),
// 			Result:           blockindexer.TXResult_SUCCESS.Enum(),
// 			Nonce:            mockManagedTx2.Nonce.Uint64(),
// 			From:             tktypes.MustEthAddress(string(mockManagedTx2.From)),
// 		},
// 		{
// 			BlockNumber:      int64(1233),
// 			TransactionIndex: int64(23),
// 			Hash:             tktypes.Bytes32Keccak([]byte("0x00002")),
// 			Result:           blockindexer.TXResult_SUCCESS.Enum(),
// 			Nonce:            mockManagedTx3.Nonce.Uint64(),
// 			From:             tktypes.MustEthAddress(string(mockManagedTx3.From)),
// 		},
// 	})
// 	assert.NoError(t, err)
// 	assert.Equal(t, 2, len(ble.InFlightOrchestrators))

// 	// cancel context should return with error
// 	cancelCtx()
// 	assert.Regexp(t, "PD010301", ble.HandleConfirmedTransactions(ctx, []*blockindexer.IndexedTransaction{
// 		{
// 			BlockNumber:      int64(1233),
// 			TransactionIndex: int64(23),
// 			Hash:             tktypes.Bytes32Keccak([]byte("0x00001")),
// 			Result:           blockindexer.TXResult_SUCCESS.Enum(),
// 			Nonce:            mtx.Nonce.Uint64(),
// 			From:             tktypes.MustEthAddress(string(mtx.From)),
// 		},
// 	}))
// }

// func TestEngineHandleConfirmedTransactionEventsNoInFlightNotHang(t *testing.T) {
// 	ctx := context.Background()

// 	ble, _ := NewTestPublicTxManager(t)
// 	ble.gasPriceClient = NewTestFixedPriceGasPriceClient(t)

// 	mTS := componentmocks.NewPublicTransactionStore(t)
// 	mBI := componentmocks.NewBlockIndexer(t)
// 	mEN := componentmocks.NewPublicTxEventNotifier(t)

// 	mEC := componentmocks.NewEthClient(t)
// 	mKM := componentmocks.NewKeyManager(t)
// 	ble.Init(ctx, mEC, mKM, mTS, mEN, mBI)

// 	ble.InFlightOrchestrators = map[string]*orchestrator{}
// 	// test not hang
// 	assert.NoError(t, ble.HandleConfirmedTransactions(ctx, []*blockindexer.IndexedTransaction{}))
// }
