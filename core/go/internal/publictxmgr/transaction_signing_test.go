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
	"fmt"
	"testing"

	"github.com/hyperledger/firefly-signer/pkg/ethsigner"
	"github.com/hyperledger/firefly-signer/pkg/ethtypes"
	"github.com/kaleido-io/paladin/core/pkg/ethclient"
	"github.com/kaleido-io/paladin/toolkit/pkg/tktypes"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

func TestInFlightTxSign(t *testing.T) {
	ctx, o, m, done := newTestOrchestrator(t)
	defer done()
	it, _ := newInflightTransaction(o, 1)

	fromAddr := *tktypes.RandAddress()
	ethTx := &ethsigner.Transaction{
		Nonce: ethtypes.NewHexInteger64(12345),
	}
	rs := &ethclient.ResolvedSigner{
		Address: fromAddr,
	}

	buildRawTransactionMock := m.ethClient.On("BuildRawTransactionNoResolve", ctx, ethclient.EIP1559, rs, ethTx, mock.Anything)
	buildRawTransactionMock.Run(func(args mock.Arguments) {
		signer := args[2].(*ethclient.ResolvedSigner)
		assert.Equal(t, fromAddr, signer.Address)
		buildRawTransactionMock.Return(nil, fmt.Errorf("pop"))
	}).Once()
	_, txHash, err := it.signTx(ctx, rs, ethTx)
	assert.Error(t, err)
	assert.Nil(t, txHash)

	// signing succeeded
	testTxData := tktypes.HexBytes(tktypes.RandBytes(32))
	buildRawTransactionMock.Run(func(args mock.Arguments) {
		signer := args[2].(*ethclient.ResolvedSigner)
		assert.Equal(t, fromAddr, signer.Address)
	}).Return(testTxData, nil).Once()
	_, txHash, err = it.signTx(ctx, rs, ethTx)
	require.NoError(t, err)
	assert.Equal(t, *calculateTransactionHash(testTxData), *txHash)
}
