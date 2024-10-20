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

package pldclient

import (
	"testing"

	"github.com/google/uuid"
	"github.com/kaleido-io/paladin/toolkit/pkg/algorithms"
	"github.com/kaleido-io/paladin/toolkit/pkg/pldapi"
	"github.com/kaleido-io/paladin/toolkit/pkg/query"
	"github.com/kaleido-io/paladin/toolkit/pkg/verifiers"
	"github.com/stretchr/testify/assert"
)

func TestPTXFunctions(t *testing.T) {

	ctx, c, _, done := newTestClientAndServerHTTP(t)
	defer done()

	_, err := c.PTX().SendTransaction(ctx, &pldapi.TransactionInput{})
	assert.Regexp(t, "PD020702.*ptx_sendTransaction", err)

	_, err = c.PTX().SendTransactions(ctx, []*pldapi.TransactionInput{})
	assert.Regexp(t, "PD020702.*ptx_sendTransactions", err)

	_, err = c.PTX().Call(ctx, &pldapi.TransactionCall{})
	assert.Regexp(t, "PD020702.*ptx_call", err)

	_, err = c.PTX().GetTransaction(ctx, uuid.New())
	assert.Regexp(t, "PD020702.*ptx_getTransaction", err)

	_, err = c.PTX().GetTransactionFull(ctx, uuid.New())
	assert.Regexp(t, "PD020702.*ptx_getTransactionFull", err)

	_, err = c.PTX().GetTransactionByIdempotencyKey(ctx, "idem1")
	assert.Regexp(t, "PD020702.*ptx_getTransactionByIdempotencyKey", err)

	_, err = c.PTX().QueryTransactions(ctx, query.NewQueryBuilder().Query())
	assert.Regexp(t, "PD020702.*ptx_queryTransactions", err)

	_, err = c.PTX().QueryTransactionsFull(ctx, query.NewQueryBuilder().Query())
	assert.Regexp(t, "PD020702.*ptx_queryTransactionsFull", err)

	_, err = c.PTX().GetTransactionReceipt(ctx, uuid.New())
	assert.Regexp(t, "PD020702.*ptx_getTransactionReceipt", err)

	_, err = c.PTX().QueryTransactionReceipts(ctx, query.NewQueryBuilder().Query())
	assert.Regexp(t, "PD020702.*ptx_queryTransactionReceipts", err)

	_, err = c.PTX().ResoleVerifier(ctx, "key.one", algorithms.ECDSA_SECP256K1, verifiers.ETH_ADDRESS)
	assert.Regexp(t, "PD020702.*ptx_resolveVerifier", err)

}
