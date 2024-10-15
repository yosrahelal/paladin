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
	"context"

	"github.com/google/uuid"
	"github.com/kaleido-io/paladin/toolkit/pkg/ptxapi"
)

type PTX interface {
	SendTransaction(ctx context.Context, tx *ptxapi.TransactionInput) (result *uuid.UUID, err error)
	SendTransactions(ctx context.Context, tx *ptxapi.TransactionInput) (result []uuid.UUID, err error)
}

type ptx struct{ *paladinClient }

func (p *ptx) SendTransaction(ctx context.Context, tx *ptxapi.TransactionInput) (result *uuid.UUID, err error) {
	err = p.rpc.CallRPC(ctx, &result, "ptx_sendTransaction", tx)
	return result, err
}

func (p *ptx) SendTransactions(ctx context.Context, txs *ptxapi.TransactionInput) (result []uuid.UUID, err error) {
	err = p.rpc.CallRPC(ctx, &result, "ptx_sendTransactions", txs)
	return result, err
}

func (c *paladinClient) PTX() PTX {
	return &ptx{}
}
