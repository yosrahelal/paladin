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

package txmgr

import (
	"github.com/hyperledger/firefly-signer/pkg/abi"
	"github.com/kaleido-io/paladin/core/internal/filters"
	"github.com/kaleido-io/paladin/toolkit/pkg/ptxapi"
	"github.com/kaleido-io/paladin/toolkit/pkg/tktypes"
)

var txFields = filters.FieldMap{
	"id":              filters.StringField("id"),
	"created":         filters.TimestampField("created"),
	"idempotency_key": filters.StringField("created"),
	"type":            filters.StringField("type"),
	"domain":          filters.StringField("domain"),
	"from":            filters.StringField("from"),
	"to":              filters.HexBytesField("to"),
	"function":        filters.JSONField("function"),
	"inputs":          filters.JSONField("inputs"),
}

type TransactionPersisted struct {
	ID             string
	Created        tktypes.Timestamp `gorm:"autoCreateTime:nano"`
	IdempotencyKey string
	Type           tktypes.Enum[ptxapi.TransactionType]
	Domain         string
	From           string
	To             *tktypes.EthAddress
	Function       abi.Entry
	Inputs         tktypes.RawJSON
}
