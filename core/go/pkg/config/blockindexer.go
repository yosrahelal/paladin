// Copyright © 2024 Kaleido, Inc.
//
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package config

import (
	"github.com/kaleido-io/paladin/toolkit/pkg/confutil"
	"github.com/kaleido-io/paladin/toolkit/pkg/retry"
	"github.com/kaleido-io/paladin/toolkit/pkg/tktypes"
)

type BlockIndexerConfig struct {
	FromBlock             tktypes.RawJSON    `json:"fromBlock,omitempty"`
	CommitBatchSize       *int               `json:"commitBatchSize"`
	CommitBatchTimeout    *string            `json:"commitBatchTimeout"`
	RequiredConfirmations *int               `json:"requiredConfirmations"`
	ChainHeadCacheLen     *int               `json:"chainHeadCacheLen"`
	BlockPollingInterval  *string            `json:"blockPollingInterval"`
	EventStreams          EventStreamsConfig `json:"eventStreams"`
	Retry                 retry.Config       `json:"retry"`
}

type EventStreamsConfig struct {
	BlockDispatchQueueLength *int `json:"blockDispatchQueueLength"`
	CatchUpQueryPageSize     *int `json:"catchupQueryPageSize"`
}

var EventStreamDefaults = &EventStreamsConfig{
	BlockDispatchQueueLength: confutil.P(100),
	CatchUpQueryPageSize:     confutil.P(100),
}

var BlockIndexerDefaults = &BlockIndexerConfig{
	FromBlock:             tktypes.RawJSON(`0`),
	CommitBatchSize:       confutil.P(50),
	CommitBatchTimeout:    confutil.P("100ms"),
	RequiredConfirmations: confutil.P(0),
	ChainHeadCacheLen:     confutil.P(50),
	BlockPollingInterval:  confutil.P("10s"),
}
