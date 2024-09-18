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
	"github.com/kaleido-io/paladin/core/internal/cache"
	"github.com/kaleido-io/paladin/toolkit/pkg/confutil"
)

type Config struct {
	TransactionActivity TransactionActivityConfig `yaml:"transactionActivity"`
	ABI                 ABIConfig                 `yaml:"abi"`
}

type TransactionActivityConfig struct {
	Cache                 cache.Config `yaml:"cache"`
	RecordsPerTransaction *int         `yaml:"recordsPerTransaction"`
}

type ABIConfig struct {
	Cache cache.Config `yaml:"cache"`
}

var DefaultConfig = &Config{
	TransactionActivity: TransactionActivityConfig{
		Cache: cache.Config{
			Capacity: confutil.P(1000),
		},
		RecordsPerTransaction: confutil.P(10),
	},
	ABI: ABIConfig{
		Cache: cache.Config{
			Capacity: confutil.P(100),
		},
	},
}
