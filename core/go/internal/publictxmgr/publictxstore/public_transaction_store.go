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

package publictxstore

import (
	"context"

	"github.com/kaleido-io/paladin/core/internal/cache"
	"github.com/kaleido-io/paladin/core/internal/components"
	"github.com/kaleido-io/paladin/core/internal/statestore"
	"github.com/kaleido-io/paladin/core/pkg/persistence"
	"github.com/kaleido-io/paladin/toolkit/pkg/confutil"
)

type pubTxStore struct {
	bgCtx         context.Context
	cancelCtx     context.CancelFunc
	writer        *pubTxWriter
	publicTxCache cache.Cache[string, *components.PublicTX]
	p             persistence.Persistence
}

type Config struct {
	cache  cache.Config              `yaml:"cache"`
	writer statestore.DBWriterConfig `yaml:"writer"`
}

func NewPubTxStore(ctx context.Context, conf *Config, p persistence.Persistence) components.PublicTransactionStore {
	pts := &pubTxStore{
		p:             p,
		publicTxCache: cache.NewCache[string, *components.PublicTX](&conf.cache, pubTxCacheDefaults),
	}
	pts.bgCtx, pts.cancelCtx = context.WithCancel(ctx)
	pts.writer = newPubTxWriter(ctx, &conf.writer)
	return pts
}

var pubTxCacheDefaults = &cache.Config{
	Capacity: confutil.P(1000),
}

func (pts *pubTxStore) Close() {
	pts.writer.stop()
	pts.cancelCtx()
}
