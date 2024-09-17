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

package privatetxnstore

import (
	"context"

	"github.com/kaleido-io/paladin/core/internal/cache"
	"github.com/kaleido-io/paladin/core/pkg/persistence"
	"github.com/kaleido-io/paladin/toolkit/pkg/confutil"
)

type Config struct {
	SchemaCache cache.Config `yaml:"schemaCache"`
	Writer      WriterConfig `yaml:"stateWriter"`
}

type WriterConfig struct {
	WorkerCount  *int    `yaml:"workerCount"`
	BatchTimeout *string `yaml:"batchTimeout"`
	BatchMaxSize *int    `yaml:"batchMaxSize"`
}

var WriterConfigDefaults = WriterConfig{
	WorkerCount:  confutil.P(10),
	BatchTimeout: confutil.P("25ms"),
	BatchMaxSize: confutil.P(100),
}

type Store interface {
	//We persist multiple sequences in a single call, one for each signing address
	PersistDispatchBatch(ctx context.Context, dispatchBatch *DispatchBatch) error
	Close()
}

type store struct {
	p         persistence.Persistence
	bgCtx     context.Context
	cancelCtx context.CancelFunc
	writer    *writer
}

func NewStore(ctx context.Context, conf *Config, p persistence.Persistence) Store {
	s := &store{
		p: p,
	}
	s.bgCtx, s.cancelCtx = context.WithCancel(ctx)
	s.writer = newWriter(ctx, s, &conf.Writer)
	// TODO add RPC modules.initRPC()
	return s
}

func (s *store) Close() {
	s.writer.stop()
	s.cancelCtx()
}
