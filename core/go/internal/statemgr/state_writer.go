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

package statemgr

import (
	"context"

	"github.com/kaleido-io/paladin/config/pkg/pldconf"
	"github.com/kaleido-io/paladin/core/internal/components"
	"github.com/kaleido-io/paladin/core/internal/flushwriter"

	"github.com/kaleido-io/paladin/toolkit/pkg/tktypes"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"

	"github.com/kaleido-io/paladin/toolkit/pkg/log"
)

// Each domain context can have up to two of these
// - one active
// - one flushing
// the rotation and is protected by the stateLock of the parent stateContext
type writeOperation struct {
	id          string
	domainKey   string
	writerOp    flushwriter.Operation[*writeOperation, *noResult]
	flushResult error
	flushed     chan struct{}
	// States and state nullifiers can be flushed to persistence, although
	// are only available for consumption outside of a DomainContext
	// with creation locks once they are confirmed via the blockchain.
	states          []*components.StateWithLabels
	stateNullifiers []*components.StateNullifier
}

type noResult struct{}

type stateWriter struct {
	w flushwriter.Writer[*writeOperation, *noResult]
}

func (wo *writeOperation) WriteKey() string {
	return wo.domainKey
}

func newStateWriter(bgCtx context.Context, ss *stateManager, conf *pldconf.FlushWriterConfig) *stateWriter {
	sw := &stateWriter{}
	sw.w = flushwriter.NewWriter(bgCtx, sw.runBatch, ss.p, conf, &pldconf.StateWriterConfigDefaults)
	return sw
}

func (op *writeOperation) flush(ctx context.Context) error {
	_, err := op.writerOp.WaitFlushed(ctx)
	return err
}

func (sw *stateWriter) newWriteOp(domainName string, contractAddress tktypes.EthAddress) *writeOperation {
	return &writeOperation{
		id:        tktypes.ShortID(),
		domainKey: domainName + ":" + contractAddress.String(),
	}
}

func (sw *stateWriter) queue(ctx context.Context, op *writeOperation) {
	op.writerOp = sw.w.Queue(ctx, op)
}

func (sw *stateWriter) runBatch(ctx context.Context, tx *gorm.DB, values []*writeOperation) ([]flushwriter.Result[*noResult], error) {

	// Build lists of things to insert (we are insert only)
	var states []*components.State
	var labels []*components.StateLabel
	var int64Labels []*components.StateInt64Label
	var stateLocks []*components.StateLock
	var stateNullifiers []*components.StateNullifier
	for _, op := range values {
		for _, s := range op.states {
			states = append(states, s.State)
			labels = append(labels, s.State.Labels...)
			int64Labels = append(int64Labels, s.State.Int64Labels...)
		}
		if len(op.stateNullifiers) > 0 {
			stateNullifiers = append(stateNullifiers, op.stateNullifiers...)
		}
	}
	log.L(ctx).Debugf("Writing state batch states=%d locks=%d nullifiers=%d labels=%d int64Labels=%d",
		len(states), len(stateLocks), len(stateNullifiers), len(labels), len(int64Labels))

	var err error
	if len(states) > 0 {
		err = tx.
			Table("states").
			Clauses(clause.OnConflict{
				Columns:   []clause.Column{{Name: "domain_name"}, {Name: "id"}},
				DoNothing: true, // immutable
			}).
			Omit("Labels", "Int64Labels", "Confirmed", "Spent"). // we do this ourselves below
			Create(states).
			Error
	}
	if err == nil && len(labels) > 0 {
		err = tx.
			Table("state_labels").
			Clauses(clause.OnConflict{
				Columns:   []clause.Column{{Name: "domain_name"}, {Name: "state"}, {Name: "label"}},
				DoNothing: true, // immutable
			}).
			Create(labels).
			Error
	}
	if err == nil && len(int64Labels) > 0 {
		err = tx.
			Table("state_int64_labels").
			Clauses(clause.OnConflict{
				Columns:   []clause.Column{{Name: "domain_name"}, {Name: "state"}, {Name: "label"}},
				DoNothing: true, // immutable
			}).
			Create(int64Labels).
			Error
	}
	if err == nil && len(stateNullifiers) > 0 {
		err = tx.
			Table("state_nullifiers").
			Clauses(clause.OnConflict{
				DoNothing: true, // immutable
			}).
			Create(stateNullifiers).
			Error
	}
	// We don't actually provide any result, so just build an array of nil results
	return make([]flushwriter.Result[*noResult], len(values)), err
}

func (sw *stateWriter) stop() {
	sw.w.Shutdown()
}
