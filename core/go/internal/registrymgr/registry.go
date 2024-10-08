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

package registrymgr

import (
	"context"
	"encoding/json"
	"sync/atomic"

	"github.com/google/uuid"
	"github.com/hyperledger/firefly-common/pkg/i18n"
	"github.com/kaleido-io/paladin/config/pkg/pldconf"
	"github.com/kaleido-io/paladin/core/internal/components"
	"github.com/kaleido-io/paladin/core/internal/msgs"

	"github.com/kaleido-io/paladin/toolkit/pkg/log"
	"github.com/kaleido-io/paladin/toolkit/pkg/prototk"
	"github.com/kaleido-io/paladin/toolkit/pkg/retry"
	"gorm.io/gorm/clause"
)

type registry struct {
	ctx       context.Context
	cancelCtx context.CancelFunc

	conf *pldconf.RegistryConfig
	rm   *registryManager
	id   uuid.UUID
	name string
	api  components.RegistryManagerToRegistry

	initialized atomic.Bool
	initRetry   *retry.Retry

	initError atomic.Pointer[error]
	initDone  chan struct{}
}

func (rm *registryManager) newRegistry(id uuid.UUID, name string, conf *pldconf.RegistryConfig, toRegistry components.RegistryManagerToRegistry) *registry {
	r := &registry{
		rm:        rm,
		conf:      conf,
		initRetry: retry.NewRetryIndefinite(&conf.Init.Retry),
		name:      name,
		id:        id,
		api:       toRegistry,
		initDone:  make(chan struct{}),
	}
	r.ctx, r.cancelCtx = context.WithCancel(log.WithLogField(rm.bgCtx, "registry", r.name))
	return r
}

func (r *registry) init() {
	defer close(r.initDone)

	// We block retrying each part of init until we succeed, or are cancelled
	// (which the plugin manager will do if the registry disconnects)
	err := r.initRetry.Do(r.ctx, func(attempt int) (bool, error) {
		// Send the configuration to the registry for processing
		confJSON, _ := json.Marshal(&r.conf.Config)
		_, err := r.api.ConfigureRegistry(r.ctx, &prototk.ConfigureRegistryRequest{
			Name:       r.name,
			ConfigJson: string(confJSON),
		})
		return true, err
	})
	if err != nil {
		log.L(r.ctx).Debugf("registry initialization cancelled before completion: %s", err)
		r.initError.Store(&err)
	} else {
		log.L(r.ctx).Debugf("registry initialization complete")
		r.initialized.Store(true)
		// Inform the plugin manager callback
		r.api.Initialized()
	}
}

func (r *registry) UpsertTransportDetails(ctx context.Context, req *prototk.UpsertTransportDetails) (*prototk.UpsertTransportDetailsResponse, error) {

	if req.Node == "" || req.Transport == "" {
		return nil, i18n.NewError(ctx, msgs.MsgRegistryInvalidEntry)
	}

	existingEntries, _ := r.rm.GetNodeTransports(ctx, req.Node)
	deDuped := make([]*components.RegistryNodeTransportEntry, 0, len(existingEntries))
	for _, existing := range existingEntries {
		if existing.Registry != r.id.String() || existing.Node != req.Node || existing.Transport != req.Transport {
			deDuped = append(deDuped, existing)
		}
	}
	entry := append(deDuped, &components.RegistryNodeTransportEntry{
		Registry:         r.id.String(),
		Node:             req.Node,
		Transport:        req.Transport,
		TransportDetails: req.TransportDetails,
	})

	// Store entry in database
	r.rm.persistence.DB().Clauses(clause.OnConflict{
		UpdateAll: true,
	}).Table("registry_transport_details").Create(entry)

	// If the entry is present in cache, update it
	_, present := r.rm.registryCache.Get(req.Node)
	if present {
		r.rm.registryCache.Set(req.Node, entry)
	}

	return &prototk.UpsertTransportDetailsResponse{}, nil
}

func (r *registry) close() {
	r.cancelCtx()
	<-r.initDone
}
