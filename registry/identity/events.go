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

package identity

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"time"

	"github.com/hyperledger/firefly-signer/pkg/abi"
	"github.com/hyperledger/firefly-signer/pkg/ethtypes"
	"github.com/kaleido-io/paladin/kata/pkg/blockindexer"
	"gorm.io/gorm"
)

type identityRegisteredEvent struct {
	ParentIndentityHash ethtypes.HexBytes0xPrefix `json:"parentIndentityHash"`
	IdentityHash        ethtypes.HexBytes0xPrefix `json:"identityHash"`
	Name                string                    `json:"name"`
	Owner               ethtypes.Address0xHex     `json:"owner"`
}

type propertySetEvent struct {
	IdentityHash ethtypes.HexBytes0xPrefix `json:"identityHash"`
	Name         string                    `json:"name"`
	Value        string                    `json:"value"`
}

func (registry *IdentityRegistry) StartListening() (err error) {
	identityStream := blockindexer.InternalEventStream{
		Handler: func(ctx context.Context, tx *gorm.DB, batch *blockindexer.EventDeliveryBatch) error {
			for _, e := range batch.Events {
				if !bytes.Equal(e.Address[:], registry.contractAddr[:]) {
					continue
				}
				var ire identityRegisteredEvent
				err = json.Unmarshal(e.Data, &ire)
				if err != nil {
					slog.Error(fmt.Sprintf("Failed to process identity event %s", err))
				} else {
					registry.PropertyCache[ire.IdentityHash.String()] = &map[string]string{}
					registry.IdentityCache[ire.IdentityHash.String()] = &Identity{
						Parent:   ire.ParentIndentityHash,
						Name:     ire.Name,
						Owner:    ire.Owner,
						Children: make([]ethtypes.HexBytes0xPrefix, 0),
					}
					parent, ok := registry.IdentityCache[ire.ParentIndentityHash.String()]
					if ok && !contains(parent.Children, ire.IdentityHash) {
						parent.Children = append(parent.Children, ire.IdentityHash)
					}
				}
				registry.LastIncrementalUpdate = time.Now().Unix()
			}
			return nil
		},
		Definition: &blockindexer.EventStream{
			Name: "IdentityRegistered",
			ABI:  abi.ABI{registry.contract.ABI.Events()["IdentityRegistered"]},
		},
	}

	propertyStream := blockindexer.InternalEventStream{
		Handler: func(ctx context.Context, tx *gorm.DB, batch *blockindexer.EventDeliveryBatch) error {
			for _, e := range batch.Events {
				if !bytes.Equal(e.Address[:], registry.contractAddr[:]) {
					continue
				}
				var pse propertySetEvent
				err = json.Unmarshal(e.Data, &pse)
				if err != nil {
					slog.Error(fmt.Sprintf("Failed to process property event %s", err))
				} else {
					properties, ok := registry.PropertyCache[pse.IdentityHash.String()]
					if ok {
						(*properties)[pse.Name] = pse.Value
					}
				}
				registry.LastIncrementalUpdate = time.Now().Unix()
			}
			return nil
		},
		Definition: &blockindexer.EventStream{
			Name: "PropertySet",
			ABI:  abi.ABI{registry.contract.ABI.Events()["PropertySet"]},
		},
	}

	err = registry.indexer.Start(&identityStream, &propertyStream)
	return
}

func (registry *IdentityRegistry) StopListening() {
	registry.indexer.Stop()
}

func contains(list []ethtypes.HexBytes0xPrefix, entry ethtypes.HexBytes0xPrefix) bool {
	for _, currentEntry := range list {
		if currentEntry.Equals(entry) {
			return true
		}
	}
	return false
}
