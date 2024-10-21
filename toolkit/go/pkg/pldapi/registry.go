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

package pldapi

import "github.com/kaleido-io/paladin/toolkit/pkg/tktypes"

// An entity within a registry with its current properties
type RegistryEntry struct {
	Registry         string              `json:"registry"`           // the registry that maintains this record
	ID               tktypes.HexBytes    `json:"id"`                 // unique within the registry, across all records in the hierarchy
	Name             string              `json:"name"`               // unique across entries with the same parent, within the particular registry
	ParentID         tktypes.HexBytes    `json:"parentId,omitempty"` // nil a root record, otherwise will be a reference to another entity in the same registry
	*OnChainLocation `json:",omitempty"` // only included if the registry uses blockchain indexing
	*ActiveFlag      `json:",omitempty"` // only returned from queries that explicitly look for inactive entries
}

type RegistryProperty struct {
	Registry         string              `json:"registry"` // the registry that maintains this record
	EntryID          tktypes.HexBytes    `json:"entityId"` // the ID of the entity that owns this record within the registry
	Name             string              `json:"name"`     // unique across entries with the same parent, within the particular registry
	Value            string              `json:"value"`    // unique across entries with the same parent, within the particular registry
	*OnChainLocation `json:",omitempty"` // only included if the registry uses blockchain indexing
	*ActiveFlag      `json:",omitempty"` // only returned from queries that explicitly look for inactive entries
}

type ActiveFlag struct {
	Active bool `json:"active"`
}

type OnChainLocation struct {
	BlockNumber      int64 `json:"blockNumber"`
	TransactionIndex int64 `json:"transactionIndex"`
	LogIndex         int64 `json:"logIndex"`
}

// A convenience structure that gives a snapshot of the whole entity, with all it's properties.
// Alternatively you can list the full RegistryProperty (with the provenance information) separately.
type RegistryEntryWithProperties struct {
	*RegistryEntry `json:",inline"`
	// With this convenience object all of the properties are flattened into a name=value string map
	Properties map[string]string `json:"properties"`
}

type ActiveFilter string

const (
	ActiveFilterActive   ActiveFilter = "active"
	ActiveFilterInactive ActiveFilter = "inactive"
	ActiveFilterAny      ActiveFilter = "any"
)

func (af ActiveFilter) Enum() tktypes.Enum[ActiveFilter] {
	return tktypes.Enum[ActiveFilter](af)
}

func (af ActiveFilter) Options() []string {
	return []string{
		string(ActiveFilterActive),
		string(ActiveFilterInactive),
		string(ActiveFilterAny),
	}
}
