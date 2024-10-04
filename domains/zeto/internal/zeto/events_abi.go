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

package zeto

import (
	_ "embed"

	"github.com/hyperledger/firefly-signer/pkg/abi"
	"github.com/kaleido-io/paladin/toolkit/pkg/domain"
)

//go:embed abis/IZeto.json
var zetoABIBytes []byte // From "gradle copySolidity"
//go:embed abis/IZetoEncrypted.json
var zetoEncryptedABIBytes []byte // From "gradle copySolidity"

func getAllZetoEventAbis() abi.ABI {
	var events abi.ABI
	contract := domain.LoadBuild(zetoABIBytes)
	events = buildEvents(events, contract)
	contract = domain.LoadBuild(zetoEncryptedABIBytes)
	events = buildEvents(events, contract)
	return events
}

func buildEvents(events abi.ABI, contract *domain.SolidityBuild) abi.ABI {
	for _, entry := range contract.ABI {
		if entry.Type == abi.Event {
			events = append(events, entry)
		}
	}
	events = dedup(events)
	return events
}

func dedup(events abi.ABI) abi.ABI {
	for i := 0; i < len(events); i++ {
		for j := i + 1; j < len(events); j++ {
			if events[i].Name == events[j].Name {
				events = append(events[:j], events[j+1:]...)
			}
		}
	}
	return events
}
