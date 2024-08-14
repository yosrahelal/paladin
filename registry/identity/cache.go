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
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/hyperledger/firefly-signer/pkg/ethtypes"
)

func (registry *IdentityRegistry) SyncCache() (err error) {
	if (registry.contractAddr == ethtypes.Address0xHex{}) {
		err = errors.New("Smart contract not set")
		return
	}

	start := time.Now()
	propertyCount := 0

	var list = []ethtypes.HexBytes0xPrefix{GetRootIdentityHash()}

	for len(list) > 0 {

		hash := list[0]
		identity, err := registry.LookupIdentity(hash)
		if err != nil {
			return err
		}

		registry.identityCache[hash.String()] = identity
		properties, err := registry.GetIdentityProperties(hash)
		if err != nil {
			return err
		}

		registry.propertyCache[hash.String()] = properties
		propertyCount += len(properties)

		list = list[1:]
		if len(identity.Children) > 0 {
			list = append(list, identity.Children...)
		}
	}

	registry.LastSync = time.Now().Unix()
	slog.Info(fmt.Sprintf("Synchronized cache in %v identities=%d properties=%d", time.Since(start), len(registry.identityCache), propertyCount))
	return nil
}
