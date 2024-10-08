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
	"crypto/sha256"
	"strings"

	"github.com/hyperledger/firefly-signer/pkg/ethtypes"
)

func GetIdentityHash(identifier string) ethtypes.HexBytes0xPrefix {
	if len(identifier) == 0 {
		return GetRootIdentityHash()
	}

	segments := strings.Split(identifier, "/")
	hash := GetRootIdentityHash()

	for _, segment := range segments {
		hash = CalculateIdentityHash(hash, segment)
	}

	return hash
}

func CalculateIdentityHash(parentIdentityHash ethtypes.HexBytes0xPrefix, name string) (result ethtypes.HexBytes0xPrefix) {
	h := sha256.New()
	h.Write(append(parentIdentityHash[:], []byte(name)...))
	result = h.Sum(nil)
	return
}

func GetRootIdentityHash() ethtypes.HexBytes0xPrefix {
	h := [32]byte{}
	return h[:]
}
