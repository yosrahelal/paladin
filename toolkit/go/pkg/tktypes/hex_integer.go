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

package tktypes

import (
	"math/big"
	"strings"

	"github.com/hyperledger/firefly-signer/pkg/ethtypes"
)

// HexBytes is byte slice that is formatted in JSON with an 0x prefix, and stored in the DB as hex
type HexInteger struct {
	ethtypes.HexInteger
}

func (id HexInteger) String() string {
	str := id.HexInteger.String()
	// padd to 32 bytes
	if len(str) < 66 {
		str = "0x" + strings.Repeat("0", 66-len(str)) + str[2:]
	}
	return str
}

func NewHexInteger(i *big.Int) *HexInteger {
	return &HexInteger{*ethtypes.NewHexInteger(i)}
}
