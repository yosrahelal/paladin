// Copyright © 2024 Kaleido, Inc.
//
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package msgs

import (
	"fmt"
	"strings"

	"github.com/hyperledger/firefly-common/pkg/i18n"
	"golang.org/x/text/language"
)

const notoPrefix = "PD20"

var registered = false
var ffe = func(key, translation string, statusHint ...int) i18n.ErrorMessageKey {
	if !registered {
		i18n.RegisterPrefix(notoPrefix, "Noto Domain")
		registered = true
	}
	if !strings.HasPrefix(key, notoPrefix) {
		panic(fmt.Errorf("must have prefix '%s': %s", notoPrefix, key))
	}
	return i18n.FFE(language.AmericanEnglish, key, translation, statusHint...)
}

var (
	MsgUnexpectedConfigType        = ffe("PD200000", "Unexpected config type: %s")
	MsgUnknownFunction             = ffe("PD200001", "Unknown function: %s")
	MsgUnexpectedFunctionSignature = ffe("PD200002", "Unexpected signature for function '%s': expected=%s actual=%s")
	MsgUnknownSchema               = ffe("PD200003", "Unknown schema: %s")
	MsgInvalidListInput            = ffe("PD200004", "Invalid item in list %s[%d] (%s): %s")
	MsgInsufficientFunds           = ffe("PD200005", "Insufficient funds (available=%s)")
	MsgInvalidStateData            = ffe("PD200006", "State data %s is invalid: %s")
)
