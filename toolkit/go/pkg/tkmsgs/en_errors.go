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

package tkmsgs

import (
	"sync"

	"github.com/hyperledger/firefly-common/pkg/i18n"
	"golang.org/x/text/language"
)

var registered sync.Once
var ffe = func(key, translation string, statusHint ...int) i18n.ErrorMessageKey {
	registered.Do(func() {
		i18n.RegisterPrefix("PD02", "Paladin Toolkit")
	})
	return i18n.FFE(language.AmericanEnglish, key, translation, statusHint...)
}

var (
	// Types PD0200XX
	MsgContextCanceled                    = ffe("PD020000", "Context canceled")
	MsgTypesUnmarshalNil                  = ffe("PD020001", "UnmarshalJSON on nil pointer")
	MsgTypesScanFail                      = ffe("PD020002", "Unable to scan type %T into type %T")
	MsgTypesEnumValueInvalid              = ffe("PD020003", "Value must be one of %s")
	MsgTypesABIDefNotInBothStructs        = ffe("PD020004", "ABI is not equal due to mismatch on: %s")
	MsgTypesInvalidNameSafeCharAlphaBoxed = ffe("PD020005", "Field '%s' must be 1-%d characters, including alphanumerics (a-zA-Z0-9), dot (.), dash (-) and underscore (_), and must start/end in an alphanumeric: %q")
	MsgTypesPrivateIdentityLocatorInvalid = ffe("PD020006", "Locator string %s is invalid")
	MsgTypesInvalidHex                    = ffe("PD020007", "Invalid hex: %s")
	MsgTypesValueInvalidHexBytes32        = ffe("PD020008", "Failed to parse value as 32 byte hex string (parsedBytes=%d)")
	MsgTypesInvalidHexInteger             = ffe("PD020009", "Invalid integer: %s")
	MsgTypesInvalidUint64                 = ffe("PD020010", "Integer cannot be converted to uint64 without losing precision: %s")
	MsgTypesInvalidDBInt64                = ffe("PD020011", "Integer too large for storage in a signed int64 database column: %s")
	MsgTypesInvalidDBInt256               = ffe("PD020012", "Integer incorrectly serialized to the database for a int256: %s")
	MsgTypesInvalidDBUint256              = ffe("PD020013", "Integer incorrectly serialized to the database for a uint256: %s")

	// Inflight PD0201XX
	MsgInflightRequestCancelled = ffe("PD020100", "Request cancelled after %s")

	// Config PD0202XX
	MsgConfigFileMissing               = ffe("PD020200", "Config file not found at path: %s")
	MsgConfigFileReadError             = ffe("PD020201", "Failed to read config file %s with error: %s")
	MsgConfigFileParseError            = ffe("PD020202", "Failed to parse config file %s with error: %s")
	MsgConfigFileMissingMandatoryValue = ffe("PD020203", "Mandatory config field %s missing ")

	// Plugin PD0203XX
	MsgPluginUnsupportedRequest   = ffe("PD020300", "Unsupported request %T")
	MsgPluginUnexpectedResponse   = ffe("PD020301", "Unexpected response %T (expected %T)")
	MsgPluginUnimplementedRequest = ffe("PD020302", "Unimplemented plugin request %T")

	// TLS PD0204XX
	MsgTLSInvalidCAFile             = ffe("PD020400", "Invalid CA certificates file")
	MsgTLSConfigFailed              = ffe("PD020401", "Failed to initialize TLS configuration")
	MsgTLSInvalidKeyPairFiles       = ffe("PD020402", "Invalid certificate and key pair files")
	MsgTLSInvalidTLSDnMatcherAttr   = ffe("PD020403", "Unknown DN attribute '%s'")
	MsgTLSInvalidTLSDnMatcherRegexp = ffe("PD020404", "Invalid regexp '%s' for requiredDNAttributes[%s]: %s")
	MsgTLSInvalidTLSDnChain         = ffe("PD020405", "Cannot match subject distinguished name as cert chain is not verified")
	MsgTLSInvalidTLSDnMismatch      = ffe("PD020406", "Certificate subject does not meet requirements")

	// RPCClient PD0205XX
	MsgRPCClientInvalidWebSocketURL = ffe("PD020500", "Invalid WebSocket URL: %s")
	MsgRPCClientInvalidHTTPURL      = ffe("PD020501", "Invalid HTTP URL: %s")

	// HTTPServer PD0108XX
	MsgHTTPServerStartFailed        = ffe("PD020600", "Failed to start server on '%s'")
	MsgHTTPServerMissingPort        = ffe("PD020601", "HTTP server port must be specified for '%s'")
	MsgHTTPServerNoWSUpgradeSupport = ffe("PD020602", "HTTP server does not support WebSocket upgrade (%T)")

	// JSON/RPC PD0110XX
	MsgJSONRPCInvalidRequest      = ffe("PD020700", "Invalid JSON/RPC request data")
	MsgJSONRPCMissingRequestID    = ffe("PD020701", "Invalid JSON/RPC request. Must set request ID")
	MsgJSONRPCUnsupportedMethod   = ffe("PD020702", "method not supported")
	MsgJSONRPCIncorrectParamCount = ffe("PD020703", "method %s requires %d params (supplied=%d)")
	MsgJSONRPCInvalidParam        = ffe("PD020704", "method %s parameter %d invalid: %s")
	MsgJSONRPCResultSerialization = ffe("PD020705", "method %s result serialization failed: %s")
)
