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

package rpcclient

type RPCCode int64

const (
	RPCCodeParseError     RPCCode = -32700
	RPCCodeInvalidRequest RPCCode = -32600
	RPCCodeInternalError  RPCCode = -32603
	// JSON-RPC 2.0 specification reserves -32000 to -32099 for "implementation-defined server-errors"
	// Paladin uses this range for custom application errors like authentication failures
	RPCCodeUnauthorized RPCCode = -32000 // Unauthorized request - authentication failed
	RPCCodeConflict     RPCCode = -32001 // Idempotency key clash - request already submitted with this key
)
