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

package components

import "context"

// IdentityResolver is the interface for resolving verifiers for a given alorithm from a lookup identity
// It can integrate with a local key manager or can communicate with an other IdentityResolver on a remote node
// depending on the node identity part of the lookup string
type IdentityResolver interface {
	TransportClient
	ResolveVerifier(ctx context.Context, lookup string, algorithm string, verifierType string) (string, error)
	ResolveVerifierAsync(ctx context.Context, lookup string, algorithm string, verifierType string, resolved func(ctx context.Context, verifier string), failed func(ctx context.Context, err error))
}
