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

package constants

const (
	// the base circuits support inputs and outputs up to size 2
	CIRCUIT_ANON           = "anon"
	CIRCUIT_ANON_ENC       = "anon_enc"
	CIRCUIT_ANON_NULLIFIER = "anon_nullifier"

	// the batch circuits support inputs and outputs from size 3 up to size 10
	CIRCUIT_ANON_BATCH           = "anon_batch"
	CIRCUIT_ANON_ENC_BATCH       = "anon_enc_batch"
	CIRCUIT_ANON_NULLIFIER_BATCH = "anon_nullifier_batch"

	TOKEN_ANON           = "Zeto_Anon"
	TOKEN_ANON_ENC       = "Zeto_AnonEnc"
	TOKEN_ANON_NULLIFIER = "Zeto_AnonNullifier"
)
