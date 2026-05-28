/*
 * Copyright © 2026 Kaleido, Inc.
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

package common

// RejectionReason is the reason a sequencer message was rejected. The same set of reasons
// applies to all rejection message types (endorsement, delegation, assemble, pre-dispatch).
// The integer values are carried over the wire as int32 in the proto rejection_reason field.
type RejectionReason int

const (
	RejectionReason_BlockHeightTolerance        RejectionReason = iota // 0 — sender and receiver block heights differ by more than the configured tolerance
	RejectionReason_NotCurrentDelegate                                 // 1 — receiver does not recognise the sender as its current active coordinator/delegate
	RejectionReason_TransactionUnknown                                 // 2 — receiver does not recognise the transaction (already cleaned up)
	RejectionReason_EndorserIsActiveCoordinator                        // 3 — endorser is currently the active coordinator; the sender should re-route to a different endorser
)
