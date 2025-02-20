/*
 * Copyright © 2025 Kaleido, Inc.
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

package publictxmgr

type transactionUpdateRequest struct {
	response chan error
}

// TODO AM: what's the history that means the public tx manager is abbreviated to ble?
// Can this change
// TODO AM: this should use the dispatch action- but will want the
// func (ble *pubTxManager) QueueNewTransactionUpdateRequest(txu *pldapi.TransactionUpdate) chan error {
// 	responseChan := make(chan error, 1)
// 	updateRequest := transactionUpdateRequest{
// 		response: responseChan,
// 	}
// 	ble.updateRequestMux.Lock()
// 	ble.updateRequests = append(ble.updateRequests, updateRequest)
// 	// TODO AM: I think this is fine to reuse this channel but come back to it
// 	ble.MarkInFlightOrchestratorsStale()
// 	return responseChan
// }
