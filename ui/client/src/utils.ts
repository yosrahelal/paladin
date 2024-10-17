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

export const constants = {
  UPDATE_FREQUENCY_MILLISECONDS: 5000,
  TRANSACTION_QUERY_LIMIT: 100,
  EVENT_QUERY_LIMIT: 100,
  REGISTRY_ENTRIES_QUERY_LIMIT: 100
};

export const getLatestBlockWithTransactions = async () => {
  let requestPayload = {
    jsonrpc: '2.0',
    id: Date.now(),
    method: 'bidx_queryIndexedTransactions',
    params: [{ limit: 1, sort: ['blockNumber DESC', 'transactionIndex DESC'] }]
  };
  const response = await fetch('/json-rpc', {
    method: 'post',
    headers: {
      'Accept': 'application/json',
      'Content-Type': 'application/json'
    },
    body: JSON.stringify(requestPayload)
  });
  if (response.ok) {
    const responseBody = await response.json();
    if(Array.isArray(responseBody.result) && responseBody.result.length > 0) {
      return responseBody.result[0].blockNumber as number;
    }
  } else {
    throw new Error(`${response.status}: ${response.statusText}`)
  }
  return 0;
}