// Copyright © 2025 Kaleido, Inc.
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

import { IKeyEntry, IKeyMappingAndVerifier } from "../interfaces";
import { generatePostReq, returnResponse } from "./common";
import { RpcEndpoint, RpcMethods } from "./rpcMethods";
import i18next from "i18next";

export const fetchKeys = async (parent: string, limit: number, sortBy: string, sortOrder: 'asc' | 'desc', pathFilter?: string, refEntry?: IKeyEntry): Promise<IKeyEntry[]> => {
  let requestPayload: any = {
    jsonrpc: "2.0",
    id: Date.now(),
    method: RpcMethods.keymgr_queryKeys,
    params: [{
      eq: [
        {
          field: 'parent',
          value: parent
        }
      ],
      sort: [`${sortBy} ${sortOrder}`],
      limit
    }]
  };

  if(refEntry !== undefined) {
    requestPayload.params[0][sortOrder === 'asc' ? 'greaterThan' : 'lessThan'] = [{
      field: sortBy,
      value: refEntry[sortBy as 'path' | 'index']
    }];
  }

  if(pathFilter !== undefined) {
    requestPayload.params[0].eq.push({
      field: 'path',
      value: pathFilter
    });
  }

  return <Promise<IKeyEntry[]>>(
    returnResponse(
      () => fetch(RpcEndpoint, generatePostReq(JSON.stringify(requestPayload))),
      i18next.t("errorFetchingKeys")
    )
  );
};

export const reverseKeyLookup = async (algorithm: string, verifierType: string, verifier: string): Promise<IKeyMappingAndVerifier> => {
  const requestPayload = {
    jsonrpc: "2.0",
    id: Date.now(),
    method: RpcMethods.keymgr_reverseKeyLookup,
    params: [algorithm, verifierType, verifier]
  };

  return <Promise<IKeyMappingAndVerifier>>(
    returnResponse(
      () => fetch(RpcEndpoint, generatePostReq(JSON.stringify(requestPayload))),
      i18next.t("errorFetchingReverseKeyLookup"), []
    )
  );
};
