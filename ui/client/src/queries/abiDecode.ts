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

import { IABIDecodedEntry } from "../interfaces";
import { generatePostReq, returnResponse } from "./common";
import { RpcEndpoint, RpcMethods } from "./rpcMethods";

export const fetchDecodedCallData = async (
  callData: string
): Promise<IABIDecodedEntry> => {
  const payload = {
    jsonrpc: "2.0",
    id: Date.now(),
    method: RpcMethods.ptx_decodeCall,
    params: [callData, "mode=object"],
  };

  return <Promise<IABIDecodedEntry>>(
    returnResponse(
      await fetch(RpcEndpoint, generatePostReq(JSON.stringify(payload))), "", [500]
    )
  );
};

export const fetchDecodedEvent = async (
  topics: string[],
  data: string
): Promise<IABIDecodedEntry> => {
  const payload = {
    jsonrpc: "2.0",
    id: Date.now(),
    method: RpcMethods.ptx_decodeEvent,
    params: [topics, data, "mode=object"],
  };

  return <Promise<IABIDecodedEntry>>(
    returnResponse(
      await fetch(RpcEndpoint, generatePostReq(JSON.stringify(payload))), "", [500]
    )
  );
};
