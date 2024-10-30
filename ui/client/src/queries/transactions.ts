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

import i18next from "i18next";
import { constants } from "../components/config";
import {
  IPaladinTransaction,
  ITransaction,
  ITransactionReceipt,
} from "../interfaces";
import { generatePostReq, returnResponse } from "./common";
import { RpcEndpoint, RpcMethods } from "./rpcMethods";

export const fetchIndexedTransactions = async (): Promise<ITransaction[]> => {
  const payload = {
    jsonrpc: "2.0",
    id: Date.now(),
    method: RpcMethods.bidx_QueryIndexedTransactions,
    params: [
      {
        limit: constants.TRANSACTION_QUERY_LIMIT,
        sort: ["blockNumber DESC", "transactionIndex DESC"],
      },
    ],
  };

  return <Promise<ITransaction[]>>(
    returnResponse(
      await fetch(RpcEndpoint, generatePostReq(JSON.stringify(payload))),
      i18next.t("errorFetchingTransactions")
    )
  );
};

export const fetchSubmissions = async (
  type: "all" | "pending"
): Promise<IPaladinTransaction[]> => {
  const allParams = [
    {
      limit: constants.PENDING_TRANSACTIONS_QUERY_LIMIT,
      sort: ["created DESC"],
    },
  ];
  const pendingParams = [...allParams, true];
  const payload = {
    jsonrpc: "2.0",
    id: Date.now(),
    method:
      type === "all"
        ? RpcMethods.ptx_QueryTransactions
        : RpcMethods.ptx_QueryPendingTransactions,
    params: type === "all" ? allParams : pendingParams,
  };

  return <Promise<IPaladinTransaction[]>>(
    returnResponse(
      await fetch(RpcEndpoint, generatePostReq(JSON.stringify(payload))),
      i18next.t("errorFetchingSubmissions")
    )
  );
};

export const fetchTransactionReceipt = async (
  transactionId: string
): Promise<ITransactionReceipt> => {
  const payload = {
    jsonrpc: "2.0",
    id: Date.now(),
    method: RpcMethods.ptx_getTransactionReceipt,
    params: [transactionId],
  };

  return <Promise<ITransactionReceipt>>(
    returnResponse(
      await fetch(RpcEndpoint, generatePostReq(JSON.stringify(payload))),
      i18next.t("errorFetchingTransactionReceipt")
    )
  );
};

export const fetchTransactionReceipts = async (
  transactions: ITransaction[]
): Promise<ITransactionReceipt[]> => {
  const payload = {
    jsonrpc: "2.0",
    id: Date.now(),
    method: RpcMethods.ptx_QueryTransactionReceipts,
    params: [
      {
        limit: constants.TRANSACTION_QUERY_LIMIT,
        in: [
          {
            field: "transactionHash",
            values: transactions.map((transaction) =>
              transaction.hash.substring(2)
            ),
          },
        ],
      },
    ],
  };

  return <Promise<ITransactionReceipt[]>>(
    returnResponse(
      await fetch(RpcEndpoint, generatePostReq(JSON.stringify(payload))),
      i18next.t("errorFetchingTransactionReceipts")
    )
  );
};

export const fetchPaladinTransactions = async (
  transactionReceipts: ITransactionReceipt[]
): Promise<IPaladinTransaction[]> => {
  const payload = {
    jsonrpc: "2.0",
    id: Date.now(),
    method: RpcMethods.ptx_QueryTransactions,
    params: [
      {
        limit: constants.TRANSACTION_QUERY_LIMIT,
        in: [
          {
            field: "id",
            values: transactionReceipts.map((transaction) => transaction.id),
          },
        ],
      },
    ],
  };

  return <Promise<IPaladinTransaction[]>>(
    returnResponse(
      await fetch(RpcEndpoint, generatePostReq(JSON.stringify(payload))),
      i18next.t("errorFetchingPaladinTransactions")
    )
  );
};
