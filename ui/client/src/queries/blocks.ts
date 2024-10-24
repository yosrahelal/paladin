import i18next from "i18next";
import { generatePostReq, returnResponse } from "./common";
import { RpcEndpoint, RpcMethods } from "./rpcMethods";
import { ITransaction } from "../interfaces";

export const fetchLatestBlockWithTxs = async (): Promise<ITransaction[]> => {
  const payload = {
    jsonrpc: "2.0",
    id: Date.now(),
    method: RpcMethods.bidx_QueryIndexedTransactions,
    params: [{ limit: 1, sort: ["blockNumber DESC", "transactionIndex DESC"] }],
  };

  return <Promise<ITransaction[]>>(
    returnResponse(
      await fetch(RpcEndpoint, generatePostReq(JSON.stringify(payload))),
      i18next.t("errorFetchingLatestBlock")
    )
  );
};
