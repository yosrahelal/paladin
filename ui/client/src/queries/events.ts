import i18next from "i18next";
import { constants } from "../components/config";
import { IEvent } from "../interfaces";
import { generatePostReq, returnResponse } from "./common";
import { RpcEndpoint, RpcMethods } from "./rpcMethods";

export const fetchEvents = async (): Promise<IEvent[]> => {
  const requestPayload = {
    jsonrpc: "2.0",
    id: Date.now(),
    method: RpcMethods.bidx_QueryIndexedEvents,
    params: [
      {
        limit: constants.EVENT_QUERY_LIMIT,
        sort: ["blockNumber DESC", "transactionIndex DESC", "logIndex DESC"],
      },
    ],
  };

  return <Promise<IEvent[]>>(
    returnResponse(
      await fetch(RpcEndpoint, generatePostReq(JSON.stringify(requestPayload))),
      i18next.t("errorFetchingLatestEvents")
    )
  );
};
