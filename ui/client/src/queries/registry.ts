import i18next from "i18next";
import { constants } from "../components/config";
import { IRegistryEntry } from "../interfaces";
import { generatePostReq, returnResponse } from "./common";
import { RpcEndpoint, RpcMethods } from "./rpcMethods";

export const fetchRegistries = async (): Promise<string[]> => {
  const requestPayload = {
    jsonrpc: "2.0",
    id: Date.now(),
    method: RpcMethods.reg_Registries,
  };

  return <Promise<string[]>>(
    returnResponse(
      await fetch(RpcEndpoint, generatePostReq(JSON.stringify(requestPayload))),
      i18next.t("errorFetchingRegistries")
    )
  );
};

export const fetchRegistryEntries = async (
  registryName: string
): Promise<IRegistryEntry[]> => {
  const requestPayload = {
    jsonrpc: "2.0",
    id: Date.now(),
    method: RpcMethods.reg_QueryEntriesWithProps,
    params: [
      registryName,
      { limit: constants.REGISTRY_ENTRIES_QUERY_LIMIT },
      "any",
    ],
  };

  return <Promise<IRegistryEntry[]>>(
    returnResponse(
      await fetch(RpcEndpoint, generatePostReq(JSON.stringify(requestPayload))),
      i18next.t("errorFetchingRegistryEntries")
    )
  );
};
