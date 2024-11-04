import { AxiosRequestConfig } from "axios";
import { Logger } from "./logger";

export interface PaladinConfig {
  url: string;
  wsUrl?: string;
  requestConfig?: AxiosRequestConfig;
  logger?: Logger;
}

export interface JsonRpcResult<T> {
  result: T;
}
