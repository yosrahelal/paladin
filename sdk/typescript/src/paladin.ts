import axios, { AxiosError, AxiosInstance, AxiosRequestConfig } from "axios";
import { JsonRpcResult, PaladinConfig } from "./interfaces/paladin";
import { Logger } from "./interfaces/logger";
import { IQuery } from "./interfaces/query";
import {
  ITransactionInput,
  ITransactionCall,
  ITransaction,
  IPreparedTransaction,
  ITransactionReceipt,
  ITransactionStates,
} from "./interfaces/transaction";
import { Algorithms, Verifiers } from "./interfaces";

const WAIT_INCREMENT_MS = 100; // for status polling

export default class PaladinClient {
  protected http: AxiosInstance;
  private logger: Logger;

  constructor(options: PaladinConfig) {
    this.http = axios.create({
      ...options.requestConfig,
      baseURL: options.url,
    });
    this.logger = options.logger ?? console;
  }

  protected defaultHeaders() {
    return {
      Accept: "application/json",
      "Content-Type": "application/json",
    };
  }

  protected defaultPayload() {
    return {
      jsonrpc: "2.0",
      id: Date.now(),
    };
  }

  private parseAxiosErrorMessage(err: any) {
    if (err instanceof AxiosError && err.response?.data?.error) {
      return err.response.data.error;
    }
    return `${err}`;
  }

  private post<T>(method: string, params: any[], config?: AxiosRequestConfig) {
    const res = this.http.post<T>(
      "/",
      { ...this.defaultPayload(), method, params },
      { ...config, headers: this.defaultHeaders() }
    );
    res.catch((err: AxiosError) => {
      this.logger.error(
        `JSON-RPC error from ${method}: ${err.response?.status} ${err.response?.statusText}`,
        this.parseAxiosErrorMessage(err)
      );
    });
    return res;
  }

  async waitForReceipt(txID: string, waitMs: number, full?: boolean) {
    for (let i = 0; i < waitMs; i += WAIT_INCREMENT_MS) {
      var receipt = await this.getTransactionReceipt(txID, full);
      if (receipt != undefined) {
        return receipt;
      }
      await new Promise((resolve) => setTimeout(resolve, WAIT_INCREMENT_MS));
    }
    this.logger.error(`Failed while waiting for receipt: ${txID}`);
    return undefined;
  }

  async waitForPrepare(txID: string, waitMs: number) {
    for (let i = 0; i < waitMs; i += WAIT_INCREMENT_MS) {
      var receipt = await this.getPreparedTransaction(txID);
      if (receipt != undefined) {
        return receipt;
      }
      await new Promise((resolve) => setTimeout(resolve, WAIT_INCREMENT_MS));
    }
    this.logger.error(`Failed while waiting for prepare: ${txID}`);
    return undefined;
  }

  async prepareTransaction(transaction: ITransactionInput) {
    const res = await this.post<JsonRpcResult<string>>(
      "ptx_prepareTransaction",
      [transaction],
      undefined
    );
    return res.data.result;
  }

  async sendTransaction(transaction: ITransactionInput) {
    const res = await this.post<JsonRpcResult<string>>(
      "ptx_sendTransaction",
      [transaction],
      undefined
    );
    return res.data.result;
  }

  async call(transaction: ITransactionCall) {
    const res = await this.post<JsonRpcResult<any>>("ptx_call", [transaction]);
    return res.data.result;
  }

  async queryTransactions(query: IQuery) {
    const res = await this.post<JsonRpcResult<ITransaction[]>>(
      "ptx_queryTransactions",
      [query]
    );
    return res.data.result;
  }

  async getTransaction(txID: string, full?: boolean) {
    const res = await this.post<JsonRpcResult<ITransaction>>(
      full ? "ptx_getTransactionFull" : "ptx_getTransaction",
      [txID],
      {
        validateStatus: (status) => status < 300 || status === 404,
      }
    );
    return res.status === 404 ? undefined : res.data.result;
  }

  async getPreparedTransaction(txID: string) {
    const res = await this.post<JsonRpcResult<IPreparedTransaction>>(
      "ptx_getPreparedTransaction",
      [txID],
      {
        validateStatus: (status) => status < 300 || status === 404,
      }
    );
    return res.status === 404 ? undefined : res.data.result;
  }

  async queryTransactionReceipts(query: IQuery) {
    const res = await this.post<JsonRpcResult<ITransactionReceipt[]>>(
      "ptx_queryTransactionReceipts",
      [query]
    );
    return res.data.result;
  }

  async getTransactionReceipt(txID: string, full?: boolean) {
    const res = await this.post<JsonRpcResult<ITransactionReceipt>>(
      full ? "ptx_getTransactionReceiptFull" : "ptx_getTransactionReceipt",
      [txID],
      {
        validateStatus: (status) => status < 300 || status === 404,
      }
    );
    return res.status === 404 ? undefined : res.data.result;
  }

  async getStateReceipt(txID: string) {
    const res = await this.post<JsonRpcResult<ITransactionStates>>(
      "ptx_getStateReceipt",
      [txID],
      {
        validateStatus: (status) => status < 300 || status === 404,
      }
    );
    return res.status === 404 ? undefined : res.data.result;
  }

  async resolveVerifier(
    lookup: string,
    algorithm: Algorithms,
    verifierType: Verifiers
  ) {
    const res = await this.post<JsonRpcResult<string>>("ptx_resolveVerifier", [
      lookup,
      algorithm,
      verifierType,
    ]);
    return res.data.result;
  }
}
