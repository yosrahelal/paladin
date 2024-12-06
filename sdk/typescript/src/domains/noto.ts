import { ethers } from "ethers";
import { IGroupInfo, IStateEncoded, TransactionType } from "../interfaces";
import PaladinClient from "../paladin";
import * as notoPrivateJSON from "./abis/INotoPrivate.json";
import { penteGroupABI } from "./pente";

const DEFAULT_POLL_TIMEOUT = 10000;

export interface NotoOptions {
  pollTimeout?: number;
}

export const notoConstructorABI = (
  withHooks: boolean
): ethers.JsonFragment => ({
  type: "constructor",
  inputs: [
    { name: "notary", type: "string" },
    { name: "restrictMinting", type: "bool" },
    ...(withHooks
      ? [
          {
            name: "hooks",
            type: "tuple",
            components: [
              {
                name: "privateGroup",
                type: "tuple",
                components: penteGroupABI.components,
              },
              { name: "publicAddress", type: "address" },
              { name: "privateAddress", type: "address" },
            ],
          },
        ]
      : []),
  ],
});

export interface NotoConstructorParams {
  notary: string;
  hooks?: {
    privateGroup?: IGroupInfo;
    publicAddress?: string;
    privateAddress?: string;
  };
  restrictMinting?: boolean;
}

export interface NotoMintParams {
  to: string;
  amount: string | number;
  data: string;
}

export interface NotoTransferParams {
  to: string;
  amount: string | number;
  data: string;
}

export interface NotoBurnParams {
  amount: string | number;
  data: string;
}

export interface NotoApproveTransferParams {
  inputs: IStateEncoded[];
  outputs: IStateEncoded[];
  data: string;
  delegate: string;
}

export class NotoFactory {
  private options: Required<NotoOptions>;

  constructor(
    private paladin: PaladinClient,
    public readonly domain: string,
    options?: NotoOptions
  ) {
    this.options = {
      pollTimeout: DEFAULT_POLL_TIMEOUT,
      ...options,
    };
  }

  using(paladin: PaladinClient) {
    return new NotoFactory(paladin, this.domain, this.options);
  }

  async newNoto(from: string, data: NotoConstructorParams) {
    const txID = await this.paladin.sendTransaction({
      type: TransactionType.PRIVATE,
      domain: this.domain,
      abi: [notoConstructorABI(!!data.hooks)],
      function: "",
      from,
      data,
    });
    const receipt = await this.paladin.pollForReceipt(
      txID,
      this.options.pollTimeout
    );
    return receipt?.contractAddress === undefined
      ? undefined
      : new NotoInstance(this.paladin, receipt.contractAddress, this.options);
  }
}

export class NotoInstance {
  private options: Required<NotoOptions>;

  constructor(
    private paladin: PaladinClient,
    public readonly address: string,
    options?: NotoOptions
  ) {
    this.options = {
      pollTimeout: DEFAULT_POLL_TIMEOUT,
      ...options,
    };
  }

  using(paladin: PaladinClient) {
    return new NotoInstance(paladin, this.address, this.options);
  }

  async mint(from: string, data: NotoMintParams) {
    const txID = await this.paladin.sendTransaction({
      type: TransactionType.PRIVATE,
      abi: notoPrivateJSON.abi,
      function: "mint",
      to: this.address,
      from,
      data,
    });
    return this.paladin.pollForReceipt(txID, this.options.pollTimeout);
  }

  async transfer(from: string, data: NotoTransferParams) {
    const txID = await this.paladin.sendTransaction({
      type: TransactionType.PRIVATE,
      abi: notoPrivateJSON.abi,
      function: "transfer",
      to: this.address,
      from,
      data,
    });
    return this.paladin.pollForReceipt(txID, this.options.pollTimeout);
  }

  async prepareTransfer(from: string, data: NotoTransferParams) {
    const txID = await this.paladin.prepareTransaction({
      type: TransactionType.PRIVATE,
      abi: notoPrivateJSON.abi,
      function: "transfer",
      to: this.address,
      from,
      data,
    });
    return this.paladin.pollForPreparedTransaction(
      txID,
      this.options.pollTimeout
    );
  }

  async approveTransfer(from: string, data: NotoApproveTransferParams) {
    const txID = await this.paladin.sendTransaction({
      type: TransactionType.PRIVATE,
      abi: notoPrivateJSON.abi,
      function: "approveTransfer",
      to: this.address,
      from,
      data,
    });
    return this.paladin.pollForReceipt(txID, this.options.pollTimeout);
  }

  async burn(from: string, data: NotoBurnParams) {
    const txID = await this.paladin.sendTransaction({
      type: TransactionType.PRIVATE,
      abi: notoPrivateJSON.abi,
      function: "burn",
      to: this.address,
      from,
      data,
    });
    return this.paladin.pollForReceipt(txID, this.options.pollTimeout);
  }
}
