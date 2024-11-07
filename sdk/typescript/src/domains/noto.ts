import { ethers } from "ethers";
import {
  IGroupInfo,
  IStateBase,
  IStateEncoded,
  TransactionType,
} from "../interfaces";
import PaladinClient from "../paladin";
import { encodeHex } from "../utils";
import * as notoPrivateJSON from "./abis/INotoPrivate.json";
import { penteGroupABI } from "./pente";

const POLL_TIMEOUT_MS = 5000;

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

export interface NotoApproveTransferParams {
  inputs: IStateEncoded[];
  outputs: IStateEncoded[];
  data: string;
  delegate: string;
}

export class NotoFactory {
  constructor(private paladin: PaladinClient, public readonly domain: string) {}

  using(paladin: PaladinClient) {
    return new NotoFactory(paladin, this.domain);
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
    const receipt = await this.paladin.pollForReceipt(txID, POLL_TIMEOUT_MS);
    return receipt?.contractAddress === undefined
      ? undefined
      : new NotoInstance(this.paladin, receipt.contractAddress);
  }
}

export class NotoInstance {
  constructor(
    private paladin: PaladinClient,
    public readonly address: string
  ) {}

  using(paladin: PaladinClient) {
    return new NotoInstance(paladin, this.address);
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
    return this.paladin.pollForReceipt(txID, POLL_TIMEOUT_MS);
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
    return this.paladin.pollForReceipt(txID, POLL_TIMEOUT_MS);
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
    return this.paladin.pollForPreparedTransaction(txID, POLL_TIMEOUT_MS);
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
    return this.paladin.pollForReceipt(txID, POLL_TIMEOUT_MS);
  }
}
