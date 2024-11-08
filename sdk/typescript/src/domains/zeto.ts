import { ethers } from "ethers";
import {
  IGroupInfo,
  IStateBase,
  IStateEncoded,
  TransactionType,
} from "../interfaces";
import PaladinClient from "../paladin";

const POLL_TIMEOUT_MS = 5000;

const zetoPrivateAbi = [{
  "name": "mint",
  "type": "function",
  "inputs": [
    {
      "name": "mints",
      "type": "tuple[]",
      "components": [
        {
          "name": "to",
          "type": "string",
          "internalType": "string"
        },
        {
          "name": "amount",
          "type": "uint256",
          "internalType": "uint256"
        }
      ]
    }
  ],
  "outputs": [],
}, {
  "type": "function",
  "name": "transfer",
  "inputs": [
    {
      "name": "transfers",
      "type": "tuple[]",
      "components": [
        {
          "name": "to",
          "type": "string",
          "internalType": "string"
        },
        {
          "name": "amount",
          "type": "uint256",
          "internalType": "uint256"
        }
      ]
    }
  ],
  "outputs": []
}]

export const zetoConstructorABI = {
  type: "constructor",
  inputs: [
    { name: "tokenName", type: "string" }
  ],
};

export interface ZetoConstructorParams {
  tokenName: string;
}

export interface ZetoMintParams {
  mints: ZetoTransfer[];
}

export interface ZetoTransferParams {
  transfers: ZetoTransfer[];
}

export interface ZetoTransfer {
  to: string;
  amount: string | number;
}

export class ZetoFactory {
  constructor(private paladin: PaladinClient, public readonly domain: string) { }

  using(paladin: PaladinClient) {
    return new ZetoFactory(paladin, this.domain);
  }

  async newZeto(from: string, data: ZetoConstructorParams) {
    const txID = await this.paladin.sendTransaction({
      type: TransactionType.PRIVATE,
      domain: this.domain,
      abi: [zetoConstructorABI],
      function: "",
      from,
      data,
    });
    const receipt = await this.paladin.pollForReceipt(txID, POLL_TIMEOUT_MS);
    return receipt?.contractAddress === undefined
      ? undefined
      : new ZetoInstance(this.paladin, receipt.contractAddress);
  }
}

export class ZetoInstance {
  constructor(
    private paladin: PaladinClient,
    public readonly address: string
  ) { }

  using(paladin: PaladinClient) {
    return new ZetoInstance(paladin, this.address);
  }

  async mint(from: string, data: ZetoMintParams) {
    const txID = await this.paladin.sendTransaction({
      type: TransactionType.PRIVATE,
      abi: zetoPrivateAbi,
      function: "mint",
      to: this.address,
      from,
      data,
    });
    return this.paladin.pollForReceipt(txID, POLL_TIMEOUT_MS);
  }

  async transfer(from: string, data: ZetoTransferParams) {
    const txID = await this.paladin.sendTransaction({
      type: TransactionType.PRIVATE,
      abi: zetoPrivateAbi,
      function: "transfer",
      to: this.address,
      from,
      data,
    });
    return this.paladin.pollForReceipt(txID, POLL_TIMEOUT_MS);
  }
}
