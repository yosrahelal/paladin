import { TransactionType } from "../interfaces";
import PaladinClient from "../paladin";
import { PaladinVerifier } from "../verifier";

const DEFAULT_POLL_TIMEOUT = 10000;

export interface ZetoOptions {
  pollTimeout?: number;
}

const zetoPrivateAbi = [
  {
    name: "mint",
    type: "function",
    inputs: [
      {
        name: "mints",
        type: "tuple[]",
        components: [
          {
            name: "to",
            type: "string",
            internalType: "string",
          },
          {
            name: "amount",
            type: "uint256",
            internalType: "uint256",
          },
        ],
      },
    ],
    outputs: [],
  },
  {
    type: "function",
    name: "transfer",
    inputs: [
      {
        name: "transfers",
        type: "tuple[]",
        components: [
          {
            name: "to",
            type: "string",
            internalType: "string",
          },
          {
            name: "amount",
            type: "uint256",
            internalType: "uint256",
          },
        ],
      },
    ],
    outputs: [],
  },
];

export const zetoConstructorABI = {
  type: "constructor",
  inputs: [{ name: "tokenName", type: "string" }],
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
  to: PaladinVerifier;
  amount: string | number;
}

export class ZetoFactory {
  private options: Required<ZetoOptions>;

  constructor(
    private paladin: PaladinClient,
    public readonly domain: string,
    options?: ZetoOptions
  ) {
    this.options = {
      pollTimeout: DEFAULT_POLL_TIMEOUT,
      ...options,
    };
  }

  using(paladin: PaladinClient) {
    return new ZetoFactory(paladin, this.domain, this.options);
  }

  async newZeto(from: PaladinVerifier, data: ZetoConstructorParams) {
    const txID = await this.paladin.sendTransaction({
      type: TransactionType.PRIVATE,
      domain: this.domain,
      abi: [zetoConstructorABI],
      function: "",
      from: from.lookup,
      data,
    });
    const receipt = await this.paladin.pollForReceipt(
      txID,
      this.options.pollTimeout
    );
    return receipt?.contractAddress === undefined
      ? undefined
      : new ZetoInstance(this.paladin, receipt.contractAddress, this.options);
  }
}

export class ZetoInstance {
  private options: Required<ZetoOptions>;

  constructor(
    private paladin: PaladinClient,
    public readonly address: string,
    options?: ZetoOptions
  ) {
    this.options = {
      pollTimeout: DEFAULT_POLL_TIMEOUT,
      ...options,
    };
  }

  using(paladin: PaladinClient) {
    return new ZetoInstance(paladin, this.address, this.options);
  }

  async mint(from: PaladinVerifier, data: ZetoMintParams) {
    const txID = await this.paladin.sendTransaction({
      type: TransactionType.PRIVATE,
      abi: zetoPrivateAbi,
      function: "mint",
      to: this.address,
      from: from.lookup,
      data: {
        mints: data.mints.map((t) => ({ ...t, to: t.to.lookup })),
      },
    });
    return this.paladin.pollForReceipt(txID, this.options.pollTimeout);
  }

  async transfer(from: PaladinVerifier, data: ZetoTransferParams) {
    const txID = await this.paladin.sendTransaction({
      type: TransactionType.PRIVATE,
      abi: zetoPrivateAbi,
      function: "transfer",
      to: this.address,
      from: from.lookup,
      data: {
        transfers: data.transfers.map((t) => ({ ...t, to: t.to.lookup })),
      },
    });
    return this.paladin.pollForReceipt(txID, this.options.pollTimeout);
  }
}
