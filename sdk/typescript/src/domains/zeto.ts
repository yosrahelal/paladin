import { TransactionType } from "../interfaces";
import PaladinClient from "../paladin";

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

const zetoPublicAbi = [{
  "inputs": [
    {
      "internalType": "contract IERC20",
      "name": "_erc20",
      "type": "address"
    }
  ],
  "name": "setERC20",
  "outputs": [],
  "stateMutability": "nonpayable",
  "type": "function"
}];

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

export interface ZetoSetERC20Params {
  _erc20: string;
}

export interface ZetoTransfer {
  to: string;
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

  async newZeto(from: string, data: ZetoConstructorParams) {
    const txID = await this.paladin.sendTransaction({
      type: TransactionType.PRIVATE,
      domain: this.domain,
      abi: [zetoConstructorABI],
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

  async mint(from: string, data: ZetoMintParams) {
    const txID = await this.paladin.sendTransaction({
      type: TransactionType.PRIVATE,
      abi: zetoPrivateAbi,
      function: "mint",
      to: this.address,
      from,
      data,
    });
    return this.paladin.pollForReceipt(txID, this.options.pollTimeout);
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
    return this.paladin.pollForReceipt(txID, this.options.pollTimeout);
  }

  async setERC20(from: string, data: ZetoSetERC20Params) {
    const txID = await this.paladin.sendTransaction({
      type: TransactionType.PUBLIC,
      abi: zetoPublicAbi,
      function: "setERC20",
      to: this.address,
      from,
      data,
    });
    return this.paladin.pollForReceipt(txID, DEFAULT_POLL_TIMEOUT);
  }
}
