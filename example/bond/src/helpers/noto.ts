import { ethers } from "ethers";
import PaladinClient, {
  IGroupInfo,
  IStateBase,
  IStateWithData,
  TransactionType,
} from "paladin-sdk";
import * as notoPrivateABI from "../abis/INotoPrivate.json";
import { encodeHex } from "../utils";
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
  inputs: IStateWithData[];
  outputs: IStateWithData[];
  data: string;
  delegate: string;
}

export interface NotoCoinData {
  salt: string;
  owner: string;
  amount: string;
}

export const encodeStates = (states: IStateBase[]): IStateWithData[] => {
  return states.map((state) => ({
    id: state.id,
    schema: state.schema,
    data: encodeHex(JSON.stringify(state.data as NotoCoinData)),
  }));
};

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
      : new NotoHelper(this.paladin, receipt.contractAddress);
  }
}

export class NotoHelper {
  constructor(
    private paladin: PaladinClient,
    public readonly address: string
  ) {}

  using(paladin: PaladinClient) {
    return new NotoHelper(paladin, this.address);
  }

  async mint(from: string, data: NotoMintParams) {
    const txID = await this.paladin.sendTransaction({
      type: TransactionType.PRIVATE,
      abi: notoPrivateABI.abi,
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
      abi: notoPrivateABI.abi,
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
      abi: notoPrivateABI.abi,
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
      abi: notoPrivateABI.abi,
      function: "approveTransfer",
      to: this.address,
      from,
      data,
    });
    return this.paladin.pollForReceipt(txID, POLL_TIMEOUT_MS);
  }
}
