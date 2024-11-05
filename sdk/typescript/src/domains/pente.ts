import { ethers } from "ethers";
import { IGroupInfo, TransactionType } from "../interfaces";
import PaladinClient from "../paladin";
import * as penteJSON from "./abis/PentePrivacyGroup.json";

const POLL_TIMEOUT_MS = 5000;

export const penteGroupABI = {
  name: "group",
  type: "tuple",
  components: [
    { name: "salt", type: "bytes32" },
    { name: "members", type: "string[]" },
  ],
};

export const penteConstructorABI = {
  type: "constructor",
  inputs: [
    penteGroupABI,
    { name: "evmVersion", type: "string" },
    { name: "endorsementType", type: "string" },
    { name: "externalCallsEnabled", type: "bool" },
  ],
};

export const privateDeployABI = (
  inputComponents: ReadonlyArray<ethers.JsonFragmentType>
): ethers.JsonFragment => ({
  name: "deploy",
  type: "function",
  inputs: [
    penteGroupABI,
    { name: "bytecode", type: "bytes" },
    { name: "inputs", type: "tuple", components: inputComponents },
  ],
});

const privateInvokeABI = (
  name: string,
  inputComponents: ReadonlyArray<ethers.JsonFragmentType>
): ethers.JsonFragment => ({
  name,
  type: "function",
  inputs: [
    penteGroupABI,
    { name: "to", type: "address" },
    { name: "inputs", type: "tuple", components: inputComponents },
  ],
});

const privateCallABI = (
  name: string,
  inputComponents: ReadonlyArray<ethers.JsonFragmentType>,
  outputComponents: ReadonlyArray<ethers.JsonFragmentType>
): ethers.JsonFragment => ({
  name,
  type: "function",
  inputs: [
    penteGroupABI,
    { name: "to", type: "address" },
    { name: "inputs", type: "tuple", components: inputComponents },
  ],
  outputs: outputComponents,
});

export interface PentePrivacyGroupParams {
  group: IGroupInfo;
  evmVersion: string;
  endorsementType: string;
  externalCallsEnabled: boolean;
}

export interface PenteApproveTransitionParams {
  txId: string;
  delegate: string;
  transitionHash: string;
  signatures: string[];
}

export class PenteFactory {
  constructor(private paladin: PaladinClient, public readonly domain: string) {}

  using(paladin: PaladinClient) {
    return new PenteFactory(paladin, this.domain);
  }

  async newPrivacyGroup(from: string, data: PentePrivacyGroupParams) {
    const txID = await this.paladin.sendTransaction({
      type: TransactionType.PRIVATE,
      domain: this.domain,
      abi: [penteConstructorABI],
      function: "",
      from,
      data,
    });
    const receipt = await this.paladin.pollForReceipt(txID, POLL_TIMEOUT_MS);
    return receipt?.contractAddress === undefined
      ? undefined
      : new PentePrivacyGroup(
          this.paladin,
          data.group,
          receipt.contractAddress
        );
  }
}

export class PentePrivacyGroup {
  constructor(
    private paladin: PaladinClient,
    public readonly group: IGroupInfo,
    public readonly address: string
  ) {}

  using(paladin: PaladinClient) {
    return new PentePrivacyGroup(paladin, this.group, this.address);
  }

  async deploy<ConstructorParams>(
    abi: ReadonlyArray<ethers.JsonFragment>,
    bytecode: string,
    from: string,
    inputs: ConstructorParams
  ) {
    const constructor = abi.find((entry) => entry.type === "constructor");
    if (constructor === undefined) {
      throw new Error("Constructor not found");
    }
    const txID = await this.paladin.sendTransaction({
      type: TransactionType.PRIVATE,
      abi: [privateDeployABI(constructor.inputs ?? [])],
      function: "deploy",
      to: this.address,
      from,
      data: { group: this.group, bytecode, inputs },
    });
    const receipt = await this.paladin.pollForReceipt(
      txID,
      POLL_TIMEOUT_MS,
      true
    );
    return receipt?.domainReceipt?.receipt.contractAddress;
  }

  async invoke<Params>(
    from: string,
    to: string,
    methodAbi: ethers.JsonFragment,
    inputs: Params
  ) {
    const txID = await this.paladin.sendTransaction({
      type: TransactionType.PRIVATE,
      abi: [privateInvokeABI(methodAbi.name ?? "", methodAbi.inputs ?? [])],
      function: "",
      to: this.address,
      from,
      data: { group: this.group, to, inputs },
    });
    return this.paladin.pollForReceipt(txID, POLL_TIMEOUT_MS);
  }

  async call<Params>(
    from: string,
    to: string,
    methodAbi: ethers.JsonFragment,
    inputs: Params
  ) {
    return this.paladin.call({
      type: TransactionType.PRIVATE,
      abi: [
        privateCallABI(
          methodAbi.name ?? "",
          methodAbi.inputs ?? [],
          methodAbi.outputs ?? []
        ),
      ],
      function: "",
      to: this.address,
      from,
      data: { group: this.group, to, inputs },
    });
  }

  async approveTransition(from: string, data: PenteApproveTransitionParams) {
    const txID = await this.paladin.sendTransaction({
      type: TransactionType.PUBLIC,
      abi: penteJSON.abi,
      function: "approveTransition",
      to: this.address,
      from,
      data,
    });
    return this.paladin.pollForReceipt(txID, POLL_TIMEOUT_MS);
  }
}

export abstract class PentePrivateContract<ConstructorParams> {
  constructor(
    protected evm: PentePrivacyGroup,
    protected abi: ReadonlyArray<ethers.JsonFragment>,
    public readonly address: string
  ) {}

  abstract using(
    paladin: PaladinClient
  ): PentePrivateContract<ConstructorParams>;

  async invoke<Params>(from: string, methodName: string, params: Params) {
    const method = this.abi.find((entry) => entry.name === methodName);
    if (method === undefined) {
      throw new Error(`Method '${methodName}' not found`);
    }
    return this.evm.invoke(from, this.address, method, params);
  }

  async call<Params>(from: string, methodName: string, params: Params) {
    const method = this.abi.find((entry) => entry.name === methodName);
    if (method === undefined) {
      throw new Error(`Method '${methodName}' not found`);
    }
    return this.evm.call(from, this.address, method, params);
  }
}
