import PaladinClient, { IGroupInfo, TransactionType } from "paladin-sdk";
import { ethers } from "ethers";
import pente from "../abis/PentePrivacyGroup.json";

const POLL_TIMEOUT_MS = 5000;

export const penteConstructorABI = {
  type: "constructor",
  inputs: [
    {
      name: "group",
      type: "tuple",
      components: [
        { name: "salt", type: "bytes32" },
        { name: "members", type: "string[]" },
      ],
    },
    { name: "evmVersion", type: "string" },
    { name: "endorsementType", type: "string" },
    { name: "externalCallsEnabled", type: "bool" },
  ],
};

export const penteGroupABI = {
  name: "group",
  type: "tuple",
  components: [
    { name: "salt", type: "bytes32" },
    { name: "members", type: "string[]" },
  ],
};

export const penteDeployABI = (
  inputComponents: ReadonlyArray<ethers.JsonFragmentType>
): ethers.JsonFragment => ({
  name: "deploy",
  type: "function",
  inputs: [
    {
      name: "group",
      type: "tuple",
      components: [
        { name: "salt", type: "bytes32" },
        { name: "members", type: "string[]" },
      ],
    },
    { name: "bytecode", type: "bytes" },
    { name: "inputs", type: "tuple", components: inputComponents },
  ],
});

const penteInvokeABI = (
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

const penteCallABI = (
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
      : new PentePrivacyGroupHelper(
          this.paladin,
          data[0],
          receipt.contractAddress
        );
  }
}

export class PentePrivacyGroupHelper {
  constructor(
    private paladin: PaladinClient,
    public readonly group: IGroupInfo,
    public readonly address: string
  ) {}

  using(paladin: PaladinClient) {
    return new PentePrivacyGroupHelper(paladin, this.group, this.address);
  }

  async deploy(
    from: string,
    constructorAbi: ethers.JsonFragment & {
      inputs: ReadonlyArray<ethers.JsonFragmentType>;
    },
    bytecode: string,
    inputs: any
  ) {
    const txID = await this.paladin.sendTransaction({
      type: TransactionType.PRIVATE,
      abi: [penteDeployABI(constructorAbi.inputs)],
      function: "deploy",
      to: this.address,
      from,
      data: {
        group: this.group,
        bytecode,
        inputs,
      },
    });
    return this.paladin.pollForReceipt(txID, POLL_TIMEOUT_MS, true);
  }

  async invoke(
    from: string,
    to: string,
    methodAbi: ethers.JsonFragment & {
      inputs: ReadonlyArray<ethers.JsonFragmentType>;
    },
    inputs: any
  ) {
    const txID = await this.paladin.sendTransaction({
      type: TransactionType.PRIVATE,
      abi: [penteInvokeABI(methodAbi.name ?? "", methodAbi.inputs)],
      function: "",
      to: this.address,
      from,
      data: {
        group: this.group,
        to,
        inputs,
      },
    });
    return this.paladin.pollForReceipt(txID, POLL_TIMEOUT_MS);
  }

  async call(
    from: string,
    to: string,
    methodAbi: ethers.JsonFragment & {
      inputs: ReadonlyArray<ethers.JsonFragmentType>;
      outputs: ReadonlyArray<ethers.JsonFragmentType>;
    },
    inputs: any
  ) {
    return this.paladin.call({
      type: TransactionType.PRIVATE,
      abi: [
        penteCallABI(methodAbi.name ?? "", methodAbi.inputs, methodAbi.outputs),
      ],
      function: "",
      to: this.address,
      from,
      data: {
        group: this.group,
        to,
        inputs,
      },
    });
  }

  async approveTransition(from: string, data: PenteApproveTransitionParams) {
    const txID = await this.paladin.sendTransaction({
      type: TransactionType.PUBLIC,
      abi: pente.abi,
      function: "approveTransition",
      to: this.address,
      from,
      data,
    });
    return this.paladin.pollForReceipt(txID, POLL_TIMEOUT_MS);
  }
}
