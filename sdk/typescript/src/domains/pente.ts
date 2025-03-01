import { randomBytes } from "crypto";
import { ethers } from "ethers";
import {
  IGroupInfo,
  IGroupInfoUnresolved
} from "../interfaces";
import { IPrivacyGroupEVMCall, IPrivacyGroupEVMTXInput, IPrivacyGroupInput } from "../interfaces/privacygroups";
import PaladinClient from "../paladin";
import { PaladinVerifier } from "../verifier";

const DEFAULT_POLL_TIMEOUT = 10000;

export interface PenteOptions {
  pollTimeout?: number;
}

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

export interface PentePrivacyGroupParams extends IPrivacyGroupInput {
  properties: {
    salt?: string;
    members: [string | PaladinVerifier][];
    pente: {
      evmVersion: string;
      endorsementType: string;
      externalCallsEnabled: boolean;          
    }
    [x: string]: unknown;
  }
}

export interface PenteApproveTransitionParams {
  txId: string;
  delegate: string;
  transitionHash: string;
  signatures: string[];
}

export const newGroupSalt = () =>
  "0x" + Buffer.from(randomBytes(32)).toString("hex");

export const resolveGroup = (
  group: IGroupInfo | IGroupInfoUnresolved
): IGroupInfo => {
  const members: string[] = [];
  for (const member of group.members) {
    if (typeof member === "string") {
      members.push(member);
    } else {
      members.push(member.lookup);
    }
  }
  return { members, salt: group.salt };
};

export class PenteFactory {
  private options: Required<PenteOptions>;

  constructor(
    private paladin: PaladinClient,
    public readonly domain: string,
    options?: PenteOptions
  ) {
    this.options = {
      pollTimeout: DEFAULT_POLL_TIMEOUT,
      ...options,
    };
  }

  using(paladin: PaladinClient) {
    return new PenteFactory(paladin, this.domain, this.options);
  }

  async newPrivacyGroup(input: PentePrivacyGroupParams) {
    
    const group = await this.paladin.createPrivacyGroup({
      domain: this.domain,
      members: input.members,
    });
    const receipt = group.genesisTransaction ? await this.paladin.pollForReceipt(
      group.genesisTransaction,
      this.options.pollTimeout
    ) : undefined;
    return receipt?.contractAddress === undefined
      ? undefined
      : new PentePrivacyGroup(
          this.paladin,
          receipt.id,
          this.options
        );
  }
}

export class PentePrivacyGroup {
  private options: Required<PenteOptions>;

  constructor(
    private paladin: PaladinClient,
    public readonly id: string,
    options?: PenteOptions
  ) {
    this.options = {
      pollTimeout: DEFAULT_POLL_TIMEOUT,
      ...options,
    };
  }

  using(paladin: PaladinClient) {
    return new PentePrivacyGroup(
      paladin,
      this.id,
      this.options
    );
  }
  
  async deploy(transaction: IPrivacyGroupEVMTXInput) {

    const txID = await this.paladin.sendPrivacyGroupTransaction(transaction);
    const receipt = await this.paladin.pollForReceipt(
      txID,
      this.options.pollTimeout,
      true
    );
    return receipt?.domainReceipt !== undefined &&
      "receipt" in receipt.domainReceipt
      ? receipt.domainReceipt.receipt.contractAddress
      : undefined;
  }

  // sendTransaction functions in the contract (write)
  async sendTransaction(transaction: IPrivacyGroupEVMTXInput){ 
    const txID = await this.paladin.sendPrivacyGroupTransaction(transaction);
      return this.paladin.pollForReceipt(txID, this.options.pollTimeout);
  }

  // call functions in the contract (read-only)
  async call(call: IPrivacyGroupEVMCall) { 
    return this.paladin.callPrivacyGroup(call);
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

  async sendTransaction(functionName: string, transaction: IPrivacyGroupEVMTXInput){ 
    const method = this.abi.find((entry) => entry.name === functionName);
    if (method === undefined) {
      throw new Error(`Method '${transaction.function}' not found`);
    }
    return this.evm.sendTransaction({
      ...transaction,
      function: method,
    });
  }

  async call(functionName: string, transaction: IPrivacyGroupEVMCall){ 
    const method = this.abi.find((entry) => entry.name === functionName);
    if (method === undefined) {
      throw new Error(`Method '${transaction.function}' not found`);
    }
    return this.evm.call({
      ...transaction,
      function: method,
    });
  }
}
