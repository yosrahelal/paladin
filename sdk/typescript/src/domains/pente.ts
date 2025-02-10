import { randomBytes } from "crypto";
import { ethers } from "ethers";
import {
  IGroupInfo,
  IGroupInfoUnresolved,
  TransactionType,
} from "../interfaces";
import PaladinClient from "../paladin";
import * as penteJSON from "./abis/PentePrivacyGroup.json";
import { PaladinVerifier } from "../verifier";

const DEFAULT_POLL_TIMEOUT = 10000;

export interface PenteGroupTransactionInput {
  from: string;
  methodAbi: ethers.JsonFragment;
  to: string;
  data: {
    [key: string]: any;
  };
}

export interface PenteContractTransactionInput {
  from: string;
  function: string;
  data?: {
    [key: string]: any;
  };
}

export interface PenteDeploy {
  abi: ReadonlyArray<ethers.JsonFragment>;
  bytecode: string,
  from: string;
  inputs?: any;
} 
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

export interface PentePrivacyGroupParams {
  group: IGroupInfo | IGroupInfoUnresolved;
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

  async newPrivacyGroup(from: PaladinVerifier, data: PentePrivacyGroupParams) {
    const txID = await this.paladin.sendTransaction({
      type: TransactionType.PRIVATE,
      domain: this.domain,
      abi: [penteConstructorABI],
      function: "",
      from: from.lookup,
      data: {
        ...data,
        group: resolveGroup(data.group),
      },
    });
    const receipt = await this.paladin.pollForReceipt(
      txID,
      this.options.pollTimeout
    );
    return receipt?.contractAddress === undefined
      ? undefined
      : new PentePrivacyGroup(
          this.paladin,
          resolveGroup(data.group),
          receipt.contractAddress,
          this.options
        );
  }
}

export class PentePrivacyGroup {
  private options: Required<PenteOptions>;

  constructor(
    private paladin: PaladinClient,
    public readonly group: IGroupInfo,
    public readonly address: string,
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
      this.group,
      this.address,
      this.options
    );
  }

  // deploy a contract
  // async deploy<ConstructorParams>(
  //   abi: ReadonlyArray<ethers.JsonFragment>,
  //   bytecode: string,
  //   from: PaladinVerifier,
  //   inputs?: ConstructorParams
  // ) {
  
  async deploy(params: PenteDeploy) {

      // Find the constructor in the ABI
    const constructor = params.abi.find((entry) => entry.type === "constructor");

    // Handle the absence of a constructor
    const constructorInputs = constructor?.inputs ?? [];
    const bytecode = params.bytecode;

    // Prepare the data object
    const data: Record<string, any> = {
      group: this.group,
      bytecode,
      inputs: params.inputs ?? [], // Ensure `inputs` is always included, defaulting to an empty array
    };

    const txID = await this.paladin.sendTransaction({
      type: TransactionType.PRIVATE,
      abi: [privateDeployABI(constructorInputs ?? [])],
      function: "deploy",
      to: this.address,
      from: params.from,
      data: data
    });
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
  async sendTransaction(transaction: PenteGroupTransactionInput){ 
    const inputs = transaction.data;  
    const to = transaction.to;  
      const txID = await this.paladin.sendTransaction({
        type: TransactionType.PRIVATE,
        abi: [privateInvokeABI(transaction.methodAbi.name ?? "", transaction.methodAbi.inputs ?? [])],
        function: "",
        to: this.address,
        from: transaction.from,
        data: { group: this.group, to, inputs },
      });
      return this.paladin.pollForReceipt(txID, this.options.pollTimeout);
  }

  // call functions in the contract (read-only)
  async call(transaction: PenteGroupTransactionInput){ 
    const to = transaction.to;
    const inputs = transaction.data;
    return this.paladin.call({
      type: TransactionType.PRIVATE,
      abi: [
        privateCallABI(
          transaction.methodAbi.name ?? "",
          transaction.methodAbi.inputs ?? [],
          transaction.methodAbi.outputs ?? []
        ),
      ],
      function: "",
      to: this.address,
      from: transaction.from,
      data: { group: this.group, to, inputs }
    });
  }

  async approveTransition(
    from: PaladinVerifier,
    data: PenteApproveTransitionParams
  ) {
    const txID = await this.paladin.sendTransaction({
      type: TransactionType.PUBLIC,
      abi: penteJSON.abi,
      function: "approveTransition",
      to: this.address,
      from: from.lookup,
      data,
    });
    return this.paladin.pollForReceipt(txID, this.options.pollTimeout);
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

  async sendTransaction(transaction: PenteContractTransactionInput){ 
    const method = this.abi.find((entry) => entry.name === transaction.function);
    if (method === undefined) {
      throw new Error(`Method '${transaction.function}' not found`);
    }
    return this.evm.sendTransaction({
      from: transaction.from,
      to: this.address,
      methodAbi: method,
      data: transaction.data ?? []
    });
  }

  async call(transaction: PenteContractTransactionInput){ 
    const method = this.abi.find((entry) => entry.name === transaction.function);
    if (method === undefined) {
      throw new Error(`Method '${transaction.function}' not found`);
    }
    return this.evm.call({
      from: transaction.from,
      to: this.address,
      methodAbi: method,
      data: transaction.data ?? []
    });
  }
}
