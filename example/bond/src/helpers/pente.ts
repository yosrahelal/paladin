import PaladinClient, { IGroupInfo, TransactionType } from "paladin-sdk";

const POLL_TIMEOUT_MS = 10000;

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

export const penteDeployABI = (inputComponents: any) => ({
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

export type PentePrivacyGroupParams = [IGroupInfo, string, string, boolean];

export const newPentePrivacyGroup = async (
  paladin: PaladinClient,
  domain: string,
  from: string,
  data: PentePrivacyGroupParams
) => {
  const txID = await paladin.sendTransaction({
    type: TransactionType.PRIVATE,
    domain: "pente",
    abi: [penteConstructorABI],
    function: "",
    from,
    data,
  });
  const receipt = await paladin.pollForReceipt(txID, POLL_TIMEOUT_MS);
  return receipt?.contractAddress === undefined
    ? undefined
    : new PentePrivacyGroupHelper(paladin, data[0], receipt.contractAddress);
};

export class PentePrivacyGroupHelper {
  constructor(
    private paladin: PaladinClient,
    public readonly group: IGroupInfo,
    public readonly address: string
  ) {}

  async deploy(
    from: string,
    constructorAbi: any,
    bytecode: string,
    inputs: any
  ) {
    const txID = await this.paladin.sendTransaction({
      type: TransactionType.PRIVATE,
      abi: [penteDeployABI(constructorAbi?.inputs)],
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
}
