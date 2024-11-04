import PaladinClient, { IGroupInfo, TransactionType } from "paladin-sdk";

const POLL_TIMEOUT_MS = 10000;

export const groupTuple = {
  name: "group",
  type: "tuple",
  components: [
    { name: "salt", type: "bytes32" },
    { name: "members", type: "string[]" },
  ],
};

export const notoABI = (withHooks: boolean) => [
  {
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
                  components: groupTuple.components,
                },
                { name: "publicAddress", type: "address" },
                { name: "privateAddress", type: "address" },
              ],
            },
          ]
        : []),
    ],
  },
  {
    type: "function",
    name: "mint",
    inputs: [
      { name: "to", type: "string" },
      { name: "amount", type: "uint256" },
      { name: "data", type: "bytes" },
    ],
  },
  {
    type: "function",
    name: "transfer",
    inputs: [
      { name: "to", type: "string" },
      { name: "amount", type: "uint256" },
      { name: "data", type: "bytes" },
    ],
  },
  {
    type: "function",
    name: "approveTransfer",
    inputs: [
      {
        name: "inputs",
        type: "tuple[]",
        internalType: "struct FullState[]",
        components: [
          { name: "id", type: "bytes" },
          { name: "schema", type: "bytes32" },
          { name: "data", type: "bytes" },
        ],
      },
      {
        name: "outputs",
        type: "tuple[]",
        internalType: "struct FullState[]",
        components: [
          { name: "id", type: "bytes" },
          { name: "schema", type: "bytes32" },
          { name: "data", type: "bytes" },
        ],
      },
      { name: "data", type: "bytes" },
      { name: "delegate", type: "address" },
    ],
  },
];

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

export const newNoto = async (
  paladin: PaladinClient,
  domain: string,
  from: string,
  data: NotoConstructorParams
) => {
  const txID = await paladin.sendTransaction({
    type: TransactionType.PRIVATE,
    domain,
    abi: notoABI(false),
    function: "",
    from,
    data,
  });
  const receipt = await paladin.pollForReceipt(txID, POLL_TIMEOUT_MS);
  return receipt?.contractAddress === undefined
    ? undefined
    : new NotoHelper(paladin, receipt.contractAddress);
};

export class NotoHelper {
  constructor(
    private paladin: PaladinClient,
    public readonly address: string
  ) {}

  async mint(from: string, data: NotoMintParams) {
    const txID = await this.paladin.sendTransaction({
      type: TransactionType.PRIVATE,
      abi: notoABI(false),
      function: "mint",
      to: this.address,
      from,
      data,
    });
    return this.paladin.pollForReceipt(txID, POLL_TIMEOUT_MS);
  }
}
