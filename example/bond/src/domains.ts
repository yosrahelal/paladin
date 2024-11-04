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
