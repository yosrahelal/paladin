# Noto: Notarized Tokens

The Noto domain provides confidential UTXO tokens which are managed by a single party, referred
to as the notary. Each UTXO state (sometimes referred to as a "coin") encodes an owning address,
an amount, and a randomly-chosen salt. The states are identified on the base ledger only by a
hash of the state data, while the private state data is only exchanged via private channels.

The base ledger provides deterministic ordering, double-spend protection, and provable linkage
of state data to transactions. The private state data provides a record of ownership and value
transfer.

## Private ABI

The private ABI of Noto is implemented in Go, and can be accessed by calling `ptx_sendTransaction`
with `"type": "private"`.

### constructor

Creates a new Noto token, with a new address on the base ledger.

```json
{
    "name": "",
    "type": "constructor",
    "inputs": [
        {"name": "notary", "type": "string"},
        {"name": "implementation", "type": "string"},
        {"name": "restrictMinting", "type": "boolean"},
        {"name": "hooks", "type": "tuple", "components": [
            {"name": "privateGroup", "type": "tuple", "components": [
                {"name": "salt", "type": "bytes32"},
                {"name": "members", "type": "string[]"}
            ]},
            {"name": "publicAddress", "type": "address"},
            {"name": "privateAddress", "type": "address"}
        ]}
    ]
}
```

Inputs:

* **notary** - lookup string for the identity that will serve as the notary for this token instance. May be located at this node or another node.
* **implementation** - (optional) the name of a non-default Noto implementation that has previously been registered.
* **restrictMinting** - (optional - default true) only allow the notary to request mint.
* **hooks** - (optional) specify a [Pente](../pente) private smart contract that will be called for each Noto transaction, to provide custom logic and policies.

### mint

Mint new value. New UTXO state(s) will automatically be created to fulfill the requested mint.

```json
{
    "name": "mint",
    "type": "function",
    "inputs": [
        {"name": "to", "type": "string"},
        {"name": "amount", "type": "uint256"},
        {"name": "data", "type": "bytes"}
    ]
}
```

Inputs:

* **to** - lookup string for the identity that will receive minted value
* **amount** - amount of new value to create
* **data** - user/application data to include with the transaction (will be accessible from an "info" state in the state receipt)

### transfer

Transfer value from the sender to another recipient. Available UTXO states will be selected for spending, and
new UTXO states will be created, in order to facilitate the requested transfer of value.

```json
{
    "name": "transfer",
    "type": "function",
    "inputs": [
        {"name": "to", "type": "string"},
        {"name": "amount", "type": "uint256"},
        {"name": "data", "type": "bytes"}
    ]
}
```

Inputs:

* **to** - lookup string for the identity that will receive transferred value
* **amount** - amount of value to transfer
* **data** - user/application data to include with the transaction (will be accessible from an "info" state in the state receipt)

### approveTransfer

Approve a transfer to be executed by another party.

When calling `ptx_prepareTransaction()` to prepare a private `transfer`, the `metadata` of the prepared transaction
will include information on how to build a proper `approveTransfer` call. This allows preparing a transfer and then
delegating it to another party for execution.

```json
{
    "name": "approveTransfer",
    "type": "function",
    "inputs": [
        {"name": "inputs", "type": "tuple[]", "components": [
            {"name": "id", "type": "bytes"},
            {"name": "schema", "type": "bytes32"},
            {"name": "data", "type": "bytes"}
        ]},
        {"name": "outputs", "type": "tuple[]", "components": [
            {"name": "id", "type": "bytes"},
            {"name": "schema", "type": "bytes32"},
            {"name": "data", "type": "bytes"}
        ]},
        {"name": "data", "type": "bytes"},
        {"name": "delegate", "type": "address"}
    ]
}
```

Inputs:

* **inputs** - input states that will be spent
* **outputs** - output states that will be created
* **data** - encoded Paladin and/or user data
* **delegate** - address of the delegate party that will be able to execute this transaction once approved

## Public ABI

The public ABI of Noto is implemented in Solidity by [Noto.sol](../../solidity/contracts/domains/noto/Noto.sol),
and can be accessed by calling `ptx_sendTransaction` with `"type": "public"`. However, it is not often required
to invoke the public ABI directly.

### mint

Mint new UTXO states. Generally should not be called directly.

May only be invoked by the notary address.

```json
{
    "name": "mint",
    "type": "function",
    "inputs": [
        {"name": "outputs", "type": "bytes32[]"},
        {"name": "signature", "type": "bytes"},
        {"name": "data", "type": "bytes"}
    ]
}
```

Inputs:

* **outputs** - output states that will be created
* **signature** - sender's signature (not verified on-chain, but can be verified by anyone with the private state data)
* **data** - encoded Paladin and/or user data

### transfer

Spend some UTXO states and create new ones. Generally should not be called directly.

May only be invoked by the notary address.

```json
{
    "name": "transfer",
    "type": "function",
    "inputs": [
        {"name": "inputs", "type": "bytes32[]"},
        {"name": "outputs", "type": "bytes32[]"},
        {"name": "signature", "type": "bytes"},
        {"name": "data", "type": "bytes"}
    ]
}
```

Inputs:

* **inputs** - input states that will be spent
* **outputs** - output states that will be created
* **signature** - sender's signature (not verified on-chain, but can be verified by anyone with the private state data)
* **data** - encoded Paladin and/or user data

### approveTransfer

Approve a specific `transfer` transaction to be executed by a specific `delegate` address.
Generally should not be called directly.

The `txhash` should be computed as the EIP-712 hash of the intended transfer, using type:
`Transfer(bytes32[] inputs,bytes32[] outputs,bytes data)`.

May only be invoked by the notary address.

```json
{
    "name": "approveTransfer",
    "type": "function",
    "inputs": [
        {"name": "delegate", "type": "address"},
        {"name": "txhash", "type": "bytes32"},
        {"name": "signature", "type": "bytes"},
        {"name": "data", "type": "bytes"}
      ]
}
```

Inputs:

* **delegate** - address of the delegate party that will be able to execute this transaction once approved
* **txhash** - EIP-712 hash of the intended transfer, using type `Transfer(bytes32[] inputs,bytes32[] outputs,bytes data)`
* **signature** - sender's signature (not verified on-chain, but can be verified by anyone with the private state data)
* **data** - encoded Paladin and/or user data

### transferWithApproval

Execute a transfer that was previously approved.

The values of `inputs`, `outputs`, and `data` will be used to (re-)compute a `txhash`, which must exactly
match a `txhash` that was previously delegated to the sender via `approveTransfer`.

```json
{
    "name": "transferWithApproval",
    "type": "function",
    "inputs": [
        {"name": "inputs", "type": "bytes32[]"},
        {"name": "outputs", "type": "bytes32[]"},
        {"name": "signature", "type": "bytes"},
        {"name": "data", "type": "bytes"}
      ]
}
```

Inputs:

* **inputs** - input states that will be spent
* **outputs** - output states that will be created
* **signature** - sender's signature (not verified on-chain, but can be verified by anyone with the private state data)
* **data** - encoded Paladin and/or user data
