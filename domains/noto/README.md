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

The constructor is invoked by specifying `"function": ""`.

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

Mint new value.

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

Transfer value from the sender to another recipient.

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

The public ABI of Noto is implemented in Solidity, and can be accessed by calling `ptx_sendTransaction`
with `"type": "public"`. However, it is not often required to invoke the public ABI directly.

### mint

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

### transfer

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

### approveTransfer

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

### transferWithApproval

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
