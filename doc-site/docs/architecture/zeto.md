# Zeto - Zero Knowledge Proof based tokens

Zeto is a UTXO based privacy-preserving token toolkit for EVM, using Zero Knowledge Proofs, implemented via Circom.

The architecture documentations for Zeto is being managed in a separate Github repository here:
https://github.com/kaleido-io/zeto

Zeto is a growing collection of token implementations that enforce a wide variety of token transaction policies including, but not limited to, mass conservation (for fungible tokens), preservation of asset properties during ownership transfer (for non-fungible tokens), KYC with privacy, and non-repudiation compliance. Each policy is expressed in zeto knowledge proof circuits using [Circom](https://iden3.io/circom). The list of policies and their corresponding token implementations will continue to grow to meet the needs of enterprise use cases.

## Paladin Support

Zeto tokens are natively supported by Paladin, as a domain implementation called "Zeto". The foundational operations of Zeto tokens, `mint`, `transfer` are supported in the initial Paladin release. Support for other operations such as `deposit`, `withdraw` will be added later.

As a client to Zeto tokens, Paladin has the following features built into the single runtime that runs alongside an Ethereum node:

- Tokens indexer: by the nature of a UTXO based design, an account's balance is not known by querying the smart contract, as is the case with ERC-20 tokens. Instead, the UTXOs must be indexed from confirmed onchain transactions in order for an account to know the balance, by adding together all the tokens that belong to that account.
- Token selector: when sending a transaction that transfers certain amount to another account, the transaction input is made up of a collection of UTXOs that will be spent. The UTXOs must be selected from the unspent UTXOs that the account holds. The selection process needs to take into account the intend transfer amount and the values of the available tokens.
- ZK proof generator: each Zeto transaction must be accompanied by a ZK proof to demonstrate the validity of the transaction proposal. This is accomplished by a proof generator that is able to use the secrets known only to the Paladin runtime hosting the account key, as private input to the ZKP circuit.

## Private ABI

The private ABI of Zeto is implemented in [Go](https://github.com/LF-Decentralized-Trust-labs/paladin/tree/main/domains/zeto), and can be accessed by calling `ptx_sendTransaction` with `"type": "private"`.

### constructor

Creates a new Zeto token contract, with a new address on the base ledger.

```json
{
  "name": "",
  "type": "constructor",
  "inputs": [{ "name": "tokenName", "type": "string" }]
}
```

Inputs:

- **tokenName** - name of the Zeto token contract names. As of the current release, the following token contracts are supported:
  - [Zeto_Anon](https://github.com/hyperledger-labs/zeto?tab=readme-ov-file#zeto_anon)
  - [Zeto_AnonEnc](https://github.com/hyperledger-labs/zeto?tab=readme-ov-file#zeto_anonenc)
  - [Zeto_AnonNullifier](https://github.com/hyperledger-labs/zeto?tab=readme-ov-file#zeto_anonnullifier)

### mint

Mint new value. New UTXO state(s) will automatically be created to fulfill the requested mint.

```json
{
  "name": "mint",
  "type": "function",
  "inputs": [
    {
      "name": "mints",
      "type": "tuple[]",
      "components": [
        {
          "name": "to",
          "type": "string",
          "internalType": "string"
        },
        {
          "name": "amount",
          "type": "uint256",
          "internalType": "uint256"
        }
      ]
    },
    {
      "name": "data",
      "type": "bytes"
    }
  ]
}
```

Inputs:

- **mints** - list of mints, each with a receiver name and amount
  - **to** - lookup string for the identity that will receive minted value
  - **amount** - amount of new value to create
- **data** - user/application data to include with the transaction (will be accessible from an "info" state in the state receipt)

### transfer

Transfer value from the sender to another recipient. Available UTXO states will be selected for spending, and new UTXO states will be created, in order to facilitate the requested transfer of value.

```json
{
  "type": "function",
  "name": "transfer",
  "inputs": [
    {
      "name": "transfers",
      "type": "tuple[]",
      "components": [
        {
          "name": "to",
          "type": "string",
          "internalType": "string"
        },
        {
          "name": "amount",
          "type": "uint256",
          "internalType": "uint256"
        }
      ]
    },
    {
      "name": "data",
      "type": "bytes"
    }
  ],
  "outputs": null
}
```

Inputs:

- **transfers** - list of transfers, each with a receiver name and amount
  - **to** - lookup string for the identity that will receive transferred value
  - **amount** - amount of value to transfer
- **data** - user/application data to include with the transaction (will be accessible from an "info" state in the state receipt)
