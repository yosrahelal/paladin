---
title: IndexedEvent
---
{% include-markdown "./_includes/indexedevent_description.md" %}

### Example

```json
{
    "blockNumber": 0,
    "transactionIndex": 0,
    "logIndex": 0,
    "transactionHash": "0x0000000000000000000000000000000000000000000000000000000000000000",
    "signature": "0x0000000000000000000000000000000000000000000000000000000000000000"
}
```

### Field Descriptions

| Field Name | Description | Type |
|------------|-------------|------|
| `blockNumber` | The block number containing this event | `int64` |
| `transactionIndex` | The index of the transaction within the block | `int64` |
| `logIndex` | The log index of the event | `int64` |
| `transactionHash` | The hash of the transaction that triggered this event | [`Bytes32`](simpletypes.md#bytes32) |
| `signature` | The event signature | [`Bytes32`](simpletypes.md#bytes32) |
| `transaction` | The transaction that triggered this event (optional) | [`IndexedTransaction`](#indexedtransaction) |
| `block` | The block containing this event (optional) | [`IndexedBlock`](#indexedblock) |

## IndexedTransaction

| Field Name | Description | Type |
|------------|-------------|------|
| `hash` | The unique hash of the transaction | [`Bytes32`](simpletypes.md#bytes32) |
| `blockNumber` | The block number containing this transaction | `int64` |
| `transactionIndex` | The index of the transaction within the block | `int64` |
| `from` | The sender's Ethereum address | [`EthAddress`](simpletypes.md#ethaddress) |
| `to` | The recipient's Ethereum address (optional) | [`EthAddress`](simpletypes.md#ethaddress) |
| `nonce` | The transaction nonce | `uint64` |
| `contractAddress` | The contract address created by this transaction (optional) | [`EthAddress`](simpletypes.md#ethaddress) |
| `result` | The result of the transaction (optional) | `Enum[github.com/kaleido-io/paladin/toolkit/pkg/pldapi.EthTransactionResult]` |


## IndexedBlock

| Field Name | Description | Type |
|------------|-------------|------|
| `number` | The block number | `int64` |
| `hash` | The unique hash of the block | [`Bytes32`](simpletypes.md#bytes32) |


