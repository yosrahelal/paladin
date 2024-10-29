---
title: IndexedTransaction
---
{% include-markdown "./_includes/indexedtransaction_description.md" %}

### Example

```json
{
    "hash": "0x0000000000000000000000000000000000000000000000000000000000000000",
    "blockNumber": 0,
    "transactionIndex": 0,
    "from": null,
    "nonce": 0
}
```

### Field Descriptions

| Field Name | Description | Type |
|------------|-------------|------|
| `hash` | The unique hash of the transaction | [`Bytes32`](simpletypes.md#bytes32) |
| `blockNumber` | The block number containing this transaction | `int64` |
| `transactionIndex` | The index of the transaction within the block | `int64` |
| `from` | The sender's Ethereum address | [`EthAddress`](simpletypes.md#ethaddress) |
| `to` | The recipient's Ethereum address (optional) | [`EthAddress`](simpletypes.md#ethaddress) |
| `nonce` | The transaction nonce | `uint64` |
| `contractAddress` | The contract address created by this transaction (optional) | [`EthAddress`](simpletypes.md#ethaddress) |
| `result` | The result of the transaction (optional) | `"failure", "success"` |
| `block` | The block containing this event | [`IndexedBlock`](indexedblock.md#indexedblock) |

