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
| `transaction` | The transaction that triggered this event (optional) | [`IndexedTransaction`](indexedtransaction.md#indexedtransaction) |
| `block` | The block containing this event | [`IndexedBlock`](indexedblock.md#indexedblock) |

