---
title: EventWithData
---
{% include-markdown "./_includes/eventwithdata_description.md" %}

### Example

```json
{
    "soliditySignature": "",
    "address": "0x0000000000000000000000000000000000000000",
    "data": null
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
| `soliditySignature` | A Solidity style description of the event and parameters, including parameter names and whether they are indexed | `string` |
| `address` | The address of the smart contract that emitted this event | [`EthAddress`](simpletypes.md#ethaddress) |
| `data` | JSON formatted data from the event | [`RawJSON`](simpletypes.md#rawjson) |

