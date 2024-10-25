---
title: IndexedBlock
---
{% include-markdown "./_includes/indexedblock_description.md" %}

### Example

```json
{
    "number": 0,
    "hash": "0x0000000000000000000000000000000000000000000000000000000000000000",
    "timestamp": 0
}
```

### Field Descriptions

| Field Name | Description | Type |
|------------|-------------|------|
| `number` | The block number | `int64` |
| `hash` | The unique hash of the block | [`Bytes32`](simpletypes.md#bytes32) |
| `timestamp` | The block timestamp | [`Timestamp`](simpletypes.md#timestamp) |

