---
title: OnChainLocation
---
{% include-markdown "./_includes/onchainlocation_description.md" %}

### Example

```json
{
    "blockNumber": 0,
    "transactionIndex": 0,
    "logIndex": 0
}
```

### Field Descriptions

| Field Name | Description | Type |
|------------|-------------|------|
| `blockNumber` | For Ethereum blockchain backed registries, this is the block number where the registry entry/property was set | `int64` |
| `transactionIndex` | The transaction index within the block | `int64` |
| `logIndex` | The log index within the transaction of the event | `int64` |

