---
title: RegistryEntry
---
{% include-markdown "./_includes/registryentry_description.md" %}

### Example

```json
{
    "registry": "",
    "id": "0x",
    "name": "",
    "blockNumber": 0,
    "transactionIndex": 0,
    "logIndex": 0
}
```

### Field Descriptions

| Field Name | Description | Type |
|------------|-------------|------|
| `registry` | The registry that maintains this record | `string` |
| `id` | The ID of the entry, which is unique within the registry across all records in the hierarchy | [`HexBytes`](simpletypes.md#hexbytes) |
| `name` | The name of the entry, which is unique across entries with the same parent | `string` |
| `parentId` | Unset for a root record, otherwise a reference to another entity in the same registry | [`HexBytes`](simpletypes.md#hexbytes) |
| `blockNumber` | For Ethereum blockchain backed registries, this is the block number where the registry entry/property was set | `int64` |
| `transactionIndex` | The transaction index within the block | `int64` |
| `logIndex` | The log index within the transaction of the event | `int64` |
| `active` | When querying with an activeFilter of 'any' or 'inactive', this boolean shows if the entry/property is active or not | `bool` |

