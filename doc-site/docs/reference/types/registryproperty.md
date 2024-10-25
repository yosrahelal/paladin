---
title: RegistryProperty
---
{% include-markdown "./_includes/registryproperty_description.md" %}

### Example

```json
{
    "registry": "",
    "entryId": "0x",
    "name": "",
    "value": ""
}
```

### Field Descriptions

| Field Name | Description | Type |
|------------|-------------|------|
| `registry` | The registry that maintains this record | `string` |
| `entryId` | The ID of the entry this property is associated with | [`HexBytes`](simpletypes.md#hexbytes) |
| `name` | The name of the property | `string` |
| `value` | The value of the property | `string` |
| `blockNumber` | For Ethereum blockchain backed registries, this is the block number where the registry entry/property was set | `int64` |
| `transactionIndex` | The transaction index within the block | `int64` |
| `logIndex` | The log index within the transaction of the event | `int64` |
| `active` | When querying with an activeFilter of 'any' or 'inactive', this boolean shows if the entry/property is active or not | `bool` |

