---
title: Schema
---
{% include-markdown "./_includes/schema_description.md" %}

### Example

```json
{
    "id": "0x0000000000000000000000000000000000000000000000000000000000000000",
    "created": 0,
    "domain": "",
    "type": "",
    "signature": "",
    "definition": null,
    "labels": null
}
```

### Field Descriptions

| Field Name | Description | Type |
|------------|-------------|------|
| `id` | The hash derived ID of the schema (query only) | [`Bytes32`](simpletypes.md#bytes32) |
| `created` | Server-generated creation timestamp for this schema (query only) | [`Timestamp`](simpletypes.md#timestamp) |
| `domain` | The name of the domain this schema is managed by | `string` |
| `type` | The type of the schema, such as if it is an ABI defined schema | `"abi"` |
| `signature` | Human readable signature string for this schema, that is used to generate the hash | `string` |
| `definition` | The definition of the schema, such as the ABI definition | [`RawJSON`](simpletypes.md#rawjson) |
| `labels` | The list of indexed labels that can be used to filter and sort states using to this schema | `string[]` |

