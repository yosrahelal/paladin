---
title: ABIDecodedData
---
{% include-markdown "./_includes/abidecodeddata_description.md" %}

### Example

```json
{
    "data": null,
    "definition": null,
    "signature": ""
}
```

### Field Descriptions

| Field Name | Description | Type |
|------------|-------------|------|
| `data` | The decoded JSON data using the matched ABI definition | [`RawJSON`](simpletypes.md#rawjson) |
| `summary` | A string formatted summary - errors only | `string` |
| `definition` | The ABI definition entry matched from the dictionary of ABIs | [`Entry`](transactioninput.md#entry) |
| `signature` | The signature of the matched ABI definition | `string` |

