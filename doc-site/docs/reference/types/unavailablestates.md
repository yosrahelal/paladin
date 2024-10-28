---
title: UnavailableStates
---
{% include-markdown "./_includes/unavailablestates_description.md" %}

### Example

```json
{
    "confirmed": null,
    "read": null,
    "spent": null,
    "info": null
}
```

### Field Descriptions

| Field Name | Description | Type |
|------------|-------------|------|
| `confirmed` | The IDs of confirmed states created by this transaction, for which the private data is unavailable | [`HexBytes[]`](simpletypes.md#hexbytes) |
| `read` | The IDs of read states used by this transaction, for which the private data is unavailable | [`HexBytes[]`](simpletypes.md#hexbytes) |
| `spent` | The IDs of spent states consumed by this transaction, for which the private data is unavailable | [`HexBytes[]`](simpletypes.md#hexbytes) |
| `info` | The IDs of info states referenced in this transaction, for which the private data is unavailable | [`HexBytes[]`](simpletypes.md#hexbytes) |

