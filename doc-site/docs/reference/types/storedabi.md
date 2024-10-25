---
title: StoredABI
---
{% include-markdown "./_includes/storedabi_description.md" %}

### Example

```json
{
    "hash": "0x0000000000000000000000000000000000000000000000000000000000000000",
    "abi": [
        {
            "type": "function",
            "name": "name",
            "stateMutability": "pure",
            "inputs": null,
            "outputs": null
        }
    ]
}
```

### Field Descriptions

| Field Name | Description | Type |
|------------|-------------|------|
| `hash` | The unique hash of the ABI | [`Bytes32`](simpletypes.md#bytes32) |
| `abi` | The Application Binary Interface (ABI) definition | [`Entry[]`](transactioninput.md#entry) |

