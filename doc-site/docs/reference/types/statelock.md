---
title: StateLock
---
{% include-markdown "./_includes/statelock_description.md" %}

### Example

```json
{
    "transaction": "00000000-0000-0000-0000-000000000000",
    "type": ""
}
```

### Field Descriptions

| Field Name | Description | Type |
|------------|-------------|------|
| `transaction` | The ID of the Paladin transaction being assembled that is responsible for this lock | [`UUID`](simpletypes.md#uuid) |
| `type` | Whether this lock is for create, read or spend | `Enum[github.com/kaleido-io/paladin/toolkit/pkg/pldapi.StateLockType]` |

