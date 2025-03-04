---
title: PrivacyGroupInput
---
{% include-markdown "./_includes/privacygroupinput_description.md" %}

### Example

```json
{
    "domain": "",
    "members": null,
    "properties": null
}
```

### Field Descriptions

| Field Name | Description | Type |
|------------|-------------|------|
| `domain` | The domain that will manages the privacy group | `string` |
| `members` | The fully qualified identities of each member of the privacy group | `string[]` |
| `properties` | Properties to supply to the domain that will be included in the final genesis state of the group. Domains specify well known properties can override behavior. Indexed properties are queryable and should be used for lookup | [`RawJSON`](simpletypes.md#rawjson) |
| `propertiesABI` | Optional ABI for the supplied properties. If omitted then an ABI will be auto-generated based on the types of input, with the top-level properties automatically indexed | [`Parameter[]`](#parameter) |
| `transactionOptions` | Options that will be propagated to the final private transaction that is submitted after the domain has validated the input properties and generated the base private transaction | [`PrivacyGroupTXOptions`](#privacygrouptxoptions) |

## Parameter


## PrivacyGroupTXOptions


