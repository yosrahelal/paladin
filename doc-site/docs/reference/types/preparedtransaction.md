---
title: PreparedTransaction
---
{% include-markdown "./_includes/preparedtransaction_description.md" %}

### Example

```json
{
    "id": "00000000-0000-0000-0000-000000000000",
    "domain": "",
    "to": null,
    "transaction": {},
    "states": {}
}
```

### Field Descriptions

| Field Name | Description | Type |
|------------|-------------|------|
| `id` | The ID of the original transaction that prepared this transaction, and will be confirmed by its submission to the blockchain | [`UUID`](simpletypes.md#uuid) |
| `domain` | The domain of the original transaction that prepared this transaction submission | `string` |
| `to` | The to address or the original transaction that prepared this transaction submission | [`EthAddress`](simpletypes.md#ethaddress) |
| `transaction` | The Paladin transaction definition that has been prepared for submission, with the ABI and function details resolved | [`TransactionInput`](transactioninput.md#transactioninput) |
| `extraData` | Domain specific additional information that is created during preparation of the transaction is required as part of a coordination submission, particular pre-approval in atomic multi-party transactions | [`RawJSON`](simpletypes.md#rawjson) |
| `states` | Details of all states of the original transaction that prepared this transaction submission | [`TransactionStates`](transactionstates.md#transactionstates) |

