---
title: TransactionStates
---
{% include-markdown "./_includes/transactionstates_description.md" %}

### Example

```json
{}
```

### Field Descriptions

| Field Name | Description | Type |
|------------|-------------|------|
| `none` | No state reference records have been indexed for this transaction. Either the transaction has not been indexed, or it did not reference any states | `bool` |
| `spent` | Private state data for input states that were spent in this transaction | [`StateBase[]`](#statebase) |
| `read` | Private state data for states that were unspent and used during execution of this transaction, but were not spent by it | [`StateBase[]`](#statebase) |
| `confirmed` | Private state data for new states that were confirmed as new unspent states during this transaction | [`StateBase[]`](#statebase) |
| `info` | Private state data for states that were recorded as part of this transaction, and existed only as reference data during its execution. They were not validated as unspent during execution, or recorded as new unspent states | [`StateBase[]`](#statebase) |
| `unavailable` | If present, this contains information about states recorded as used by this transactions when indexing, but for which the private data is unavailable on this node | [`UnavailableStates`](#unavailablestates) |

## StateBase

| Field Name | Description | Type |
|------------|-------------|------|
| `id` | The ID of the state, which is generated from the content per the rules of the domain, and is unique within the contract | [`HexBytes`](simpletypes.md#hexbytes) |
| `created` | Server-generated creation timestamp for this state (query only) | [`Timestamp`](simpletypes.md#timestamp) |
| `domain` | The name of the domain this state is managed by | `string` |
| `schema` | The ID of the schema for this state, which defines what fields it has and which are indexed for query | [`Bytes32`](simpletypes.md#bytes32) |
| `contractAddress` | The address of the contract that manages this state within the domain | [`EthAddress`](simpletypes.md#ethaddress) |
| `data` | The JSON formatted data for this state | [`RawJSON`](simpletypes.md#rawjson) |


## UnavailableStates

| Field Name | Description | Type |
|------------|-------------|------|
| `confirmed` | The IDs of confirmed states created by this transaction, for which the private data is unavailable | [`HexBytes[]`](simpletypes.md#hexbytes) |
| `read` | The IDs of read states used by this transaction, for which the private data is unavailable | [`HexBytes[]`](simpletypes.md#hexbytes) |
| `spent` | The IDs of spent states consumed by this transaction, for which the private data is unavailable | [`HexBytes[]`](simpletypes.md#hexbytes) |
| `info` | The IDs of info states referenced in this transaction, for which the private data is unavailable | [`HexBytes[]`](simpletypes.md#hexbytes) |


