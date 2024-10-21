---
title: TransactionFull
---
{% include-markdown "./_includes/transactionfull_description.md" %}

### Example

```json
{
    "receipt": null,
    "public": null
}
```

### Field Descriptions

| Field Name | Description | Type |
|------------|-------------|------|
| `id` | Server-generated UUID for this transaction (query only) | [`UUID`](simpletypes.md#uuid) |
| `created` | Server-generated creation timestamp for this transaction (query only) | [`Timestamp`](simpletypes.md#timestamp) |
| `idempotencyKey` | Externally supplied unique identifier for this transaction. 409 Conflict will be returned on attempt to re-submit | `string` |
| `type` | Type of transaction (public or private) | `Enum[github.com/kaleido-io/paladin/toolkit/pkg/pldapi.TransactionType]` |
| `domain` | Name of a domain - only required on input for private deploy transactions | `string` |
| `function` | Function signature - inferred from definition if not supplied | `string` |
| `abiReference` | Calculated ABI reference - required with ABI on input if not constructor | [`Bytes32`](simpletypes.md#bytes32) |
| `from` | Locator for a local signing identity to use for submission of this transaction | `string` |
| `to` | Target contract address, or null for a deploy | [`EthAddress`](simpletypes.md#ethaddress) |
| `data` | Pre-encoded array with/without function selector, array, or object input | `uint8[]` |
| `gas` | The gas limit for the transaction (optional) | [`HexUint64`](simpletypes.md#hexuint64) |
| `value` | The value transferred in the transaction (optional) | [`HexUint256`](simpletypes.md#hexuint256) |
| `maxPriorityFeePerGas` | The maximum priority fee per gas (optional) | [`HexUint256`](simpletypes.md#hexuint256) |
| `maxFeePerGas` | The maximum fee per gas (optional) | [`HexUint256`](simpletypes.md#hexuint256) |
| `gasPrice` | The gas price (optional) | [`HexUint256`](simpletypes.md#hexuint256) |
| `dependsOn` | Transactions registered as dependencies when the transaction was created | [`UUID[]`](simpletypes.md#uuid) |
| `receipt` | Transaction receipt data - available if the transaction has reached a final state | [`TransactionReceiptData`](#transactionreceiptdata) |
| `public` | List of public transactions associated with this transaction | [`PublicTx[]`](#publictx) |

## TransactionReceiptData

| Field Name | Description | Type |
|------------|-------------|------|
| `success` | Transaction success status | `bool` |
| `transactionHash` | Transaction hash | [`Bytes32`](simpletypes.md#bytes32) |
| `blockNumber` | Block number | `int64` |
| `transactionIndex` | Transaction index | `int64` |
| `logIndex` | Log index | `int64` |
| `source` | Event source | [`EthAddress`](simpletypes.md#ethaddress) |
| `failureMessage` | Failure message - set if transaction reverted | `string` |
| `revertData` | Encoded revert data - if available | `uint8[]` |
| `contractAddress` | New contract address - to be used in the 'To' field for subsequent invoke transactions | [`EthAddress`](simpletypes.md#ethaddress) |


