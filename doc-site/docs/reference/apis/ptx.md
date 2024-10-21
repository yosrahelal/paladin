---
title: ptx_*
---
## `ptx_getTransactionReceipt`

### Parameters

0. `transactionId`: [`UUID`](../types/simpletypes.md#uuid)

### Returns

0. `receipt`: [`TransactionReceipt`](../types/transactionreceipt.md#transactionreceipt)

## `ptx_getTransactionByIdempotencyKey`

### Parameters

0. `idempotencyKey`: `string`

### Returns

0. `transaction`: [`Transaction`](../types/transaction.md#transaction)

## `ptx_queryTransactionReceipts`

### Parameters

0. `query`: [`QueryJSON`](../types/queryjson.md#queryjson)

### Returns

0. `receipts`: [`TransactionReceipt[]`](../types/transactionreceipt.md#transactionreceipt)

## `ptx_call`

### Parameters

0. `transaction`: [`TransactionCall`](../types/transactioncall.md#transactioncall)

### Returns

0. `result`: [`RawJSON`](../types/simpletypes.md#rawjson)

## `ptx_queryTransactionsFull`

### Parameters

0. `query`: [`QueryJSON`](../types/queryjson.md#queryjson)

### Returns

0. `transactions`: [`TransactionFull[]`](../types/transactionfull.md#transactionfull)

## `ptx_resolveVerifier`

### Parameters

0. `keyIdentifier`: `string`
1. `algorithm`: `string`
2. `verifierType`: `string`

### Returns

0. `receipts`: `string`

## `ptx_queryTransactions`

### Parameters

0. `query`: [`QueryJSON`](../types/queryjson.md#queryjson)

### Returns

0. `transactions`: [`Transaction[]`](../types/transaction.md#transaction)

## `ptx_sendTransaction`

### Parameters

0. `transaction`: [`TransactionInput`](../types/transactioninput.md#transactioninput)

### Returns

0. `transactionId`: [`UUID`](../types/simpletypes.md#uuid)

## `ptx_sendTransactions`

### Parameters

0. `transactions`: [`TransactionInput[]`](../types/transactioninput.md#transactioninput)

### Returns

0. `transactionIds`: [`UUID[]`](../types/simpletypes.md#uuid)

## `ptx_getTransaction`

### Parameters

0. `transactionId`: [`UUID`](../types/simpletypes.md#uuid)

### Returns

0. `transaction`: [`Transaction`](../types/transaction.md#transaction)

## `ptx_getTransactionFull`

### Parameters

0. `transactionId`: [`UUID`](../types/simpletypes.md#uuid)

### Returns

0. `transaction`: [`TransactionFull`](../types/transactionfull.md#transactionfull)

