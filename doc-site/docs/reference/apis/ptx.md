---
title: API ptx
---
## ptx_getTransaction

{% include-markdown "./_includes/gettransaction_description.md" %}

### Parameters

- [UUID](../types/simpletypes.md#uuid)

### Returns

- [Transaction](../types/transaction.md#transaction)

## ptx_getTransactionFull

{% include-markdown "./_includes/gettransactionfull_description.md" %}

### Parameters

- [UUID](../types/simpletypes.md#uuid)

### Returns

- TransactionFull

## ptx_getTransactionReceipt

{% include-markdown "./_includes/gettransactionreceipt_description.md" %}

### Parameters

- [UUID](../types/simpletypes.md#uuid)

### Returns

- TransactionReceipt

## ptx_queryTransactionReceipts

{% include-markdown "./_includes/querytransactionreceipts_description.md" %}

### Parameters

- [QueryJSON](../types/queryjson.md#queryjson)

### Returns

- TransactionReceipt[]

## ptx_queryTransactions

{% include-markdown "./_includes/querytransactions_description.md" %}

### Parameters

- [QueryJSON](../types/queryjson.md#queryjson)

### Returns

- [Transaction[]](../types/transaction.md#transaction)

## ptx_queryTransactionsFull

{% include-markdown "./_includes/querytransactionsfull_description.md" %}

### Parameters

- [QueryJSON](../types/queryjson.md#queryjson)

### Returns

- TransactionFull[]

