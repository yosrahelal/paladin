---
title: keymgr_*
---
## `keymgr_resolveEthAddress`

### Parameters

0. `keyIdentifier`: `string`

### Returns

0. `ethAddress`: [`EthAddress`](../types/simpletypes.md#ethaddress)

## `keymgr_resolveKey`

### Parameters

0. `keyIdentifier`: `string`
1. `algorithm`: `string`
2. `verifierType`: `string`

### Returns

0. `mapping`: `KeyMappingAndVerifier`

## `keymgr_reverseKeyLookup`

### Parameters

0. `algorithm`: `string`
1. `verifierType`: `string`
2. `verifier`: `string`

### Returns

0. `mapping`: `KeyMappingAndVerifier`

## `keymgr_wallets`

### Returns

0. `wallets`: `string[]`

