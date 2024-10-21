---
title: reg_*
---
## `reg_getEntryProperties`

### Parameters

0. `registryName`: `string`
1. `entryId`: [`HexBytes`](../types/simpletypes.md#hexbytes)
2. `activeFilter`: `"active", "inactive", "any"`

### Returns

0. `properties`: [`RegistryProperty[]`](../types/registryproperty.md#registryproperty)

## `reg_queryEntries`

### Parameters

0. `registryName`: `string`
1. `query`: [`QueryJSON`](../types/queryjson.md#queryjson)
2. `activeFilter`: `"active", "inactive", "any"`

### Returns

0. `entries`: [`RegistryEntry[]`](../types/registryentry.md#registryentry)

## `reg_queryEntriesWithProps`

### Parameters

0. `registryName`: `string`
1. `query`: [`QueryJSON`](../types/queryjson.md#queryjson)
2. `activeFilter`: `"active", "inactive", "any"`

### Returns

0. `entries`: [`RegistryEntryWithProperties[]`](../types/registryentrywithproperties.md#registryentrywithproperties)

## `reg_registries`

### Returns

0. `registryNames`: `string[]`

