---
title: reg_*
---
## `reg_getEntryProperties`

### Parameters

0. `registryName`: `string`
1. `entryId`: [`HexBytes`](../types/simpletypes.md#hexbytes)
2. `activeFilter`: `Enum[github.com/kaleido-io/paladin/toolkit/pkg/pldapi.ActiveFilter]`

### Returns

0. `properties`: `RegistryProperty[]`

## `reg_registries`

### Returns

0. `registryNames`: `string[]`

## `reg_queryEntries`

### Parameters

0. `registryName`: `string`
1. `query`: [`QueryJSON`](../types/queryjson.md#queryjson)
2. `activeFilter`: `Enum[github.com/kaleido-io/paladin/toolkit/pkg/pldapi.ActiveFilter]`

### Returns

0. `entries`: `RegistryEntry[]`

## `reg_queryEntriesWithProps`

### Parameters

0. `registryName`: `string`
1. `query`: [`QueryJSON`](../types/queryjson.md#queryjson)
2. `activeFilter`: `Enum[github.com/kaleido-io/paladin/toolkit/pkg/pldapi.ActiveFilter]`

### Returns

0. `entries`: `RegistryEntryWithProperties[]`

