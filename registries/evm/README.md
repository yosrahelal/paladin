# Identity Registry

### Introduction

The core logic of the identity registry has been written in a Solidity smart contract. The source code can be found [here][smartContract] and the corresponding Hardhat tests can be found [here](smartContractTests).

An identity contains:
 - Name `string`
 - Owner `address`
 - Parent identity `hash`
 - Child identities `hash array`

When the smart contract is deployed the `root` identity is automatically created with the following values:
 - Name: "root"
 - Owner: address in the smart contract deployment
 - Parent identity: 0
 - Child identities: empty array

Identities can be uniquely identified by a hash. The hash is calculated as the SHA256  of the identity name and the parent identity hash. By convention, the hash of the root identity is 0. When registering an identity, the parent hash is provided. This makes it possible to hierarchically arrange identities. Each identity has an associated set of `properties`. These consists of key-value string pairs that can be set and updated.

The following diagram illustrates a sample set of identities:


<img src="./readme-resources/diagram-1.png" width="600">


The following rules enforced by the smart contract:
 - Only the owner of an identity can add child identities
 - Only the owner of an identity can set/update its properties
 - Identity names cannot be empty
 - Names are unique among sibling identities

> **_NOTE:_**  when registering an identity, the owner may be set to an address different from the parent identity.

### Setup
Running the [gradle build](gradleBuild) will:
 - Compile the [smart contract][smartContract]
 - Copy the smart contract ABI and bytecode to [registry/identity/abi/IdentityRegistry.json][contractAbi]
 - Setup test infrastructure

### Identity Registry Plug-in (Go code)
A set of APIs (REST, JSON-RPC and soon to be developed gRPC) are provided in order to interact with the identity registry. Through these APIs it is possible to:
 - Deploy the identity registry smart contract
 - Set/change the identity registry smart contract address
 - Register identities
 - Set identity properties
 - Resolve identities

#### Resolving identities
An identity is resolved using paths where each segment (separated by a forward slash) consists of the name of an identity. Since the root identity name is constant ("root"), for convenience it is ommited from the path. Following the sample diagram above, in order to resolve identity `identity-a-b` the following path is used:
```
identity-a/identity-a-b
```
Resolving an identity provides access to its associated properties, owner address and list of child identities.

#### Implementation
The following components are used to interact with the identity registry smart contract:
 - Eth client
 - Block indexer
 - Key manager
 - Persistence
 
A [YAML configuration file][yamlConfig] is loaded on startup with values for the components listed above as well as:
 - `api/port`: port used by the identity registry plug-in
 - `contract/address`: smart contract address if already deployed

#### Caching
The contents of the registry is kept in a set of in-memory data structures, specifically maps. One map is used for identity entries and the other is used for identity properties. These maps are populated from the smart contract contents on startup and are automatically kept in sync through event listeners. This makes resolving identities very efficient.

#### RESTful API
`POST /api/v1/contract` Deploys the identity registry smart contract. Sample request body:
```json
{
    "signer": "mykey"
}
```
<br><br>
`GET /api/v1/contract` Gets the identity smart contract address. Sample response body:
```json
{
    "address": "0x01234567890123456789"
}
```
<br><br>
`PUT /api/v1/contract` Sets the identity smart contract address. Sample request body:
```json
{
    "address": "0x01234567890123456789"
}
```
<br><br>
`POST /api/v1/identities/*` Register identity. Sample URL:
```
/api/v1/identities/identity-a
```
Sample request body:
```json
{
    "signer": "mykey"
    "name": "identity-a-c"
    "owner": "0x01234567890123456789"
}
```
> **_NOTE:_**  the signer key must be the owner of the parent identity. Also note that the parent identity is the one identified in the URL while the child identity name is the one specified in the body.

<br><br>
`PUT /api/v1/identities/*` Set identity property. Sample request body:
```json
{
    "signer": "mykey",
    "name": "my-property-key",
    "value": "my-property-value"
}
```
> **_NOTE:_**  the signer key must be the owner of the identity.

<br><br>
`GET /api/v1/identities/*` Lookup identity. Sample URL:
```
/api/v1/identities/identity-a
```
Sample response body:
```json
{
    "name": "identity-a",
    "owner": "0x01234567890123456789",
    "parent": "root",
    "children": [
        "identity-a-a"
    ],
    "properties": {
        "my-property-key": "my-property-value"
    }
}
```
<br><br>
`POST /api/v1/sync` Synchronize the in-memory identity registry cache with the smart contract.
<br><br>
`GET /api/v1/sync` Show status of the in-memory identity registry cache. Sample response body:
```json
{
    "lastSync": 1723748695,
    "lastIncrementalUpdate": 1723749879
}
```
> **_NOTE:_**  `lastSync` shows the epoch timestamp when the last full sync took place while the `lastIncrementalUpdate` shows the epoch timestamp when the last event based incremental update took place.

#### JSON RPC API

The JSON RPC API provides the exact same functionality as the RESTful API described above. The method names are as follows:

`contract.Deploy` Deploys the identity registry smart contract

`contract.GetStatus`Gets the identity smart contract address

`contract.SetAddress` Sets the identity smart contract address

`identities.Register` Register identity

`identities.SetProperty` Set identity property

`identities.Lookup` Lookup identity

`sync.Sync` Synchronize the in-memory identity registry cache with the smart contract

`sync.GetStatus` Show status of the in-memory identity registry cach


[smartContract]: ../solidity/contracts/registry/IdentityRegistry.sol
[smartContractTests]: ../solidity//test//registry/IdentityRegistry.ts
[gradleBuild]: ./build.gradle
[contractAbi]: ./identity/abis/IdentityRegistry.json
[yamlConfig]: ./data/config.yaml