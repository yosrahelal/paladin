# Example: ZKP Fungible Tokens with Zeto

This example demonstrates a privacy-preserving fungible tokens using [Zeto](https://github.com/hyperledger-labs/zeto) on Paladin.

See the [tutorial](https://lf-decentralized-trust-labs.github.io/paladin/head/tutorials/zeto/) for a detailed explanation.

## Pre-requisites

Requires a local 3-node Paladin cluster running on `localhost:31548`, `localhost:31648`, and `localhost:31748`.

## Run standalone

Build [TypeScript SDK](../../sdk/typescript):

```shell
cd ../../sdk/typescript
npm install
npm run abi
npm run build
```

Run example:

```shell
npm install
npm run start
```

## Run with Gradle

The following will perform all pre-requisites and then run the example:

```shell
../../gradlew build
npm run start
```
