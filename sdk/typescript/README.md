# Paladin TypeScript SDK

This is the official TypeScript SDK for building client applications that talk to Paladin nodes.

At this time the SDK is incomplete, and may only contain a subset of the available Paladin methods.

## Build standalone

Compile [Solidity contracts](../../solidity):

```shell
cd ../../solidity
npm install
npm run compile
```

Build the SDK:

```shell
npm install
npm run abi
npm run build
```

## Build with Gradle

The following will perform all pre-requisites and build the SDK:

```shell
../../gradlew build
```
