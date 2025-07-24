# Example: Private Stablecoin with KYC and Nullifiers

This example demonstrates a privacy-preserving stablecoin using Zeto with KYC compliance and nullifiers for enhanced security and regulatory oversight.

See the [tutorial](https://lf-decentralized-trust-labs.github.io/paladin/head/examples/private-stablecoin/) for a detailed explanation.

## Pre-requisites

Run the common [setup steps](../README.md) before running the example.

## Running the example

### ABI resources for Zeto

The sample uses the following ABIs to accomplish the end-to-end flow:

- `IZetoFungible.json`: Private transaction ABI for the Zeto domain, to conduct private transactions like `mint`, `transfer`, etc.
- `Zeto_AnonNullifierKyc.json`: Public transaction ABI for the Zeto KYC token implementation
- `SampleERC20.json`: Public transaction ABI for ERC20 tokens (if needed for deposit/withdraw operations)

These dependency resources can be obtained by one of the following ways.

### Option 1 - `npm` with downloaded solidity contracts

- **Extract contracts**

  - Extract the `abis.tar.gz` file that was downloaded in the [setup steps](../README.md) and copy the `abis` directory to `src/`. (full path should be: `paladin/examples/private-stablecoin/src/abis`)

- **Run the example**

> **Note**: This example requires the latest Paladin SDK functionality.
>
> **Build local SDK**
> ```shell
> cd <paladin-root>/sdk/typescript
> npm install
> npm run abi
> npm run build
> 

  ```shell
  cd <paladin-root>/examples/private-stablecoin
  npm install
  npm run start
  ```

---

### Option 2 - `npm` with locally built solidity contracts and ABIs

- **Run the example**

  ```shell
  cd <paladin-root>/examples/private-stablecoin
  npm install
  npm run abi
  npm run start
  ```

---

### Option 3 - Run with Gradle

- **Run the gradle build task, then run the sample:**

  ```shell
  cd <paladin-root>/examples/private-stablecoin
  ../../gradlew build
  npm run start
  ```

### Verify Dependent Zeto Resources

You can verify that the dependent ABIs have been successfully put in place by the build:

```shell
$ ls <paladin-root>/sdk/typescript/build/domains/abis/
INoto.json		INotoPrivate.json	IZetoFungible.json	PentePrivacyGroup.json	Zeto_AnonNullifierKyc.json
$ ls <paladin-root>/examples/private-stablecoin/src/abis/
SampleERC20.json
```

---

## Verification

After running the example, you can verify that the private stablecoin contract data is still accessible on the blockchain:

### Option 1 - Using npm scripts

```shell
cd <paladin-root>/examples/private-stablecoin
npm run verify
```

### Option 2 - Using built JavaScript

```shell
cd <paladin-root>/examples/private-stablecoin
npm run build
npm run verify:prod
```

The verification script will:
1. Load the saved contract data from the `data/` directory
2. Recreate the Zeto private stablecoin connection using `ZetoInstance`
3. Verify that current private stablecoin balances match the saved data for both clients
4. Verify that current public ERC20 balances match the saved data for both clients
5. Test private stablecoin functionality by performing balance queries
6. Test public ERC20 functionality by performing balance queries
7. Confirm that all KYC details are preserved (participant lookups and public keys)
8. Verify that all operation details are preserved (deposit, transfer, withdraw amounts and receipt IDs)
9. Test private transfer accessibility (without executing to avoid changing balances)

Contract data is automatically saved to `data/contract-data-<timestamp>.json` when you run the main example, including:
- Run ID for unique identity management
- Private stablecoin address (Zeto token)
- Public stablecoin address (ERC20 token)
- Token name and configuration
- KYC details for all participants (financial institution, client A, client B) including public keys
- Operation details (deposit, transfer, withdraw amounts, receipt IDs, transaction hashes)
- Final balances for both public and private tokens for all clients
- Participant verifier information
 
  