# Example: Storage with Privacy Groups

See the [tutorial](https://lf-decentralized-trust-labs.github.io/paladin/head/tutorials/private-storage/) for a detailed explanation.

## Pre-requisites

Requires a local Paladin instance running on `localhost:31548`.
Requires a local Paladin instance running on `localhost:31648`.
Requires a local Paladin instance running on `localhost:31748`.

## Option 1: Use the Latest Stable Version

1. **Download and extract contracts**

   - [Download Solidity contracts](https://github.com/LF-Decentralized-Trust-labs/paladin/releases/latest/download/abis.tar.gz)
   - Extract `abis.tar.gz` and copy the `abis` directory to `src/`. (full path should be: `paladin/example/private-storage/src/abis`)

2. **Build TypeScript SDK**

```shell
cp -rf src/abis ../../sdk/typescript/src/domains/
cd ../../sdk/typescript
npm install
npm run abi
npm run build
```

3. **Build common utilities**

```shell
cd ../common
npm install
npm run build
```

4. **Run the example**

```shell
npm install
npm run abi
npm run start
```

---

## Option 2: Build Locally

1. **Compile Solidity contracts**

```shell
cd ../../solidity
npm install
npm run compile
```

2. **Build TypeScript SDK**

```shell
cd ../../sdk/typescript
npm install
npm run abi
npm run build
```

3. **Build common utilities**

```shell
cd ../common
npm install
npm run build
```

4. **Run the example**

```shell
npm install
npm run abi
npm run start
```

5. **(Optional) Run the update example**

You can update the contract deployed in the previous step using the `update.js` sample. Take the output from the `npm run start` step above and pass the privacy group address, group ID, and storage contract address to the `update` script. E.g. if the output from the first script looks like this:

```shell
Creating a privacy group for Node1 and Node2...
Success! address: 0xb9473d084800cdf8c4526a117fa153ad2261d94e
Privacy group created, ID: 0x09be3a466f0c935f42e9aa0451574b639497f2c4d38dee41fdabf9fc2269af08
Deploying a smart contract to the privacy group...
Contract deployed successfully! Address: 0xe5ccd796c1d3e2cf9230fd51f4333208dabfdf80
```

then pass the following parameters in to the update script:

```shell
npm run update 0xb9473d084800cdf8c4526a117fa153ad2261d94e 0x09be3a466f0c935f42e9aa0451574b639497f2c4d38dee41fdabf9fc2269af08 0xe5ccd796c1d3e2cf9230fd51f4333208dabfdf80
```

The script reads the current value and sets it to a new one.

---

## Option 3: Run with Gradle

To perform all prerequisites and run the example in one go:

```shell
../../gradlew build
npm run start
```

**(Optional) Run the update example**

You can update the contract deployed in the previous step using the `update.js` sample. Take the output from the `npm run start` step above and pass the privacy group address, group ID, and storage contract address to the `update` script. E.g. if the output from the first script looks like this:

```shell
Creating a privacy group for Node1 and Node2...
Success! address: 0xb9473d084800cdf8c4526a117fa153ad2261d94e
Privacy group created, ID: 0x09be3a466f0c935f42e9aa0451574b639497f2c4d38dee41fdabf9fc2269af08
Deploying a smart contract to the privacy group...
Contract deployed successfully! Address: 0xe5ccd796c1d3e2cf9230fd51f4333208dabfdf80
```

then pass the following parameters in to the update script:

```shell
npm run update 0xb9473d084800cdf8c4526a117fa153ad2261d94e 0x09be3a466f0c935f42e9aa0451574b639497f2c4d38dee41fdabf9fc2269af08 0xe5ccd796c1d3e2cf9230fd51f4333208dabfdf80
```

The script reads the current value and sets it to a new one.
