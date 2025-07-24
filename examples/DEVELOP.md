# Paladin Examples Development Guide

This guide outlines the process for developing Paladin examples and the requirements that all examples must meet.

## Overview

All Paladin examples must follow a consistent pattern that includes:
1. **Data Persistence**: Saving contract data to files for later verification
2. **Verification Scripts**: Ensuring deployed contracts remain accessible and functional
3. **Standard Commands**: Providing consistent npm scripts across all examples
4. **Documentation**: Clear README with setup and verification instructions

## Required Structure

Every example must have the following structure:

```
examples/your-example/
├── src/
│   ├── index.ts              # Main example implementation
│   ├── verify-deployed.ts    # Verification script (REQUIRED)
│   └── abis/                 # Contract ABIs
├── package.json              # Required scripts
├── README.md                 # Clear instruction for running the example
└── tsconfig.json
```

## Required npm Scripts

Every example's `package.json` must include these scripts:

```json
{
  "scripts": {
    "build": "tsc",
    "start": "ts-node ./src/index.ts",
    "start:prod": "node ./build/index.js",
    "verify": "ts-node ./src/verify-deployed.ts",
    "verify:prod": "node ./build/verify-deployed.js",
    "abi": "node scripts/abi.mjs",
    "copy-abi": "node scripts/contracts.mjs"
  }
}
```

### Script Descriptions

- **`start`**: Run the example with ts-node
- **`start:prod`**: Run the example with built JavaScript
- **`verify`**: Run verification with ts-node
- **`abi`**: Copy ABIs from the solidity directory (this is for the scenario the solidity was built locally) 
- **`copy-abi`**: Copy ABIs from examples/common to example directory

## Data Persistence

### File System Imports

Every `index.ts` must include:

```typescript
import * as fs from 'fs';
import * as path from 'path';
```

### Contract Data Interface

Every example should define a `ContractData` interface in `verify-deployed.ts`:

```typescript
export interface ContractData {
  // Define all data that needs to be saved
  contractAddress: string;
  // ... other fields
  timestamp: string;
}
```

### Data Saving

At the end of the main function, save comprehensive contract data:

```typescript
const contractData: ContractData = {
  // All relevant contract addresses, balances, transaction hashes, etc.
  contractAddress: deployedContract.address,
  // ... other data
  timestamp: new Date().toISOString()
};

const dataDir = path.join(__dirname, '..', 'data');
if (!fs.existsSync(dataDir)) {
  fs.mkdirSync(dataDir, { recursive: true });
}

const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
const dataFile = path.join(dataDir, `contract-data-${timestamp}.json`);
fs.writeFileSync(dataFile, JSON.stringify(contractData, null, 2));
logger.log(`Contract data saved to ${dataFile}`);
```

## Verification Script Requirements

### Required Structure

Every `verify-deployed.ts` must include:

```typescript
import PaladinClient from "@lfdecentralizedtrust-labs/paladin-sdk";
import * as fs from 'fs';
import * as path from 'path';

export interface ContractData {
  // Same interface as used in index.ts
}

function findLatestContractDataFile(dataDir: string): string | null {
  if (!fs.existsSync(dataDir)) {
    return null;
  }

  const files = fs.readdirSync(dataDir)
    .filter(file => file.startsWith('contract-data-') && file.endsWith('.json'))
    .sort()
    .reverse(); // Most recent first

  return files.length > 0 ? path.join(dataDir, files[0]) : null;
}

async function main(): Promise<boolean> {
  // STEP 1: Load saved contract data
  // STEP 2: Recreate contract connections
  // STEP 3+: Verify functionality
  // Return true on success, false on failure
}

if (require.main === module) {
  main()
    .then((success: boolean) => {
      process.exit(success ? 0 : 1);
    })
    .catch((err) => {
      console.error("Exiting with uncaught error");
      console.error(err);
      process.exit(1);
    });
}
```

### Verification Steps

Every verification script should include these steps:

1. **STEP 1**: Load saved contract data from the most recent file
2. **STEP 2**: Recreate all contract connections using appropriate SDK classes
3. **STEP 3+**: Verify specific functionality (balances, contract calls, etc.)
4. **Final Step**: Test new operations to ensure contracts are still functional
