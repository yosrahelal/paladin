# Enterprise Stablecoin with KYC

The code for this tutorial can be found in [example/enterprise-stablecoin](https://github.com/LF-Decentralized-Trust-labs/paladin/blob/main/example/enterprise-stablecoin).

This example demonstrates a **privacy-preserving enterprise stablecoin** with **KYC (Know Your Customer) compliance** using Paladin's [Zeto domain](../../architecture/zeto/). It showcases how financial institutions can issue and manage stablecoins while maintaining regulatory compliance, transaction privacy, and enterprise-grade security.

## Running the example

Follow the [Getting Started](../../getting-started/installation/) instructions to set up a Paladin environment, and
then follow the example [README](https://github.com/LF-Decentralized-Trust-labs/paladin/blob/main/example/enterprise-stablecoin/README.md)
to run the code.

## Key Features

This tutorial demonstrates:

- **KYC Registration** – Regulatory authorities register enterprise clients for compliance
- **Privacy-Preserving Issuance** – Financial institutions mint stablecoins with privacy guarantees
- **Compliant Transfers** – Zero-knowledge proof-based transfers with KYC verification
- **Nullifier Protection** – Prevents double-spending while maintaining privacy
- **Enterprise Operations** – Business-to-business stablecoin transactions

## Scenario Overview

The example simulates a regulated enterprise stablecoin ecosystem with the following participants:

- **Regulatory Authority** (`regulator@node1`) – Manages KYC compliance and oversight
- **Financial Institution** (`bank@node2`) – Issues and manages stablecoin operations
- **Enterprise Client A** (`enterprise-a@node3`) – Receives and transfers stablecoins
- **Enterprise Client B** (`enterprise-b@node3`) – Participates in enterprise transactions

## Step-by-Step Walkthrough

### 1. Deploy Enterprise Stablecoin Contract

The example begins by deploying a Zeto contract with KYC and nullifier capabilities:

```typescript
const zetoFactory = new ZetoFactory(paladin1, "zeto");
const enterpriseStablecoin = await zetoFactory.newZeto(regulatoryAuthority, {
  tokenName: "Zeto_AnonNullifierKyc",
});
```

The `Zeto_AnonNullifierKyc` contract provides:
- **Anonymous transfers** with zero-knowledge proofs
- **Nullifier protection** against double-spending
- **KYC compliance** verification for all participants

### 2. KYC Registration Process

Before any stablecoin operations, the regulatory authority registers all participants for KYC compliance:

```typescript
// Register Enterprise Client A
const clientAPublicKey = await getBabyjubPublicKey(enterpriseClientA);
let kycTxId = await paladin1.sendTransaction({
  type: TransactionType.PUBLIC,
  from: regulatoryAuthority.lookup,
  to: enterpriseStablecoin.address,
  data: {
    publicKey: clientAPublicKey,
    data: "0x", // KYC compliance data/proof could go here
  },
  function: "register",
  abi: kycAbi.abi,
});
```

**Key Technical Details:**
- Uses **BabyJubJub elliptic curve** keys for zero-knowledge proof compatibility
- Properly decompresses compressed public keys using **circomlibjs**
- Stores KYC registration on-chain for verification during transfers

### 3. Stablecoin Issuance

The financial institution mints enterprise stablecoins under regulatory oversight:

```typescript
let receipt = await enterpriseStablecoin.mint(regulatoryAuthority, {
  mints: [
    {
      to: financialInstitution,
      amount: 1000000, // 1,000,000 stablecoin units
      data: "0x", // Additional compliance data could go here
    },
  ],
});
```

**Privacy Features:**
- Mint amounts are **cryptographically private**
- Only the issuer and recipient know the exact amount
- Regulatory authority maintains oversight without full visibility

### 4. Enterprise Transfers

The financial institution transfers stablecoins to enterprise clients:

```typescript
receipt = await enterpriseStablecoin
  .using(paladin2)
  .transfer(financialInstitution, {
    transfers: [
      {
        to: enterpriseClientA,
        amount: 500000, // 500,000 stablecoin units
        data: "0x", // Transaction metadata for compliance
      },
    ],
  });
```

**Compliance Verification:**
- Each transfer automatically **verifies KYC status** through zero-knowledge proofs
- **Nullifiers prevent double-spending** without revealing transaction details
- Transfer amounts remain **private** between sender and recipient

### 5. Business-to-Business Transactions

Enterprise clients can transfer stablecoins directly to each other:

```typescript
receipt = await enterpriseStablecoin
  .using(paladin3)
  .transfer(enterpriseClientA, {
    transfers: [
      {
        to: enterpriseClientB,
        amount: 100000, // 100,000 stablecoin units
        data: "0x", // Transaction metadata for compliance
      },
    ],
  });
```

**Enterprise Benefits:**
- **Direct peer-to-peer transfers** without intermediaries
- **Automated compliance verification** through KYC registry
- **Privacy-preserving** business transactions

## Privacy and Compliance Features

### Zero-Knowledge Proofs
- All transfers use **zk-SNARKs** to prove transaction validity
- **No transaction amounts** are revealed publicly
- **No participant identities** are exposed on-chain

### KYC Integration
- **Cryptographic verification** of participant eligibility
- **Regulatory oversight** without compromising privacy
- **Automated compliance** checking during transfers

### Nullifier Protection
- **Prevents double-spending** through cryptographic nullifiers
- **Maintains privacy** while ensuring transaction integrity
- **Enterprise-grade security** for financial operations

## Technical Implementation

### Key Management
The example demonstrates proper **BabyJubJub key handling**:

```typescript
async function getBabyjubPublicKey(verifier: PaladinVerifier): Promise<string[]> {
  const pubKeyStr = await verifier.resolve(
    algorithmZetoSnarkBJJ("zeto") as any,
    IDEN3_PUBKEY_BABYJUBJUB_COMPRESSED_0X as any
  );
  
  // Decompress the key using circomlibjs
  const babyJub = await buildBabyjub();
  const publicKey = babyJub.unpackPoint(compressedBytes);
  
  return [babyJub.F.toString(publicKey[0]), babyJub.F.toString(publicKey[1])];
}
```

### Transaction Types
- **Public transactions** for KYC registration and regulatory oversight
- **Private transactions** for stablecoin transfers and business operations
- **Mixed privacy models** balancing compliance with privacy

## Use Cases

This enterprise stablecoin pattern is suitable for:

- **Wholesale CBDC** implementations
- **Corporate treasury management** systems
- **Supply chain finance** solutions
- **Inter-bank settlement** networks
- **Enterprise payment rails** with compliance requirements

## Conclusion

The Enterprise Stablecoin example demonstrates how Paladin enables:

- **Regulatory compliance** through automated KYC verification
- **Transaction privacy** using zero-knowledge proofs
- **Enterprise scalability** with direct peer-to-peer transfers
- **Financial security** through nullifier-based double-spend protection

This showcases Paladin's capability to balance **regulatory requirements** with **privacy preservation** in enterprise financial applications.

## Next Steps

Explore how **Notarized Tokens** and **Privacy Groups** work together to create comprehensive financial solutions with controlled oversight and selective disclosure.

[Continue to the Bond Issuance Tutorial →](./bond-issuance.md) 