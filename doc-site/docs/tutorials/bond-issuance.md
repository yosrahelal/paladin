# Bond Issuance

The code for this tutorial can be found in [example/bond](https://github.com/LF-Decentralized-Trust-labs/paladin/blob/main/example/bond).

This shows how to leverage the [Noto](../architecture/noto) and [Pente](../architecture/pente) domains together in order to build a bond issuance process, illustrating multiple aspects of Paladin's privacy capabilities.

## Running the example

Follow the [Getting Started](../getting-started) instructions to set up a Paldin environment, and
then follow the example [README](https://github.com/LF-Decentralized-Trust-labs/paladin/blob/main/example/bond/README.md)
to run the code.

## Explanation

Below is a walkthrough of each step in the example, with an explanation of what it does.

### Create cash token

```typescript
const notoFactory = new NotoFactory(paladin1, "noto");
const notoCash = await notoFactory.newNoto(cashIssuer, {
  notary: cashIssuer,
  restrictMinting: true,
});
```

This creates a new instance of the Noto domain, which will translate to a new cloned contract
on the base ledger, with a new unique address. This Noto token will be used to represent
tokenized cash.

The token will be notarized by the cash issuer party, meaning that all transactions will be
sent to this party for endorsement. The Noto domain code at the notary will automatically
verify that each transaction is valid - no custom policies will be applied.

Minting is restricted to be requested only by the notary.

### Issue cash

```typescript
await notoCash.mint(cashIssuer, {
  to: investor,
  amount: 100000,
  data: "0x",
});
```

The cash issuer mints cash to the investor party. As the notary of the cash token, they are
allowed to do this.

### Create issuer+custodian private group

```typescript
const issuerCustodianGroupInfo: IGroupInfo = {
  salt: "0x" + Buffer.from(randomBytes(32)).toString("hex"),
  members: [bondIssuer, bondCustodian],
};
const penteFactory = new PenteFactory(paladin1, "pente");
const issuerCustodianGroup = await penteFactory.newPrivacyGroup(bondIssuer, {
  group: issuerCustodianGroupInfo,
  evmVersion: "shanghai",
  endorsementType: "group_scoped_identities",
  externalCallsEnabled: true,
});
```

This creates a new instance of the Pente domain, which will be a private EVM group shared by the
bond issuer and bond custodian. Each transaction proposed in this private EVM will need to be
endorsed by both participants, and then the new state of the private EVM can be hashed and
recorded on the base ledger contract.

As will be shown in future steps, any EVM logic can be deployed into this private EVM group.

### Create public bond tracker

```typescript
await paladin1.sendTransaction({
  type: TransactionType.PUBLIC,
  abi: bondTrackerPublicJson.abi,
  bytecode: bondTrackerPublicJson.bytecode,
  function: "",
  from: bondIssuerUnqualified,
  data: {
    owner: issuerCustodianGroup.address,
    issueDate_: issueDate,
    maturityDate_: maturityDate,
    currencyToken_: notoCash.address,
    faceValue_: 1,
  },
});
```

This sends a public EVM transaction to deploy the [public bond tracker](https://github.com/LF-Decentralized-Trust-labs/paladin/blob/main/solidity/contracts/shared/BondTrackerPublic.sol).
This is equivalent to performing a deploy directly on the base ledger, without any special
handling for privacy.

The public bond tracker is used to advertise public information about our bond, such as its
face value, issue date, and maturity date. It will also be updated with publically-visible
events throughout the bond's lifetime.

### Create private bond tracker

```typescript
await newBondTracker(issuerCustodianGroup, bondIssuer, {
  name: "BOND",
  symbol: "BOND",
  custodian: bondCustodianAddress,
  publicTracker: bondTrackerPublicAddress,
});
```

The [private bond tracker](https://github.com/LF-Decentralized-Trust-labs/paladin/blob/main/solidity/contracts/private/BondTracker.sol)
is an ERC-20 token, and implements the [INotoHooks](https://github.com/LF-Decentralized-Trust-labs/paladin/blob/main/solidity/contracts/private/interfaces/INotoHooks.sol) interface.

Noto supports using a Pente private smart contract to define "hooks" which are executed inline with every mint/transfer.
This provides a flexible (and EVM-native) means of writing custom policies that are enforced by the notary. In this case,
the notary tracks the bond value as an ERC-20. Every mint and transfer of the Noto token will be reflected on this private
ERC-20, and anything that causes the ERC-20 to revert will cause the Noto operation to revert. This private tracker is only
visible to the bond issuer and custodian, but will be atomically linked to the Noto token in the next step.

### Create bond token

```typescript
const notoBond = await notoFactory.newNoto(bondIssuer, {
  notary: bondCustodian,
  hooks: {
    privateGroup: issuerCustodianGroupInfo,
    publicAddress: issuerCustodianGroup.address,
    privateAddress: bondTracker.address,
  },
  restrictMinting: false,
});
```

Now that the public and private tracking contracts have been deployed, the actual Noto token for the bond can be created.
The "hooks" configuration points it to the private hooks implementation that was deployed in the previous step.

For this token, "restrictMinting" is disabled, because the hooks can enforce more flexible rules on both mint and transfer.

... to be continued