# CBDC Tokens based on Zeto

The code for this tutorial can be found in [example/zeto](https://github.com/LF-Decentralized-Trust-labs/paladin/blob/main/example/zeto).

This shows how to leverage the [Zeto](../../architecture/zeto/) in order to build a wholesale CBDC with privacy, illustrating multiple aspects of Paladin's privacy capabilities.

## Running the example

Follow the [Getting Started](../../getting-started/installation/) instructions to set up a Paldin environment, and
then follow the example [README](https://github.com/LF-Decentralized-Trust-labs/paladin/blob/main/example/zeto/README.md)
to run the code.

## Explanation

Below is a walkthrough of each step in the example, with an explanation of what it does.

### Create CBDC token

```typescript
const zetoFactory = new ZetoFactory(paladin3, 'zeto');
const zetoCBDC = await zetoFactory.newZeto(cbdcIssuer, {
  tokenName: 'Zeto_AnonNullifier',
});
```

This creates a new instance of the Zeto domain, using the [Zeto_AnonNullifier](https://github.com/hyperledger-labs/zeto/tree/main?tab=readme-ov-file#zeto_anonnullifier) contract.
This results in a new cloned contract on the base ledger, with a new unique address. This Zeto token contract will be used to represent
tokenized cash/CBDC.

The token will be minted by the central bank/CBDC issuer party. Minting is restricted to be requested only by the central bank, the
deployer account of the contract.

### Issue cash

```typescript
let receipt = await zetoCBDC.mint(cbdcIssuer, {
  mints: [
    {
      to: bank1,
      amount: 100000,
    },
    {
      to: bank2,
      amount: 100000,
    },
  ],
});
```

The cash issuer mints cash to the commercial banks, `bank1` and `bank2`.

### Bank1 transfers tokens to bank2 as payment

```typescript
receipt = await zetoCBDC.using(paladin1).transfer(bank1, {
  transfers: [
    {
      to: bank2,
      amount: 1000,
    },
  ],
});
```

Bank1 can call the `transfer` function to transfer zeto tokens to multiple parties, up to 10. Note that the identity `bank1` exists on the `paladin1` instance,
therefore it must use that instance to send the transfer transction (`.using(paladin1)`).
