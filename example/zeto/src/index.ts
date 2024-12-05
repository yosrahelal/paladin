import PaladinClient, {
  Algorithms,
  newTransactionId,
  ZetoFactory,
  TransactionType,
  Verifiers,
} from "paladin-sdk";
import erc20Abi from "./abis/SampleERC20.json";

const logger = console;

const paladin1 = new PaladinClient({
  url: "http://127.0.0.1:31548",
});
const paladin2 = new PaladinClient({
  url: "http://127.0.0.1:31648",
});
const paladin3 = new PaladinClient({
  url: "http://127.0.0.1:31748",
});

async function main() {
  const cbdcIssuer = "centralbank@node3";
  const bank1 = `bank1@node1`;
  const bank2 = `bank2@node2`;

  // Deploy a Zeto token to represent cash (CBDC)
  logger.log("Deploying Zeto CBDC token...");
  const zetoFactory = new ZetoFactory(paladin3, "zeto");
  const zetoCBDC = await zetoFactory.newZeto(cbdcIssuer, {
    tokenName: "Zeto_AnonNullifier",
  });
  if (zetoCBDC === undefined) {
    logger.error("Failed!");
    return;
  }
  logger.log(`Success! Zeto deployed at: ${zetoCBDC.address}`);

  logger.log("Deploying ERC20 token...");
  const cbdcIssuerAddress = await paladin1.resolveVerifier(
    cbdcIssuer,
    Algorithms.ECDSA_SECP256K1,
    Verifiers.ETH_ADDRESS
  );

  const txId = await paladin3.sendTransaction({
    type: TransactionType.PUBLIC,
    from: cbdcIssuer,
    data: {
      "initialOwner": cbdcIssuerAddress,
    },
    function: "",
    abi: erc20Abi.abi,
    bytecode: erc20Abi.bytecode,
  });
  if (txId === undefined) {
    logger.error("Failed!");
    return;
  }
  const result1 = await paladin3.pollForReceipt(txId, 5000);
  if (result1 === undefined) {
    logger.error("Failed!");
    return;
  }
  const erc20Address = result1.contractAddress;
  logger.log(`Success! ERC20 deployed at: ${erc20Address}`);

  logger.log("Setting ERC20 to the Zeto token contract ...");
  const result2 = await zetoCBDC.setERC20(cbdcIssuer, {
    _erc20: erc20Address as string
  });
  if (result1 === undefined) {
    logger.error("Failed!");
    return;
  }
  logger.log(`Success! ERC20 configured on the Zeto contract`);

  // Issue some cash
  logger.log("Issuing CBDC to bank1 and bank2 ...");
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
    ]
  });
  if (receipt === undefined) {
    logger.error("Failed!");
    return;
  }
  logger.log("Success!");

  // Transfer some cash from bank1 to bank2
  logger.log("Bank1 transferring CBDC to bank2 to pay for some asset trades ...");
  receipt = await zetoCBDC.using(paladin1).transfer(bank1, {
    transfers: [
      {
        to: bank2,
        amount: 1000,
      },
    ]
  });
  if (receipt === undefined) {
    logger.error("Failed!");
    return;
  }
  logger.log("Success!");
}

if (require.main === module) {
  main().catch((err) => {
    console.error("Exiting with uncaught error");
    console.error(err);
    process.exit(1);
  });
}
