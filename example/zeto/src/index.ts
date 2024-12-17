import PaladinClient, {
  Algorithms,
  ZetoFactory,
  TransactionType,
  Verifiers,
} from "@lfdecentralizedtrust-labs/paladin-sdk";
import erc20Abi from "./abis/SampleERC20.json";
import { checkDeploy, checkReceipt } from "./util";

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

async function main(): Promise<boolean> {
  const [cbdcIssuer] = paladin1.getVerifiers("centralbank@node3");
  const [bank1] = paladin2.getVerifiers("bank1@node1");
  const [bank2] = paladin3.getVerifiers("bank2@node2");

  // Deploy a Zeto token to represent cash (CBDC)
  logger.log("Use case #1: Privacy-preserving CBDC token, using private minting...");
  logger.log("- Deploying Zeto token...");
  const zetoFactory = new ZetoFactory(paladin3, "zeto");
  const zetoCBDC1 = await zetoFactory.newZeto(cbdcIssuer, {
    tokenName: "Zeto_AnonNullifier",
  });
  if (!checkDeploy(zetoCBDC1)) return false;

  // Issue some cash
  logger.log("- Issuing CBDC to bank1 and bank2 with private minting...");
  let receipt = await zetoCBDC1.mint(cbdcIssuer, {
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
  if (!checkReceipt(receipt)) return false;

  // Transfer some cash from bank1 to bank2
  logger.log(
    "Bank1 transferring CBDC to bank2 to pay for some asset trades ..."
  );
  receipt = await zetoCBDC1.using(paladin1).transfer(bank1, {
    transfers: [
      {
        to: bank2,
        amount: 1000,
      },
    ],
  });
  if (!checkReceipt(receipt)) return false;
  logger.log("  Success!\n");

  logger.log("Use case #2: Privacy-preserving CBDC token, using public minting of an ERC20 token...");
  logger.log("- Deploying Zeto token...");
  const zetoCBDC2 = await zetoFactory.newZeto(cbdcIssuer, {
    tokenName: "Zeto_AnonNullifier",
  });
  if (!checkDeploy(zetoCBDC2)) return false;
  logger.log(`  Zeto deployed at: ${zetoCBDC2.address}`);

  logger.log("- Deploying ERC20 token to manage the CBDC supply publicly...");
  const erc20Address = await deployERC20(paladin3, cbdcIssuer.lookup);
  logger.log(`  ERC20 deployed at: ${erc20Address}`);

  logger.log("- Setting ERC20 to the Zeto token contract ...");
  const result2 = await zetoCBDC2.setERC20(cbdcIssuer.lookup, {
    _erc20: erc20Address as string
  });
  if (!checkReceipt(result2)) return false;
  logger.log(`  ERC20 configured on the Zeto contract`);

  logger.log("- Issuing CBDC to bank1 with public minting in ERC20...");
  await mintERC20(paladin3, cbdcIssuer.lookup, bank1.lookup, erc20Address!, 100000);
  logger.log("  Success!");

  logger.log("- Bank1 deposit ERC20 balance to Zeto ...");
  const result4 = await zetoCBDC2.using(paladin1).deposit(bank1.lookup, {
    amount: 10000
  });
  if (!checkReceipt(result4)) return false;
  logger.log(`  Bank1 deposit successful`);

  // Transfer some cash from bank1 to bank2
  logger.log("- Bank1 transferring CBDC to bank2 to pay for some asset trades ...");
  receipt = await zetoCBDC2.using(paladin1).transfer(bank1, {
    transfers: [
      {
        to: bank2,
        amount: 1000,
      },
    ]
  });
  if (!checkReceipt(receipt)) return false;
  logger.log("  Success!");

  logger.log("- Bank1 withdraws Zeto back to ERC20 balance ...");
  const result5 = await zetoCBDC2.using(paladin1).withdraw(bank1.lookup, {
    amount: 1000
  });
  if (!checkReceipt(result5)) return false;
  logger.log(`  Bank1 withdraw successful`);

  logger.log("\nSuccess!");

  return true;
}

async function deployERC20(paladin: PaladinClient, cbdcIssuer: string): Promise<string | undefined> {
  const cbdcIssuerAddress = await paladin.resolveVerifier(
    cbdcIssuer,
    Algorithms.ECDSA_SECP256K1,
    Verifiers.ETH_ADDRESS
  );

  const txId1 = await paladin3.sendTransaction({
    type: TransactionType.PUBLIC,
    from: cbdcIssuer,
    data: {
      "initialOwner": cbdcIssuerAddress,
    },
    function: "",
    abi: erc20Abi.abi,
    bytecode: erc20Abi.bytecode,
  });
  const result1 = await paladin.pollForReceipt(txId1, 5000);
  if (!checkReceipt(result1)) return;
  const erc20Address = result1.contractAddress;
  return erc20Address;
}

async function mintERC20(paladin: PaladinClient, cbdcIssuer: string, bank1: string, erc20Address: string, amount: number): Promise<void> {
  const bank1Address = await paladin.resolveVerifier(
    bank1,
    Algorithms.ECDSA_SECP256K1,
    Verifiers.ETH_ADDRESS
  );
  const txId2 = await paladin.sendTransaction({
    type: TransactionType.PUBLIC,
    from: cbdcIssuer,
    to: erc20Address,
    data: {
      "amount": amount,
      "to": bank1Address,
    },
    function: "mint",
    abi: erc20Abi.abi,
  });
  const result3 = await paladin.pollForReceipt(txId2, 5000);
  if (!checkReceipt(result3)) return;
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
