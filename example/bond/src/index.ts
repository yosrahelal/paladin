import PaladinClient, {
  Algorithms,
  IGroupInfo,
  TransactionType,
  Verifiers,
} from "paladin-sdk";
import { randomBytes } from "crypto";
import bondTrackerPublic from "./abis/BondTrackerPublic.json";
import bondTracker from "./abis/BondTracker.json";
import { newNoto } from "./helpers/noto";
import { newPentePrivacyGroup, penteDeployABI } from "./helpers/pente";

async function main() {
  const logger = console;
  const paladin = new PaladinClient({
    url: "http://127.0.0.1:31548",
  });

  const cashIssuer = "static_bank1@node1";
  const bondIssuerUnqualified = "static_bank1";
  const bondIssuer = `${bondIssuerUnqualified}@node1`;
  const bondCustodian = "static_bank2@node2";
  const investor = "static_bank1@node1";

  const bondCustodianAddress = await paladin.resolveVerifier(
    bondCustodian,
    Algorithms.ECDSA_SECP256K1,
    Verifiers.ETH_ADDRESS
  );

  // Create a Noto token to represent cash
  logger.log("Deploying Noto cash token...");
  const notoCash = await newNoto(paladin, "noto", cashIssuer, {
    notary: cashIssuer,
    restrictMinting: true,
  });
  if (notoCash === undefined) {
    logger.error("Failed!");
    return;
  }
  logger.log(`Success! address: ${notoCash.address}`);

  // Issue some cash
  logger.log("Issuing cash...");
  let receipt = await notoCash.mint(cashIssuer, {
    to: investor,
    amount: 100000,
    data: "0x",
  });
  if (receipt === undefined) {
    logger.error("Failed!");
    return;
  }
  logger.log("Success!");

  // Create a Pente privacy group between the bond issuer and bond custodian
  logger.log("Creating issuer+custodian privacy group...");
  const issuerCustodianGroupInfo: IGroupInfo = {
    salt: "0x" + Buffer.from(randomBytes(32)).toString("hex"),
    members: [bondIssuer, bondCustodian],
  };
  const issuerCustodianGroup = await newPentePrivacyGroup(
    paladin,
    "pente",
    bondIssuer,
    [issuerCustodianGroupInfo, "shanghai", "group_scoped_identities", true]
  );
  if (issuerCustodianGroup === undefined) {
    logger.error("Failed!");
    return;
  }
  logger.log(`Success! address: ${issuerCustodianGroup.address}`);

  // Deploy the public bond tracker on the base ledger (controlled by the privacy group)
  logger.log("Creating public bond tracker...");
  const issueDate = Math.floor(Date.now() / 1000);
  const maturityDate = issueDate + 60 * 60 * 24;
  let txID = await paladin.sendTransaction({
    type: TransactionType.PUBLIC,
    abi: bondTrackerPublic.abi,
    bytecode: bondTrackerPublic.bytecode,
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
  receipt = await paladin.pollForReceipt(txID, 10000);
  if (receipt === undefined) {
    logger.error(`Failed! tx: ${txID}`);
    return;
  }
  logger.log(`Success! tx: ${txID}, address: ${receipt.contractAddress}`);
  const bondTrackerPublicAddress = receipt.contractAddress;

  // Deploy private bond tracker to the issuer/custodian privacy group
  logger.log("Creating private bond tracker...");
  const bondTrackerConstructor = bondTracker.abi.find(
    (entry) => entry.type === "constructor"
  );
  receipt = await issuerCustodianGroup.deploy(
    bondIssuer,
    bondTrackerConstructor,
    bondTracker.bytecode,
    {
      name: "BOND",
      symbol: "BOND",
      custodian: bondCustodianAddress,
      publicTracker: bondTrackerPublicAddress,
    }
  );
  if (receipt === undefined || receipt.domainReceipt === undefined) {
    logger.error("Failed!");
    return;
  }
  logger.log(
    `Success! address: ${receipt.domainReceipt.receipt.contractAddress}`
  );
  const bondTrackerAddress = receipt.domainReceipt.receipt.contractAddress;

  // Deploy Noto token to represent bond
  logger.log("Deploying Noto bond token...");
  const notoBond = await newNoto(paladin, "noto", bondIssuer, {
    notary: bondCustodian,
    hooks: {
      privateGroup: issuerCustodianGroupInfo,
      publicAddress: issuerCustodianGroup.address,
      privateAddress: bondTrackerAddress,
    },
    restrictMinting: false,
  });
  if (notoBond === undefined) {
    logger.error("Failed!");
    return;
  }
  logger.log(`Success! address: ${notoBond.address}`);

  // Issue the bond to the custodian
  logger.log("Issuing bond...");
  receipt = await notoBond.mint(bondIssuer, {
    to: bondCustodian,
    amount: 1000,
    data: "0x",
  });
  if (receipt === undefined) {
    logger.error("Failed!");
    return;
  }
  logger.log("Success!");
}

if (require.main === module) {
  main().catch(() => {
    console.error("Exiting with uncaught error");
  });
}
