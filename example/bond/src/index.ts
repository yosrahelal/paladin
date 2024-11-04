import { randomBytes } from "crypto";
import PaladinClient, {
  Algorithms,
  IGroupInfo,
  TransactionType,
  Verifiers,
} from "paladin-sdk";
import bondTrackerPublicJson from "./abis/BondTrackerPublic.json";
import { newBondTracker } from "./helpers/bondtracker";
import { newNoto } from "./helpers/noto";
import { newPentePrivacyGroup } from "./helpers/pente";
import { newBondSubscription } from "./helpers/bondsubscription";

async function main() {
  const logger = console;
  const paladin1 = new PaladinClient({
    url: "http://127.0.0.1:31548",
  });
  const paladin2 = new PaladinClient({
    url: "http://127.0.0.1:31648",
  });

  const cashIssuer = "static_bank1@node1";
  const bondIssuerUnqualified = "static_bank1";
  const bondIssuer = `${bondIssuerUnqualified}@node1`;
  const bondCustodian = "static_bank2@node2";
  const investor = "static_bank1@node1";

  const bondCustodianAddress = await paladin1.resolveVerifier(
    bondCustodian,
    Algorithms.ECDSA_SECP256K1,
    Verifiers.ETH_ADDRESS
  );

  // Create a Noto token to represent cash
  logger.log("Deploying Noto cash token...");
  const notoCash = await newNoto(paladin1, "noto", cashIssuer, {
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
    paladin1,
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
  let txID = await paladin1.sendTransaction({
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
  receipt = await paladin1.pollForReceipt(txID, 10000);
  if (receipt?.contractAddress === undefined) {
    logger.error(`Failed! tx: ${txID}`);
    return;
  }
  logger.log(`Success! tx: ${txID}, address: ${receipt.contractAddress}`);
  const bondTrackerPublicAddress = receipt.contractAddress;

  // Deploy private bond tracker to the issuer/custodian privacy group
  logger.log("Creating private bond tracker...");
  const bondTracker = await newBondTracker(issuerCustodianGroup, bondIssuer, {
    name: "BOND",
    symbol: "BOND",
    custodian: bondCustodianAddress,
    publicTracker: bondTrackerPublicAddress,
  });
  if (bondTracker === undefined) {
    logger.error("Failed!");
    return;
  }
  logger.log(`Success! address: ${bondTracker.address}`);

  // Deploy Noto token to represent bond
  logger.log("Deploying Noto bond token...");
  const notoBond = await newNoto(paladin1, "noto", bondIssuer, {
    notary: bondCustodian,
    hooks: {
      privateGroup: issuerCustodianGroupInfo,
      publicAddress: issuerCustodianGroup.address,
      privateAddress: bondTracker.address,
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

  // Begin bond distribution to investors
  logger.log("Beginning distribution...");
  receipt = await bondTracker.using(paladin2).beginDistribution(bondCustodian, {
    discountPrice: 1,
    minimumDenomination: 1,
  });
  if (receipt === undefined) {
    logger.error("Failed!");
    return;
  }
  logger.log("Success!");

  // Create a Pente privacy group between the bond investor and bond custodian
  logger.log("Creating investor+custodian privacy group...");
  const investorCustodianGroupInfo: IGroupInfo = {
    salt: "0x" + Buffer.from(randomBytes(32)).toString("hex"),
    members: [investor, bondCustodian],
  };
  const investorCustodianGroup = await newPentePrivacyGroup(
    paladin1,
    "pente",
    investor,
    [investorCustodianGroupInfo, "shanghai", "group_scoped_identities", true]
  );
  if (investorCustodianGroup === undefined) {
    logger.error("Failed!");
    return;
  }
  logger.log(`Success! address: ${investorCustodianGroup.address}`);

  // Deploy bond subscription to the investor/custodian privacy group
  logger.log("Creating private bond subscription...");
  const bondSubscription = await newBondSubscription(
    investorCustodianGroup,
    bondIssuer,
    {
      bondAddress_: notoBond.address,
      units_: 100,
    }
  );
  if (bondSubscription === undefined) {
    logger.error("Failed!");
    return;
  }
  logger.log(`Success! address: ${bondSubscription.address}`);
}

if (require.main === module) {
  main().catch(() => {
    console.error("Exiting with uncaught error");
  });
}
