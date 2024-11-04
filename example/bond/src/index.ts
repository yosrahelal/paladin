import PaladinClient, {
  Algorithms,
  IGroupInfo,
  TransactionType,
  Verifiers,
} from "paladin-sdk";
import { notoABI, penteConstructorABI, penteDeployABI } from "./domains";
import { randomBytes } from "crypto";
import bondTrackerPublic from "./abis/BondTrackerPublic.json";
import bondTracker from "./abis/BondTracker.json";

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

  // Deploy a Noto token to represent cash
  logger.log("Deploying Noto cash token...");
  let txID = await paladin.sendTransaction({
    type: TransactionType.PRIVATE,
    domain: "noto",
    abi: notoABI(false),
    function: "",
    from: cashIssuer,
    data: {
      notary: cashIssuer,
      restrictMinting: true,
    },
  });
  let receipt = await paladin.pollForReceipt(txID, 10000);
  if (receipt === undefined) {
    logger.error(`Failed! tx: ${txID}`);
    return;
  }
  logger.log(`Success! tx: ${txID}, address: ${receipt.contractAddress}`);
  const notoCashAddress = receipt.contractAddress;

  // Issue some cash
  logger.log("Issuing cash...");
  txID = await paladin.sendTransaction({
    type: TransactionType.PRIVATE,
    domain: "noto",
    abi: notoABI(false),
    function: "mint",
    from: cashIssuer,
    to: notoCashAddress,
    data: {
      to: investor,
      amount: 100000,
      data: "0x",
    },
  });
  if (receipt === undefined) {
    logger.error(`Failed! tx: ${txID}`);
    return;
  }
  logger.log(`Success! tx: ${txID}`);

  // Deploy a Pente privacy group between the bond issuer and bond custodian
  logger.log("Creating issuer+custodian privacy group...");
  const issuerCustodianGroup: IGroupInfo = {
    salt: "0x" + Buffer.from(randomBytes(32)).toString("hex"),
    members: [bondIssuer, bondCustodian],
  };
  txID = await paladin.sendTransaction({
    type: TransactionType.PRIVATE,
    domain: "pente",
    abi: [penteConstructorABI],
    function: "",
    from: bondIssuer,
    data: [issuerCustodianGroup, "shanghai", "group_scoped_identities", true],
  });
  receipt = await paladin.pollForReceipt(txID, 10000);
  if (receipt === undefined) {
    logger.error(`Failed! tx: ${txID}`);
    return;
  }
  logger.log(`Success! tx: ${txID}, address: ${receipt.contractAddress}`);
  const issuerCustodianGroupAddress = receipt.contractAddress;

  // Deploy the public bond tracker on the base ledger (controlled by the privacy group)
  logger.log("Creating public bond tracker...");
  const issueDate = Math.floor(Date.now() / 1000);
  const maturityDate = issueDate + 60 * 60 * 24;
  txID = await paladin.sendTransaction({
    type: TransactionType.PUBLIC,
    abi: bondTrackerPublic.abi,
    bytecode: bondTrackerPublic.bytecode,
    function: "",
    from: bondIssuerUnqualified,
    data: {
      owner: issuerCustodianGroupAddress,
      issueDate_: issueDate,
      maturityDate_: maturityDate,
      currencyToken_: notoCashAddress,
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
  txID = await paladin.sendTransaction({
    type: TransactionType.PRIVATE,
    abi: [penteDeployABI(bondTrackerConstructor?.inputs)],
    function: "deploy",
    from: bondIssuer,
    to: issuerCustodianGroupAddress,
    data: {
      group: issuerCustodianGroup,
      bytecode: bondTracker.bytecode,
      inputs: {
        name: "BOND",
        symbol: "BOND",
        custodian: bondCustodianAddress,
        publicTracker: bondTrackerPublicAddress,
      },
    },
  });
  receipt = await paladin.pollForReceipt(txID, 10000, true);
  if (receipt === undefined || receipt.domainReceipt === undefined) {
    logger.error(`Failed! tx: ${txID}`);
    return;
  }
  logger.log(
    `Success! tx: ${txID}, address: ${receipt.domainReceipt.receipt.contractAddress}`
  );
  const bondTrackerAddress = receipt.domainReceipt.receipt.contractAddress;

  // Deploy Noto token to represent bond
  logger.log("Deploying Noto bond token...");
  txID = await paladin.sendTransaction({
    type: TransactionType.PRIVATE,
    domain: "noto",
    abi: notoABI(true),
    function: "",
    from: bondIssuer,
    data: {
      notary: bondCustodian,
      hooks: {
        privateGroup: issuerCustodianGroup,
        publicAddress: issuerCustodianGroupAddress,
        privateAddress: bondTrackerAddress,
      },
      restrictMinting: false,
    },
  });
  receipt = await paladin.pollForReceipt(txID, 10000);
  if (receipt === undefined) {
    logger.error(`Failed! tx: ${txID}`);
    return;
  }
  logger.log(`Success! tx: ${txID}, address: ${receipt.contractAddress}`);
}

if (require.main === module) {
  main().catch(() => {
    console.error("Exiting with uncaught error");
  });
}
