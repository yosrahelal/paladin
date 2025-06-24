import PaladinClient, {
  PaladinVerifier,
  TransactionType,
  ZetoFactory,
  algorithmZetoSnarkBJJ,
  IDEN3_PUBKEY_BABYJUBJUB_COMPRESSED_0X,
} from "@lfdecentralizedtrust-labs/paladin-sdk";
import { checkDeploy, checkReceipt } from "paladin-example-common";
import kycAbi from "../../../domains/zeto/tools/artifacts/contracts/lib/interfaces/izeto_kyc.sol/IZetoKyc.json";
import { buildBabyjub } from "circomlibjs";

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

async function getBabyjubPublicKey(verifier: PaladinVerifier): Promise<string[]> {
  const pubKeyStr = await verifier.resolve(
    algorithmZetoSnarkBJJ("zeto") as any,
    IDEN3_PUBKEY_BABYJUBJUB_COMPRESSED_0X as any
  );
  
  if (!pubKeyStr || pubKeyStr === "0x0" || pubKeyStr === "0x") {
    throw new Error(`No babyjub key available for ${verifier.lookup}`);
  }

  const cleanHex = pubKeyStr.startsWith('0x') ? pubKeyStr.slice(2) : pubKeyStr;
  const compressedBytes = Buffer.from(cleanHex, 'hex');
  
  if (compressedBytes.length !== 32) {
    throw new Error(`Invalid key length for ${verifier.lookup}: expected 32 bytes, got ${compressedBytes.length}`);
  }

  const babyJub = await buildBabyjub();
  const publicKey = babyJub.unpackPoint(compressedBytes);
  
  if (!publicKey || publicKey.length < 2) {
    throw new Error(`Failed to unpack babyjub key for ${verifier.lookup}: invalid point`);
  }

  return [babyJub.F.toString(publicKey[0]), babyJub.F.toString(publicKey[1])];
}

async function main(): Promise<boolean> {
  // Get verifiers for the regulatory authority, financial institution, and enterprise clients
  const [regulatoryAuthority] = paladin1.getVerifiers("regulator@node1");
  const [financialInstitution] = paladin2.getVerifiers("bank@node2");
  const [enterpriseClientA] = paladin3.getVerifiers("enterprise-a@node3");
  const [enterpriseClientB] = paladin3.getVerifiers("enterprise-b@node3");

  logger.log("=== Enterprise Stablecoin with KYC and Nullifiers ===");
  logger.log(
    "This example demonstrates a privacy-preserving enterprise stablecoin"
  );
  logger.log("using Zeto with nullifiers and KYC compliance features.\n");

  // Deploy the enterprise stablecoin using Zeto_AnonNullifierKyc
  logger.log("1. Deploying Enterprise Stablecoin with KYC capabilities...");
  const zetoFactory = new ZetoFactory(paladin1, "zeto");
  const enterpriseStablecoin = await zetoFactory.newZeto(regulatoryAuthority, {
    tokenName: "Zeto_AnonNullifierKyc",
  });
  if (!checkDeploy(enterpriseStablecoin)) return false;
  logger.log(
    `   ✓ Enterprise stablecoin deployed at: ${enterpriseStablecoin.address}\n`
  );

  // === KYC REGISTRATION PROCESS ===
  // The regulatory authority registers enterprise clients for KYC compliance
  logger.log("2. Regulatory authority registering clients for KYC compliance...");
  
  // Register Enterprise Client A for KYC using sendTransaction
  logger.log("   - Resolving Enterprise Client A babyjub public key...");
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
  let kycReceipt = await paladin1.pollForReceipt(kycTxId, 5000);
  if (!checkReceipt(kycReceipt)) return false;
  logger.log("   ✓ Enterprise Client A registered for KYC compliance");

  // Register Enterprise Client B for KYC using sendTransaction
  logger.log("   - Resolving Enterprise Client B babyjub public key...");
  const clientBPublicKey = await getBabyjubPublicKey(enterpriseClientB);
  kycTxId = await paladin1.sendTransaction({
    type: TransactionType.PUBLIC,
    from: regulatoryAuthority.lookup,
    to: enterpriseStablecoin.address,
    data: {
      publicKey: clientBPublicKey,
      data: "0x", // KYC compliance data/proof could go here
    },
    function: "register",
    abi: kycAbi.abi,
  });
  kycReceipt = await paladin1.pollForReceipt(kycTxId, 5000);
  if (!checkReceipt(kycReceipt)) return false;
  logger.log("   ✓ Enterprise Client B registered for KYC compliance");

  // Register Financial Institution for KYC using sendTransaction
  logger.log("   - Resolving Financial Institution babyjub public key...");
  const bankPublicKey = await getBabyjubPublicKey(financialInstitution);
  kycTxId = await paladin1.sendTransaction({
    type: TransactionType.PUBLIC,
    from: regulatoryAuthority.lookup,
    to: enterpriseStablecoin.address,
    data: {
      publicKey: bankPublicKey,
      data: "0x", // KYC compliance data/proof could go here
    },
    function: "register",
    abi: kycAbi.abi,
  });
  kycReceipt = await paladin1.pollForReceipt(kycTxId, 5000);
  if (!checkReceipt(kycReceipt)) return false;
  logger.log("   ✓ Financial Institution registered for KYC compliance\n");
  
  // === FINANCIAL INSTITUTION MINTS STABLECOIN ===
  logger.log("3. Financial institution minting enterprise stablecoin...");
  let receipt = await enterpriseStablecoin.mint(regulatoryAuthority, {
    mints: [
      {
        to: financialInstitution,
        amount: 1000000, // 1,000,000 stablecoin units
        data: "0x", // Additional compliance data could go here
      },
    ],
  });
  if (!checkReceipt(receipt)) return false;
  
  // Check financial institution balance
  let bankBalance = await enterpriseStablecoin
    .using(paladin2)
    .balanceOf(financialInstitution, {
      account: financialInstitution.lookup,
    });
  logger.log(
    `   ✓ Financial institution balance: ${bankBalance.totalBalance} units (${bankBalance.totalStates} states)`
  );
  logger.log(`   ✓ Overflow protection: ${bankBalance.overflow}\n`);
  
  // Brief pause for blockchain settlement
  await new Promise((resolve) => setTimeout(resolve, 2000));

  // === TRANSFER TO ENTERPRISE CLIENT A ===
  logger.log("4. Financial institution transferring to Enterprise Client A...");
  receipt = await enterpriseStablecoin
    .using(paladin2)
    .transfer(financialInstitution, {
      transfers: [
        {
          to: enterpriseClientA,
          amount: 500000, // 500,000 stablecoin units for enterprise operations
          data: "0x", // Transaction metadata for compliance
        },
      ],
    });
  if (!checkReceipt(receipt)) return false;
  logger.log("   ✓ Transfer successful - KYC compliance verified through nullifiers");

  // === ENTERPRISE-TO-ENTERPRISE TRANSFER ===
  logger.log("5. Enterprise Client A transferring to Enterprise Client B...");
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
  if (!checkReceipt(receipt)) return false;
  logger.log("   ✓ Enterprise-to-enterprise transfer successful");
  logger.log("   ✓ Both parties verified through KYC registry");

  // === FINAL BALANCES ===
  logger.log("\n6. Checking final balances...");
  
  bankBalance = await enterpriseStablecoin
    .using(paladin2)
    .balanceOf(financialInstitution, {
      account: financialInstitution.lookup,
    });
  let clientABalance = await enterpriseStablecoin
    .using(paladin3)
    .balanceOf(enterpriseClientA, {
      account: enterpriseClientA.lookup,
    });
  let clientBBalance = await enterpriseStablecoin
    .using(paladin3)
    .balanceOf(enterpriseClientB, {
      account: enterpriseClientB.lookup,
    });
  
  logger.log(
    `   ✓ Financial institution balance: ${bankBalance.totalBalance} units (${bankBalance.totalStates} states)`
  );
  logger.log(
    `   ✓ Enterprise Client A balance: ${clientABalance.totalBalance} units (${clientABalance.totalStates} states)`
  );
  logger.log(
    `   ✓ Enterprise Client B balance: ${clientBBalance.totalBalance} units (${clientBBalance.totalStates} states)`
  );

  logger.log("\n=== Enterprise Stablecoin Example Complete ===");
  logger.log("✓ Successfully demonstrated:");
  logger.log("  - KYC registration using proper register() method with circomlib babyjub decompression");
  logger.log("  - Privacy-preserving stablecoin issuance");
  logger.log("  - KYC-compliant transfers with nullifiers");
  logger.log("  - Zero-knowledge proof-based compliance verification");
  logger.log("  - Enterprise-grade financial operations");
  logger.log("  - Regulatory oversight with privacy preservation");

  return true;
}

// Export for potential testing
export { main };

// Run if called directly
if (require.main === module) {
  main()
    .then((success) => {
      if (success) {
        logger.log("\n🎉 Enterprise stablecoin example completed successfully!");
        process.exit(0);
      } else {
        logger.error("\n❌ Enterprise stablecoin example failed!");
        process.exit(1);
      }
    })
    .catch((error: unknown) => {
      logger.error("\n💥 Enterprise stablecoin example crashed:", error);
      process.exit(1);
    });
}
