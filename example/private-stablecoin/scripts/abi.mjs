import { copyFile } from "copy-file";

// Copy the KYC interface ABI from zeto domain
await copyFile(
  "../../sdk/typescript/src/domains/abis/IZetoKyc.json",
  "src/abis/IZetoKyc.json"
);

// Copy the SampleERC20 ABI from SDK
await copyFile(
  "../../sdk/typescript/src/domains/abis/SampleERC20.json",
  "src/abis/SampleERC20.json"
);

console.log("✓ Copied KYC and ERC20 ABIs to src/abis/");
