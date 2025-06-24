import { copyFile } from "copy-file";

await copyFile(
  "../../domains/zeto/zkp/artifacts/contracts/lib/interfaces/izeto_kyc.sol/IZetoKyc.json",
  "src/abis/IZetoKyc.json"
);
