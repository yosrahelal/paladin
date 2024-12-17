import { copyFile } from "copy-file";

await copyFile(
  "../../solidity/artifacts/contracts/domains/pente/PentePrivacyGroup.sol/PentePrivacyGroup.json",
  "src/domains/abis/PentePrivacyGroup.json"
);

await copyFile(
  "../../solidity/artifacts/contracts/domains/interfaces/INotoPrivate.sol/INotoPrivate.json",
  "src/domains/abis/INotoPrivate.json"
);

await copyFile(
  "../../solidity/artifacts/contracts/domains/interfaces/IZeto.sol/IZeto.json",
  "src/domains/abis/IZeto.json"
);
