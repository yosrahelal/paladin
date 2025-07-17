import { copyFile } from 'copy-file';

await copyFile('../../sdk/typescript/src/domains/abis/SampleERC20.json', 'src/zeto-abis/SampleERC20.json');
