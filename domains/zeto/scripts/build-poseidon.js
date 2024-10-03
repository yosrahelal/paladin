const { poseidonContract } = require('circomlibjs');
const fs = require('fs');

function PoseidonArtifact(param) {
  const abi = poseidonContract.generateABI(param);
  const bytecode = poseidonContract.createCode(param);
  const artifact = {
    _format: 'hh-sol-artifact-1',
    contractName: `Poseidon${param}`,
    sourceName: '',
    abi: abi,
    bytecode: bytecode,
    deployedBytecode: '', // "0x"-prefixed hex string
    linkReferences: {},
    deployedLinkReferences: {},
  };
  return artifact;
}

fs.writeFileSync('Poseidon2.json', JSON.stringify(PoseidonArtifact(2), null, 2));
fs.writeFileSync('Poseidon3.json', JSON.stringify(PoseidonArtifact(3), null, 2));
