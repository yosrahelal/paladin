// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

interface IPente {
    event UTXOTransfer(bytes32 txId, bytes32[] inputs, bytes32[] reads, bytes32[] outputs, bytes32[] info, bytes data);

    event UTXOApproved(address delegate, bytes32 txhash);
}
