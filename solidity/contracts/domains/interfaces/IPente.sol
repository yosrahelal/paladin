// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

interface IPente {
    event PenteTransition(bytes32 txId, bytes32[] inputs, bytes32[] reads, bytes32[] outputs, bytes32[] info);
    event PenteApproved(bytes32 txId, address delegate, bytes32 transitionHash);
}
