// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

/**
 * @title INotoPrivate
 * @dev This is the ABI of the Noto private transaction interface, which is implemented in Go.
 *      This interface is never expected to be implemented in a smart contract.
 */
interface INotoPrivate {
    function mint(
        string calldata to,
        uint256 amount,
        bytes calldata data
    ) external;

    function transfer(
        string calldata to,
        uint256 amount,
        bytes calldata data
    ) external;

    function approveTransfer(
        FullState[] calldata inputs,
        FullState[] calldata outputs,
        bytes calldata data,
        address delegate
    ) external;

    struct FullState {
        bytes id;
        bytes32 schema;
        bytes data;
    }
}
