// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

interface INoto {
    event NotoTransfer(
        bytes32[] inputs,
        bytes32[] outputs,
        bytes signature,
        bytes data
    );

    event NotoApproved(
        address delegate,
        bytes32 txhash,
        bytes signature,
        bytes data
    );

    function initialize(
        address notary,
        bytes memory config
    ) external returns (bytes memory);

    function mint(
        bytes32[] calldata outputs,
        bytes calldata signature,
        bytes calldata data
    ) external;

    function transfer(
        bytes32[] memory inputs,
        bytes32[] memory outputs,
        bytes memory signature,
        bytes memory data
    ) external;

    function approve(
        address delegate,
        bytes32 txhash,
        bytes memory signature,
        bytes memory data
    ) external;

    function approvedTransfer(
        bytes32[] memory inputs,
        bytes32[] memory outputs,
        bytes memory signature,
        bytes memory data
    ) external;
}
