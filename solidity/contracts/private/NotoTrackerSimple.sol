// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

import "./interfaces/INotoGuard.sol";

/**
 * Example Noto Guard which enforces a max supply.
 */
contract NotoTrackerSimple is INotoGuard {
    uint256 private maxSupply_;
    uint256 private supply_;

    constructor(uint256 maxSupply) {
        maxSupply_ = maxSupply;
        supply_ = 1; // https://github.com/kaleido-io/paladin/issues/251
    }

    function onMint(
        address to,
        uint256 amount,
        PreparedTransaction calldata prepared
    ) external {
        supply_ += amount;
        require(supply_ - 1 <= maxSupply_, "Max supply reached");
        emit PenteExternalCall(prepared.contractAddress, prepared.encodedCall);
    }

    function onTransfer(
        address from,
        address to,
        uint256 amount,
        PreparedTransaction calldata prepared
    ) external {
        emit PenteExternalCall(prepared.contractAddress, prepared.encodedCall);
    }

    function onApproveTransfer(
        address from,
        address delegate,
        PreparedTransaction calldata prepared
    ) external {
        emit PenteExternalCall(prepared.contractAddress, prepared.encodedCall);
    }
}
