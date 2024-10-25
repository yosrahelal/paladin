// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import "../private/interfaces/INotoGuard.sol";

/**
 * Example Noto Guard which tracks all Noto token movements on a private ERC20.
 */
contract NotoTrackerERC20 is INotoGuard, ERC20 {
    constructor(string memory name, string memory symbol) ERC20(name, symbol) {}

    function onMint(
        address to,
        uint256 amount,
        PreparedTransaction calldata prepared
    ) external {
        _mint(to, amount);
        emit PenteExternalCall(prepared.contractAddress, prepared.encodedCall);
    }

    function onTransfer(
        address from,
        address to,
        uint256 amount,
        PreparedTransaction calldata prepared
    ) external {
        _transfer(from, to, amount);
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
