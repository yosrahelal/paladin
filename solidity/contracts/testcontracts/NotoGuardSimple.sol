// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

import "../private/interfaces/INotoGuard.sol";

/**
 * Contract for testing Noto guards without using Pente.
 * TODO: this may become irrelevant as more "real" integration tests are developed.
 */
contract NotoGuardSimple is INotoGuard {
    function onMint(
        address to,
        uint256 amount,
        PreparedTransaction calldata prepared
    ) external {
        _executeOperation(prepared);
    }

    function onTransfer(
        address from,
        address to,
        uint256 amount,
        PreparedTransaction calldata prepared
    ) external {
        _executeOperation(prepared);
    }

    function onApproveTransfer(
        address from,
        address delegate,
        PreparedTransaction calldata prepared
    ) external {
        _executeOperation(prepared);
    }

    function _executeOperation(PreparedTransaction memory op) internal {
        (bool success, bytes memory result) = op.contractAddress.call(
            op.encodedCall
        );
        if (!success) {
            assembly {
                // Forward the revert reason
                let size := mload(result)
                let ptr := add(result, 32)
                revert(ptr, size)
            }
        }
    }
}
