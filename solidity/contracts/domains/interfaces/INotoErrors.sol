// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

/**
 * @title INotoErrors
 * @dev Definitions for common errors used in Noto implementations.
 */
interface INotoErrors {
    error NotoInvalidInput(bytes32 id);

    error NotoInvalidOutput(bytes32 id);

    error NotoNotNotary(address sender);

    error NotoInvalidDelegate(bytes32 txhash, address delegate, address sender);

    error NotoLockNotFound(bytes32 lockId);

    error NotoInvalidLockState(bytes32 lockId);

    error NotoInvalidLockDelegate(
        bytes32 lockId,
        address delegate,
        address sender
    );

    error NotoInvalidUnlockHash(
        bytes32 lockId,
        bytes32 expected,
        bytes32 actual
    );
}
