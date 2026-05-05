// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

import {SmtLib} from "@iden3/contracts/contracts/lib/SmtLib.sol";
import {Noto} from "./Noto.sol";

uint256 constant MAX_SMT_DEPTH = 64;

contract NotoNullifiers is Noto {
    using SmtLib for SmtLib.Data;

    SmtLib.Data internal _commitmentsTree;

    uint64 public constant NotoVariantNullifiers = 0x0002;

    mapping(bytes32 => bool) private _nullifiers;

    function initialize(
        string memory name_,
        string memory symbol_,
        address notary_
    ) public virtual override initializer {
        super.initialize(name_, symbol_, notary_);
        _commitmentsTree.initialize(MAX_SMT_DEPTH);
    }

    function buildConfig(
        bytes calldata data
    ) external view override returns (bytes memory) {
        return
            _encodeConfig(
                NotoConfig_V1({
                    name: _name,
                    symbol: _symbol,
                    decimals: decimals(),
                    notary: notary,
                    variant: NotoVariantNullifiers,
                    data: data
                })
            );
    }

    function transfer(
        bytes32 txId,
        bytes32[] calldata inputs,
        bytes32[] calldata outputs,
        bytes calldata proof,
        bytes calldata data
    ) external virtual override onlyNotary txIdNotUsed(txId) {
        (uint256 root, bytes memory _signature) = abi.decode(
            proof,
            (uint256, bytes)
        );
        if (!_commitmentsTree.rootExists(root)) {
            revert NotoInvalidRoot(root);
        }
        _processNullifiers(inputs);
        _processOutputs(outputs);
        emit Transfer(txId, msg.sender, inputs, outputs, _signature, data);
    }

    function _createLock(
        NotoCreateLockOperation memory lockOp,
        LockParams calldata params,
        bytes32 lockId,
        LockInfo storage lock,
        bytes calldata data
    ) internal virtual override {
        useTxId(lockOp.txId);

        (uint256 root, ) = abi.decode(lockOp.proof, (uint256, bytes));
        if (!_commitmentsTree.rootExists(root)) {
            revert NotoInvalidRoot(root);
        }

        _processNullifiers(lockOp.inputs);
        _processOutputs(lockOp.outputs);
        _processLockContents(lockId, lockOp.contents);

        _processOutput(lockOp.newLockState);
        _lockStates[lockId] = lockOp.newLockState;

        lock.spendHash = params.spendHash;
        lock.cancelHash = params.cancelHash;

        if (params.options.length != 0) {
            _setLockOptions(lockId, lock, params.options);
        }

        emit LockUpdated(lockId, msg.sender, lock, data);
    }

    function _updateLock(
        NotoUpdateLockOperation memory lockOp,
        LockParams calldata params,
        bytes32 lockId,
        LockInfo storage lock,
        bytes calldata data
    ) internal virtual override {
        if (lockOp.proof.length > 0) {
            (uint256 root, ) = abi.decode(lockOp.proof, (uint256, bytes));
            if (!_commitmentsTree.rootExists(root)) {
                revert NotoInvalidRoot(root);
            }
        }
        super._updateLock(lockOp, params, lockId, lock, data);
    }

    /**
     * @dev Lock state IDs and other outputs live in the commitment tree, not _unspent.
     *      Base Noto spends lock states via _processInput; accept tree membership there.
     */
    function _processInput(bytes32 input) internal virtual override {
        uint256 inputUint = uint256(input);
        if (existsAsUnlocked(inputUint)) {
            return;
        }
        super._processInput(input);
    }

    /**
     * @dev Append-only commitment tree instead of _unspent for public outputs.
     */
    function _processOutput(bytes32 output) internal virtual override {
        uint256 outputUint = uint256(output);
        if (
            existsAsUnlocked(outputUint) || getLockId(output) != bytes32(0)
        ) {
            revert NotoInvalidOutput(output);
        }
        _commitmentsTree.addLeaf(outputUint, outputUint);
    }

    /**
     * @dev Check the inputs are nullifiers that have not been used, and mark them as used
     */
    function _processNullifiers(
        bytes32[] memory inputNullifiers
    ) internal virtual {
        for (uint256 i = 0; i < inputNullifiers.length; ++i) {
            if (_nullifiers[inputNullifiers[i]]) {
                revert NotoInvalidInput(inputNullifiers[i]);
            }
            // record the nullifier as used
            _nullifiers[inputNullifiers[i]] = true;
        }
    }

    // check the existence of a UTXO in the commitments tree. we take a shortcut
    // by checking the list of nodes by their node hash, because the commitments
    // tree is append-only, no updates or deletions are allowed. As a result, all
    // nodes in the list are valid leaf nodes, aka there are no orphaned nodes.
    function existsAsUnlocked(uint256 utxo) internal view returns (bool) {
        uint256 nodeHash = getLeafNodeHash(utxo, utxo);
        SmtLib.Node memory node = _commitmentsTree.getNode(nodeHash);
        return node.nodeType != SmtLib.NodeType.EMPTY;
    }

    function getLeafNodeHash(
        uint256 index,
        uint256 value
    ) internal pure returns (uint256) {
        uint256[3] memory params = [index, value, uint256(1)];
        bytes memory encoded = abi.encode(params);
        return uint256(keccak256(encoded));
    }
}
