// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

uint256 constant NOTO_COMMITMENT_TREE_MAX_DEPTH = 64;

/// @dev Minimal append-only sparse Merkle tree compatible with iden3 SmtLib (keccak256, depth 64).
library NotoCommitmentTreeLib {
    enum NodeType {
        EMPTY,
        LEAF,
        MIDDLE
    }

    struct Node {
        NodeType nodeType;
        uint256 childLeft;
        uint256 childRight;
        uint256 index;
        uint256 value;
    }

    struct RootEntry {
        uint256 root;
        uint256 createdAtTimestamp;
        uint256 createdAtBlock;
    }

    struct Data {
        mapping(uint256 => Node) nodes;
        RootEntry[] rootEntries;
        mapping(uint256 => uint256[]) rootIndexes;
        uint256 maxDepth;
        bool initialized;
    }

    function initialize(Data storage self) internal {
        require(!self.initialized, "Smt is already initialized");
        require(NOTO_COMMITMENT_TREE_MAX_DEPTH > 0, "Max depth must be greater than zero");
        self.maxDepth = NOTO_COMMITMENT_TREE_MAX_DEPTH;
        _addEntry(self, 0, 0, 0);
        self.initialized = true;
    }

    function addLeaf(Data storage self, uint256 index, uint256 value) internal {
        require(self.initialized, "Smt is not initialized");
        Node memory node = Node({
            nodeType: NodeType.LEAF,
            childLeft: 0,
            childRight: 0,
            index: index,
            value: value
        });

        uint256 prevRoot = getRoot(self);
        uint256 newRoot = _addLeaf(self, node, prevRoot, 0);
        _addEntry(self, newRoot, block.timestamp, block.number);
    }

    function rootExists(
        Data storage self,
        uint256 root
    ) internal view returns (bool) {
        return self.rootIndexes[root].length > 0;
    }

    function getNode(
        Data storage self,
        uint256 nodeHash
    ) internal view returns (Node memory) {
        return self.nodes[nodeHash];
    }

    function getRoot(Data storage self) internal view returns (uint256) {
        require(self.initialized, "Smt is not initialized");
        return self.rootEntries[self.rootEntries.length - 1].root;
    }

    function _addLeaf(
        Data storage self,
        Node memory newLeaf,
        uint256 nodeHash,
        uint256 depth
    ) private returns (uint256) {
        if (depth > self.maxDepth) {
            revert("Max depth reached");
        }

        Node memory node = self.nodes[nodeHash];
        uint256 nextNodeHash;
        uint256 leafHash = 0;

        if (node.nodeType == NodeType.EMPTY) {
            leafHash = _addNode(self, newLeaf);
        } else if (node.nodeType == NodeType.LEAF) {
            leafHash = node.index == newLeaf.index
                ? _addNode(self, newLeaf)
                : _pushLeaf(self, newLeaf, node, depth);
        } else if (node.nodeType == NodeType.MIDDLE) {
            Node memory newNodeMiddle;

            if ((newLeaf.index >> depth) & 1 == 1) {
                nextNodeHash = _addLeaf(self, newLeaf, node.childRight, depth + 1);

                newNodeMiddle = Node({
                    nodeType: NodeType.MIDDLE,
                    childLeft: node.childLeft,
                    childRight: nextNodeHash,
                    index: 0,
                    value: 0
                });
            } else {
                nextNodeHash = _addLeaf(self, newLeaf, node.childLeft, depth + 1);

                newNodeMiddle = Node({
                    nodeType: NodeType.MIDDLE,
                    childLeft: nextNodeHash,
                    childRight: node.childRight,
                    index: 0,
                    value: 0
                });
            }

            leafHash = _addNode(self, newNodeMiddle);
        }

        return leafHash;
    }

    function _pushLeaf(
        Data storage self,
        Node memory newLeaf,
        Node memory oldLeaf,
        uint256 depth
    ) private returns (uint256) {
        if (depth >= self.maxDepth) {
            revert("Max depth reached");
        }

        Node memory newNodeMiddle;
        bool newLeafBitAtDepth = (newLeaf.index >> depth) & 1 == 1;
        bool oldLeafBitAtDepth = (oldLeaf.index >> depth) & 1 == 1;

        if (newLeafBitAtDepth == oldLeafBitAtDepth) {
            uint256 nextNodeHash = _pushLeaf(self, newLeaf, oldLeaf, depth + 1);

            if (newLeafBitAtDepth) {
                newNodeMiddle = Node(NodeType.MIDDLE, 0, nextNodeHash, 0, 0);
            } else {
                newNodeMiddle = Node(NodeType.MIDDLE, nextNodeHash, 0, 0, 0);
            }
            return _addNode(self, newNodeMiddle);
        }

        if (newLeafBitAtDepth) {
            newNodeMiddle = Node({
                nodeType: NodeType.MIDDLE,
                childLeft: _getNodeHash(oldLeaf),
                childRight: _getNodeHash(newLeaf),
                index: 0,
                value: 0
            });
        } else {
            newNodeMiddle = Node({
                nodeType: NodeType.MIDDLE,
                childLeft: _getNodeHash(newLeaf),
                childRight: _getNodeHash(oldLeaf),
                index: 0,
                value: 0
            });
        }

        _addNode(self, newLeaf);
        return _addNode(self, newNodeMiddle);
    }

    function _addNode(
        Data storage self,
        Node memory node
    ) private returns (uint256) {
        uint256 nodeHash = _getNodeHash(node);
        if (self.nodes[nodeHash].nodeType != NodeType.EMPTY) {
            Node storage existing = self.nodes[nodeHash];
            assert(existing.nodeType == node.nodeType);
            assert(existing.childLeft == node.childLeft);
            assert(existing.childRight == node.childRight);
            assert(existing.index == node.index);
            assert(existing.value == node.value);
            return nodeHash;
        }

        self.nodes[nodeHash] = node;
        return nodeHash;
    }

    function _getNodeHash(Node memory node) private pure returns (uint256) {
        if (node.nodeType == NodeType.LEAF) {
            uint256[3] memory params = [node.index, node.value, uint256(1)];
            return uint256(keccak256(abi.encode(params)));
        }
        if (node.nodeType == NodeType.MIDDLE) {
            uint256[2] memory params = [node.childLeft, node.childRight];
            return uint256(keccak256(abi.encode(params)));
        }
        return 0;
    }

    function _addEntry(
        Data storage self,
        uint256 root,
        uint256 timestamp,
        uint256 blockNumber
    ) private {
        self.rootEntries.push(
            RootEntry({
                root: root,
                createdAtTimestamp: timestamp,
                createdAtBlock: blockNumber
            })
        );
        self.rootIndexes[root].push(self.rootEntries.length - 1);
    }
}
