// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";

/**
 * @title BondSubscription
 * @dev Private state between an investor and a bond custodian, tracking their subscribed units.
 */
contract BondSubscription is Ownable {
    address public distributionAddress;
    uint256 public requestedUnits;
    uint256 public receivedUnits;

    constructor(
        address distributionAddress_,
        uint256 units_
    ) Ownable(_msgSender()) {
        distributionAddress = distributionAddress_;
        requestedUnits = units_;
    }

    function markReceived(uint256 units_) external onlyOwner {
        require(
            units_ <= requestedUnits && receivedUnits <= requestedUnits - units_,
            "Cannot receive more units than were requested"
        );
        receivedUnits += units_;
    }
}
