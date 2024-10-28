// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";
import {IPenteExternalCall} from "./interfaces/IPenteExternalCall.sol";

/**
 * @title BondSubscription
 * @dev Private state between an investor and a bond custodian, tracking their subscribed units.
 */
contract BondSubscription is Ownable, IPenteExternalCall {
    address public bondAddress;
    uint256 public requestedUnits;
    uint256 public receivedUnits;

    address internal distributeBondAddress;
    bytes internal distributeBondCall;

    constructor(address bondAddress_, uint256 units_) Ownable(_msgSender()) {
        bondAddress = bondAddress_;
        requestedUnits = units_;
    }

    function prepareBond(
        address to,
        bytes calldata encodedCall
    ) external {
        distributeBondAddress = to;
        distributeBondCall = encodedCall;
    }

    function distribute(uint256 units_) external onlyOwner {
        require(
            units_ <= requestedUnits &&
                receivedUnits <= requestedUnits - units_,
            "Cannot receive more units than were requested"
        );
        require(distributeBondCall.length > 0, "Bond transfer has not been prepared");
        receivedUnits += units_;
        emit PenteExternalCall(distributeBondAddress, distributeBondCall);
    }
}
