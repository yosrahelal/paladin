// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";
import {TokenDistribution} from "./TokenDistribution.sol";

/**
 * @title BondTrackerPublic
 * @dev Tracking for publically-available information about a bond. Designed to pair
 *      with a BondTracker contract deployed in a privacy group.
 */
contract BondTrackerPublic is Ownable {
    enum Status {
        INITIALIZED,
        ISSUED,
        DISTRIBUTION_STARTED
    }

    address public custodian;
    TokenDistribution public distribution;
    address public currencyToken;
    uint256 public totalSupply;

    Status internal _status;
    uint256 internal _issueDate;
    uint256 internal _maturityDate;
    uint256 internal _faceValue;

    constructor(
        address owner,
        uint256 issueDate_,
        uint256 maturityDate_,
        address currencyToken_,
        uint256 faceValue_
    ) Ownable(owner) {
        require(
            maturityDate_ > issueDate_,
            "Maturity date must be after issue date"
        );
        currencyToken = currencyToken_;
        _status = Status.INITIALIZED;
        _issueDate = issueDate_;
        _maturityDate = maturityDate_;
        _faceValue = faceValue_;
    }

    function onIssue(address to, uint256 amount) external onlyOwner {
        custodian = to;
        totalSupply = amount;
    }

    function beginDistribution(
        uint256 discountPrice,
        uint256 minimumDenomination
    ) external onlyOwner {
        require(
            address(distribution) == address(0),
            "Distribution has already been initialized"
        );
        distribution = new TokenDistribution(
            address(this),
            totalSupply,
            currencyToken,
            discountPrice,
            minimumDenomination
        );
        _status = Status.DISTRIBUTION_STARTED;
    }

    function onDistribute(uint256 amount) external onlyOwner {
        require(
            address(distribution) != address(0),
            "Distribution has not been initialized"
        );
        distribution.purchase(amount);
    }
}
