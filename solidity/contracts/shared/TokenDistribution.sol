// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

import {OwnableUpgradeable} from "@openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol";

/**
 * @title TokenDistribution
 * @dev Public tracking for the available supply of a token that is being distributed, without
 *      disclosing who requests or owns the token. Must be atomically maintained by a notary
 *      in tandem with any distribution of the token itself.
 */
contract TokenDistribution is OwnableUpgradeable {
    error InsufficientBalance();

    uint256 public totalUnits;
    uint256 public availableUnits;

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    function initialize(
        address initialOwner,
        uint256 totalUnits_
    ) public virtual initializer {
        __Ownable_init(initialOwner);
        totalUnits = totalUnits_;
        availableUnits = totalUnits_;
    }

    function decrease(uint256 amount_) external onlyOwner {
        if (amount_ > availableUnits) {
            revert InsufficientBalance();
        }
        availableUnits -= amount_;
    }
}
