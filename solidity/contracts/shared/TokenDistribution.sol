// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";

/**
 * @title TokenDistribution
 * @dev Public tracking for the available supply of a token that is being distributed, without
 *      disclosing who requests or owns the token. Must be atomically maintained by a notary
 *      in tandem with any distribution of the token itself.
 */
contract TokenDistribution is Ownable {
    error InsufficientBalance(uint256 availableUnits, uint256 requestedUnits);
    error InvalidDenomination(uint256 minimumDenomination, uint256 totalPrice);

    address public token;
    uint256 public totalUnits;
    uint256 public availableUnits;

    address public paymentToken;
    uint256 public purchasePrice;
    uint256 public minimumDenomination;

    constructor(
        address token_,
        uint256 totalUnits_,
        address paymentToken_,
        uint256 purchasePrice_,
        uint256 minimumDenomination_
    ) Ownable(_msgSender()) {
        token = token_;
        totalUnits = totalUnits_;
        availableUnits = totalUnits_;
        paymentToken = paymentToken_;
        purchasePrice = purchasePrice_;
        minimumDenomination = minimumDenomination_;
    }

    function getPrice(uint256 quantity) public view returns (uint256) {
        uint256 totalPrice = quantity * purchasePrice;
        if (totalPrice % minimumDenomination != 0) {
            revert InvalidDenomination(minimumDenomination, totalPrice);
        }
        return totalPrice;
    }

    function purchase(uint256 quantity) external onlyOwner {
        if (quantity > availableUnits) {
            revert InsufficientBalance(availableUnits, quantity);
        }
        getPrice(quantity);
        availableUnits -= quantity;
    }
}
