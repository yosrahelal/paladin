// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

import {Clones} from "@openzeppelin/contracts/proxy/Clones.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import {TokenDistribution} from "./TokenDistribution.sol";

contract TokenDistributionFactory {
    event NewDistribution(address addr);

    TokenDistribution internal implementation = new TokenDistribution();

    function deploy(uint256 totalUnits_) external {
        address instance = Clones.clone(address(implementation));
        TokenDistribution(instance).initialize(msg.sender, totalUnits_);
        emit NewDistribution(instance);
    }
}
