// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

import {SimpleToken} from "./SimpleToken.sol";
import {IPaladinContractRegistry_V0} from "../interfaces/IPaladinContractRegistry.sol";

// SIMDomain is an un-optimized, simplistic test tool that is used in the unit tests of the test bed
// PLEASE REFER TO ZETO, NOTO AND PENTE FOR REAL EXAMPLES OF ACTUAL IMPLEMENTED DOMAINS
contract SimpleDomain is IPaladinContractRegistry_V0 {
    
    function newSimpleTokenNotarized(
        bytes32 txId,
        address notary,
        string calldata notaryLocator
    ) public {
        // Simply constructs the new contract - which will emit an event
        SimpleToken instance = new SimpleToken(notary);

        emit PaladinRegisterSmartContract_V0(
            txId,
            address(instance),
            abi.encode(notaryLocator)
        );
    }
    
}
