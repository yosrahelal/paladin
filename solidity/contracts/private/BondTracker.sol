// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";
import {ERC20} from "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import {INotoHooks} from "../private/interfaces/INotoHooks.sol";
import {InvestorRegistry} from "./InvestorRegistry.sol";

/**
 * @title BondTracker
 * @dev Hook logic to model a simple bond lifecycle on top of Noto.
 */
contract BondTracker is INotoHooks, ERC20, Ownable {
    enum Status {
        INITIALIZED,
        ISSUED,
        DISTRIBUTION_STARTED
    }

    Status internal _status;
    address internal _publicTracker;
    address internal _issuer;
    InvestorRegistry public investorRegistry;

    constructor(
        string memory name,
        string memory symbol,
        address custodian,
        address publicTracker
    ) ERC20(name, symbol) Ownable(custodian) {
        _status = Status.INITIALIZED;
        _publicTracker = publicTracker;
        _issuer = _msgSender();
        investorRegistry = new InvestorRegistry(custodian);
    }

    function onMint(
        address sender,
        address to,
        uint256 amount,
        PreparedTransaction calldata prepared
    ) external onlyOwner {
        require(sender == _issuer, "Bond must be issued by issuer");
        require(to == owner(), "Bond must be issued to custodian");
        require(_status == Status.INITIALIZED, "Bond has already been issued");
        _mint(to, amount);
        _status = Status.ISSUED;

        emit PenteExternalCall(
            _publicTracker,
            abi.encodeWithSignature("onIssue(address,uint256)", to, amount)
        );
        emit PenteExternalCall(prepared.contractAddress, prepared.encodedCall);
    }

    function beginDistribution(
        uint256 discountPrice,
        uint256 minimumDenomination
    ) external {
        _status = Status.DISTRIBUTION_STARTED;
        emit PenteExternalCall(
            _publicTracker,
            abi.encodeWithSignature(
                "beginDistribution(uint256,uint256)",
                discountPrice,
                minimumDenomination
            )
        );
    }

    function onTransfer(
        address sender,
        address from,
        address to,
        uint256 amount,
        PreparedTransaction calldata prepared
    ) external onlyOwner {
        require(
            investorRegistry.isRegistered(to),
            "Investor is not registered"
        );
        _transfer(from, to, amount);

        if (from == owner()) {
            emit PenteExternalCall(
                _publicTracker,
                abi.encodeWithSignature("onDistribute(uint256)", amount)
            );
        }
        emit PenteExternalCall(prepared.contractAddress, prepared.encodedCall);
    }

    function onApproveTransfer(
        address sender,
        address from,
        address delegate,
        PreparedTransaction calldata prepared
    ) external onlyOwner {
        emit PenteExternalCall(prepared.contractAddress, prepared.encodedCall);
    }
}
