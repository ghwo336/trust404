// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;

interface IERC20 {
    function transferFrom(address, address, uint) external returns (bool);
    function transfer(address, uint) external returns (bool);
}

/// Honest airdrop: sends tokens TO the caller.
contract AirdropClaim {
    IERC20 public immutable token;
    uint public immutable amount;

    constructor(IERC20 token_, uint amount_) {
        token = token_;
        amount = amount_;
    }

    function claim() external {
        token.transfer(msg.sender, amount);
    }
}
