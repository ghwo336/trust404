// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;

/// Escrow: deposit is refundable only to the same depositor (no cross-funding).
contract UserEscrow {
    mapping(address => uint256) public deposited;

    function deposit() external payable {
        deposited[msg.sender] += msg.value;
    }

    function refund() external {
        uint256 n = deposited[msg.sender];
        deposited[msg.sender] = 0;
        payable(msg.sender).transfer(n);
    }
}
