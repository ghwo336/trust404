// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;

/// Honest vault: each user withdraws exactly their own deposit.
contract HonestVault {
    mapping(address => uint256) public deposits;

    function deposit() external payable {
        deposits[msg.sender] += msg.value;
    }

    function withdraw() external {
        uint256 n = deposits[msg.sender];
        deposits[msg.sender] = 0;
        payable(msg.sender).transfer(n);
    }
}
