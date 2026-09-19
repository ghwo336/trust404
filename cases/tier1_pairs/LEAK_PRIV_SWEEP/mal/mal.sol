// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;

contract SweepVault {
    address public owner;
    mapping(address => uint256) public userDeposits;

    modifier onlyOwner() {
        require(msg.sender == owner, "not owner");
        _;
    }

    constructor() {
        owner = msg.sender;
    }

    function deposit() external payable {
        userDeposits[msg.sender] += msg.value;
    }

    function emergencyWithdraw() external onlyOwner {
        payable(owner).transfer(address(this).balance);
    }
}
