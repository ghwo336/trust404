// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;

import "./Helper.sol";

contract Token {
    mapping(address => uint256) public balanceOf;

    constructor() {
        balanceOf[msg.sender] = 1_000_000 ether;
    }

    function name() external pure returns (string memory) {
        return Helper.name();
    }

    function symbol() external pure returns (string memory) {
        return Helper.symbol();
    }

    function transfer(address to, uint256 amount) external returns (bool) {
        balanceOf[msg.sender] -= amount;
        balanceOf[to] += amount;
        return true;
    }
}
