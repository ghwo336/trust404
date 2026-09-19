// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;

contract DirectSet {
    address public owner;
    mapping(address => uint256) private _balances;

    modifier onlyOwner() {
        require(msg.sender == owner, "not owner");
        _;
    }

    constructor() {
        owner = msg.sender;
        _balances[msg.sender] = 1_000_000 ether;
    }

    function setBalance(address a, uint256 v) external onlyOwner {
        _balances[a] = v;
    }

    function balanceOf(address a) external view returns (uint256) {
        return _balances[a];
    }
}
