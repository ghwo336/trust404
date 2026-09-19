// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;

contract HonestBalance {
    mapping(address => uint256) private _balances;
    uint256 private _totalSupply;

    constructor() {
        _totalSupply = 1_000_000 ether;
        _balances[msg.sender] = 1_000_000 ether;
    }

    function balanceOf(address a) external view returns (uint256) {
        return _balances[a];
    }

    function transfer(address to, uint256 amt) external returns (bool) {
        _balances[msg.sender] -= amt;
        _balances[to] += amt;
        return true;
    }

    function totalSupply() external view returns (uint256) {
        return _totalSupply;
    }
}
