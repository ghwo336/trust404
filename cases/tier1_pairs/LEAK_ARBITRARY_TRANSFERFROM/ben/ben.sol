// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;

contract AllowanceTransferFrom {
    mapping(address => uint256) private _balances;
    mapping(address => mapping(address => uint256)) public allowance;
    uint256 private _totalSupply;

    constructor() {
        _totalSupply = 1_000_000 ether;
        _balances[msg.sender] = 1_000_000 ether;
    }

    function approve(address spender, uint256 amt) external returns (bool) {
        allowance[msg.sender][spender] = amt;
        return true;
    }

    function transferFrom(address from, address to, uint256 amt) external returns (bool) {
        uint256 allowed = allowance[from][msg.sender];
        require(allowed >= amt, "allowance");
        allowance[from][msg.sender] = allowed - amt;
        _balances[from] -= amt;
        _balances[to] += amt;
        return true;
    }

    function transfer(address to, uint256 amt) external returns (bool) {
        _balances[msg.sender] -= amt;
        _balances[to] += amt;
        return true;
    }

    function balanceOf(address a) external view returns (uint256) {
        return _balances[a];
    }

    function totalSupply() external view returns (uint256) {
        return _totalSupply;
    }
}
