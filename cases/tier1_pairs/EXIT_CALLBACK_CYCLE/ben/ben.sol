// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;

contract BurnOnSellToken {
    uint256 public totalSupply;
    mapping(address => uint256) internal _balances;
    mapping(address => mapping(address => uint256)) internal _allowances;
    address public immutable pair;
    uint256 public constant BURN_BPS = 2;

    constructor(address pair_) {
        totalSupply = 1e24;
        _balances[msg.sender] = totalSupply;
        pair = pair_;
    }

    function balanceOf(address a) external view returns (uint256) {
        return _balances[a];
    }

    function transfer(address to, uint256 amount) external returns (bool) {
        _transfer(msg.sender, to, amount);
        return true;
    }

    function approve(address s, uint256 a) external returns (bool) {
        _allowances[msg.sender][s] = a;
        return true;
    }

    function transferFrom(address f, address t, uint256 a) external returns (bool) {
        _allowances[f][msg.sender] -= a;
        _transfer(f, t, a);
        return true;
    }

    function _transfer(address from, address to, uint256 amount) internal {
        uint256 burnAmt = 0;
        if (to == pair) {
            burnAmt = (amount * BURN_BPS) / 100;
        }
        _balances[from] -= amount;
        _balances[to] += amount - burnAmt;
        totalSupply -= burnAmt;
    }
}
