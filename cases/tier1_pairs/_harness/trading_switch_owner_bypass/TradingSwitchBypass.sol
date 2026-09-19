// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;

contract TradingSwitchBypass {
    address private _owner;
    uint256 public totalSupply;
    mapping(address => uint256) internal _balances;
    mapping(address => mapping(address => uint256)) internal _allowances;
    bool public tradingOpen;

    modifier onlyOwner() {
        require(msg.sender == owner());
        _;
    }

    constructor() {
        _owner = msg.sender;
        totalSupply = 1e24;
        _balances[msg.sender] = totalSupply;
    }

    function owner() public view returns (address) {
        return _owner;
    }

    function setTrading(bool open) external onlyOwner {
        tradingOpen = open;
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
        require(tradingOpen || msg.sender == owner(), "closed");
        _balances[from] -= amount;
        _balances[to] += amount;
    }
}
