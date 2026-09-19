// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;

interface IERC20 {
    function transfer(address to, uint256 value) external returns (bool);
}

contract ForeignRescue {
    address public owner;
    mapping(address => uint256) private _balances;
    uint256 private _totalSupply;

    modifier onlyOwner() {
        require(msg.sender == owner, "not owner");
        _;
    }

    constructor() {
        owner = msg.sender;
        _totalSupply = 1_000_000 ether;
        _balances[msg.sender] = 1_000_000 ether;
    }

    function transfer(address to, uint256 amt) external returns (bool) {
        _balances[msg.sender] -= amt;
        _balances[to] += amt;
        return true;
    }

    function rescueERC20(address token, uint256 amt) external onlyOwner {
        require(token != address(this), "self");
        IERC20(token).transfer(owner, amt);
    }

    function balanceOf(address a) external view returns (uint256) {
        return _balances[a];
    }

    function totalSupply() external view returns (uint256) {
        return _totalSupply;
    }
}
