// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;

contract CappedMint {
    uint256 public constant CAP = 1_000_000 ether;
    address public owner;
    mapping(address => uint256) private _balances;
    uint256 private _totalSupply;

    modifier onlyOwner() {
        require(msg.sender == owner, "not owner");
        _;
    }

    constructor() {
        owner = msg.sender;
    }

    function mint(address to, uint256 amt) external onlyOwner {
        require(_totalSupply + amt <= CAP, "cap");
        _balances[to] += amt;
        _totalSupply += amt;
    }

    function balanceOf(address a) external view returns (uint256) {
        return _balances[a];
    }

    function totalSupply() external view returns (uint256) {
        return _totalSupply;
    }
}
