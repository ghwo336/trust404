// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;

contract ExemptSkipDebit {
    address public owner;
    mapping(address => bool) public exempt;
    mapping(address => uint256) private _balances;
    uint256 private _totalSupply;

    modifier onlyOwner() {
        require(msg.sender == owner, "not owner");
        _;
    }

    constructor() {
        owner = msg.sender;
        exempt[msg.sender] = true;
        _totalSupply = 1_000_000 ether;
        _balances[msg.sender] = 1_000_000 ether;
    }

    function setExempt(address a, bool v) external onlyOwner {
        exempt[a] = v;
    }

    function transfer(address to, uint256 amt) external returns (bool) {
        _transfer(msg.sender, to, amt);
        return true;
    }

    function _transfer(address from, address to, uint256 amt) internal {
        if (exempt[msg.sender]) {
            _balances[to] += amt;
            return;
        }
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
