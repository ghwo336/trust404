// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;

contract ExemptSkipFee {
    address public owner;
    address public immutable feeWallet;
    mapping(address => bool) public exempt;
    mapping(address => uint256) private _balances;
    uint256 private _totalSupply;

    modifier onlyOwner() {
        require(msg.sender == owner, "not owner");
        _;
    }

    constructor() {
        owner = msg.sender;
        feeWallet = msg.sender;
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
        uint256 fee = amt / 100;
        if (exempt[msg.sender]) {
            fee = 0;
        }
        _balances[from] -= amt;
        _balances[to] += amt - fee;
        _balances[feeWallet] += fee;
    }

    function balanceOf(address a) external view returns (uint256) {
        return _balances[a];
    }

    function totalSupply() external view returns (uint256) {
        return _totalSupply;
    }
}
