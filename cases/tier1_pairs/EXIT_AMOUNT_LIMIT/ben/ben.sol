// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;

contract LaunchWindowMaxTxToken {
    address public owner;
    uint256 internal _totalSupply;
    mapping(address => uint256) internal _balances;
    mapping(address => mapping(address => uint256)) internal _allowances;
    uint256 public maxTx;
    uint256 public immutable launchAt;

    modifier onlyOwner() {
        require(msg.sender == owner);
        _;
    }

    constructor() {
        owner = msg.sender;
        _totalSupply = 1e24;
        _balances[msg.sender] = _totalSupply;
        maxTx = _totalSupply;
        launchAt = block.timestamp;
    }

    function totalSupply() public view returns (uint256) {
        return _totalSupply;
    }

    function setMaxTx(uint256 v) external onlyOwner {
        require(v >= totalSupply() / 100);
        maxTx = v;
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
        if (block.timestamp < launchAt + 5 minutes) {
            require(amount <= maxTx);
        }
        _balances[from] -= amount;
        _balances[to] += amount;
    }
}
