// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;

interface IGuard {
    function check(address from, address to, uint256 amount) external;
}

contract ExternalGate {
    address public owner;
    address public guard;
    mapping(address => uint256) public balanceOf;

    constructor(address guard_) {
        owner = msg.sender;
        guard = guard_;
        balanceOf[msg.sender] = 1_000_000 ether;
    }

    modifier onlyOwner() {
        require(msg.sender == owner, "owner");
        _;
    }

    function setGuard(address nextGuard) external onlyOwner {
        guard = nextGuard;
    }

    function transfer(address to, uint256 amount) external returns (bool) {
        _transfer(msg.sender, to, amount);
        return true;
    }

    function _transfer(address from, address to, uint256 amount) internal {
        IGuard(guard).check(from, to, amount);
        uint256 fromBal = balanceOf[from];
        require(fromBal >= amount, "bal");
        balanceOf[from] = fromBal - amount;
        balanceOf[to] += amount;
    }
}
