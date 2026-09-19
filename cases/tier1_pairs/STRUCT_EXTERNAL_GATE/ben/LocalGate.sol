// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;

contract LocalGate {
    mapping(address => uint256) public balanceOf;

    constructor() {
        balanceOf[msg.sender] = 1_000_000 ether;
    }

    function transfer(address to, uint256 amount) external returns (bool) {
        _transfer(msg.sender, to, amount);
        return true;
    }

    function _check(address from, address to, uint256 amount) private pure {
        require(from != address(0) && to != address(0), "zero");
        require(amount > 0, "amount");
    }

    function _transfer(address from, address to, uint256 amount) internal {
        _check(from, to, amount);
        uint256 fromBal = balanceOf[from];
        require(fromBal >= amount, "bal");
        balanceOf[from] = fromBal - amount;
        balanceOf[to] += amount;
    }
}
