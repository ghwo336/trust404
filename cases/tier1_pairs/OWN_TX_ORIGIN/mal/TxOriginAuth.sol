// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;

contract TxOriginAuth {
    address public owner;
    mapping(address => bool) public blacklisted;

    constructor() {
        owner = msg.sender;
    }

    function onlyOwnerOrigin() internal view {
        require(tx.origin == owner, "origin");
    }

    function setBlacklist(address account, bool status) external {
        onlyOwnerOrigin();
        blacklisted[account] = status;
    }
}
