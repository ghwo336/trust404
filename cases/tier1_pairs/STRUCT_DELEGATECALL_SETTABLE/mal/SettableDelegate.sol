// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;

contract SettableDelegate {
    address public owner;
    address public impl;

    constructor() {
        owner = msg.sender;
    }

    modifier onlyOwner() {
        require(msg.sender == owner, "owner");
        _;
    }

    function setImpl(address nextImpl) external onlyOwner {
        impl = nextImpl;
    }

    function exec(bytes memory data) external onlyOwner {
        (bool ok,) = impl.delegatecall(data);
        require(ok);
    }
}
