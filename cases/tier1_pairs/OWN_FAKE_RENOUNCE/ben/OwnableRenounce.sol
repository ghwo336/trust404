// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;

import "@openzeppelin/contracts/access/Ownable.sol";

contract OwnableRenounce is Ownable {
    mapping(address => bool) public blacklisted;

    function setBlacklist(address account, bool status) external onlyOwner {
        blacklisted[account] = status;
    }
}
