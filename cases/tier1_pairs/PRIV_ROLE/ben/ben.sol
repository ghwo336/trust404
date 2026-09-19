// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;

import "@openzeppelin/contracts/access/AccessControl.sol";

/// Documented OpenZeppelin AccessControl: DEFAULT_ADMIN_ROLE gates setBlacklist.
contract DocumentedRoleToken is AccessControl {
    mapping(address => bool) public blacklist;
    mapping(address => uint256) public balanceOf;

    constructor() {
        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
        balanceOf[msg.sender] = 1e24;
    }

    function setBlacklist(address account, bool blocked) external onlyRole(DEFAULT_ADMIN_ROLE) {
        blacklist[account] = blocked;
    }

    function transfer(address to, uint256 amount) external returns (bool) {
        require(!blacklist[msg.sender] && !blacklist[to]);
        balanceOf[msg.sender] -= amount;
        balanceOf[to] += amount;
        return true;
    }
}
