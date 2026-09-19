// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;

import "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import "@openzeppelin/contracts/access/AccessControl.sol";

contract OzRoleBlacklist is ERC20, AccessControl {
    bytes32 public constant BLACKLISTER_ROLE = keccak256("BLACKLISTER_ROLE");

    mapping(address => bool) public blacklisted;

    event Blacklisted(address indexed account);
    event UnBlacklisted(address indexed account);

    constructor() ERC20("OzRoleBlacklist", "OZRB") {
        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
        _setRoleAdmin(BLACKLISTER_ROLE, DEFAULT_ADMIN_ROLE);
        _mint(msg.sender, 1_000_000 ether);
    }

    function blacklist(address account) external onlyRole(BLACKLISTER_ROLE) {
        blacklisted[account] = true;
        emit Blacklisted(account);
    }

    function unBlacklist(address account) external onlyRole(BLACKLISTER_ROLE) {
        blacklisted[account] = false;
        emit UnBlacklisted(account);
    }

    function _beforeTokenTransfer(address from, address to, uint256 amount) internal override {
        require(!blacklisted[from], "Blacklistable: account is blacklisted");
        require(!blacklisted[to], "Blacklistable: account is blacklisted");
        super._beforeTokenTransfer(from, to, amount);
    }
}
