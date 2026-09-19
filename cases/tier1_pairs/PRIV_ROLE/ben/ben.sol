// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;

import "@openzeppelin/contracts/access/AccessControl.sol";

/// Documented OpenZeppelin AccessControl: DEFAULT_ADMIN_ROLE gates only setMetadataURI (off the transfer path).
contract DocumentedRoleToken is AccessControl {
    string public metadataURI;
    mapping(address => uint256) public balanceOf;

    constructor() {
        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
        balanceOf[msg.sender] = 1e24;
    }

    function setMetadataURI(string calldata uri) external onlyRole(DEFAULT_ADMIN_ROLE) {
        metadataURI = uri;
    }

    function transfer(address to, uint256 amount) external returns (bool) {
        balanceOf[msg.sender] -= amount;
        balanceOf[to] += amount;
        return true;
    }
}
