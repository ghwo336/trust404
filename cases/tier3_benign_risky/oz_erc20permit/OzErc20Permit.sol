// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;

import "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import "@openzeppelin/contracts/token/ERC20/extensions/ERC20Permit.sol";

/// @dev OpenZeppelin ERC20 + ERC20Permit (EIP-2612).
contract OzErc20Permit is ERC20, ERC20Permit {
    constructor() ERC20("PermitToken", "PMT") ERC20Permit("PermitToken") {
        _mint(msg.sender, 1_000_000 * 10 ** decimals());
    }
}
