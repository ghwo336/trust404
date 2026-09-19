// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;

import "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/access/Ownable.sol";

/// @dev Plain ERC20 whose only sweep is rescue of a FOREIGN token, never this token.
contract Erc20ForeignRescue is ERC20, Ownable {
    constructor() ERC20("ForeignRescueToken", "FRT") {
        _mint(msg.sender, 1_000_000 * 10 ** decimals());
    }

    function rescueERC20(address foreignToken, address to, uint256 amount) external onlyOwner {
        require(foreignToken != address(this), "Erc20ForeignRescue: native token");
        require(to != address(0), "Erc20ForeignRescue: zero to");
        require(IERC20(foreignToken).transfer(to, amount), "Erc20ForeignRescue: transfer failed");
    }
}
