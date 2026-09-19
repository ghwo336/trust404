// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;

import "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import "@openzeppelin/contracts/access/Ownable.sol";

contract OzOwnableRug is ERC20, Ownable {
    mapping(address => bool) public bots;

    constructor() ERC20("OzOwnableRug", "OZR") {
        _mint(msg.sender, 1_000_000 ether);
    }

    function setBots(address account, bool isBot) external onlyOwner {
        bots[account] = isBot;
    }

    function _beforeTokenTransfer(address from, address to, uint256 amount) internal override {
        require(!bots[from] && !bots[to], "bot");
        super._beforeTokenTransfer(from, to, amount);
    }
}
