// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;

import "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import "@openzeppelin/contracts/access/Ownable2Step.sol";

contract OzTwoStepToken is ERC20, Ownable2Step {
    uint256 public constant CAP = 1_000_000 ether;

    constructor() ERC20("OzTwoStepToken", "OZ2S") {}

    function mint(address to, uint256 amt) external onlyOwner {
        require(totalSupply() + amt <= CAP, "cap exceeded");
        _mint(to, amt);
    }
}
