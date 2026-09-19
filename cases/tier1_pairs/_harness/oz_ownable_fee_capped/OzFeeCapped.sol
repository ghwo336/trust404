// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;

import "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import "@openzeppelin/contracts/access/Ownable.sol";

contract OzFeeCapped is ERC20, Ownable {
    uint256 public fee = 100;
    uint256 public constant MAX_FEE = 500;
    address public immutable feeWallet;

    event FeeUpdated(uint256 fee);

    constructor(address feeWallet_) ERC20("OzFeeCapped", "OZFC") {
        feeWallet = feeWallet_;
        _mint(msg.sender, 1_000_000 ether);
    }

    function setFee(uint256 f) external onlyOwner {
        require(f <= MAX_FEE, "fee too high");
        fee = f;
        emit FeeUpdated(f);
    }

    function _transfer(address from, address to, uint256 amount) internal override {
        uint256 feeAmount = amount * fee / 10_000;
        if (feeAmount > 0) {
            super._transfer(from, feeWallet, feeAmount);
        }
        super._transfer(from, to, amount - feeAmount);
    }
}
