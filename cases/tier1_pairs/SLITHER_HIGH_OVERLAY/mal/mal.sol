// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;

/// Accidental reentrancy: state update AFTER the external call (Slither HIGH overlay).
contract ReentrancyWithdraw {
    mapping(address => uint256) public bal;

    function deposit() external payable {
        bal[msg.sender] += msg.value;
    }

    function withdraw() external {
        (bool s,) = msg.sender.call{value: bal[msg.sender]}("");
        require(s);
        bal[msg.sender] = 0;
    }
}
