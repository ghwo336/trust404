// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;

/// Same vault with checks-effects-interactions: balance zeroed BEFORE the call.
contract ChecksEffectsWithdraw {
    mapping(address => uint256) public bal;

    function deposit() external payable {
        bal[msg.sender] += msg.value;
    }

    function withdraw() external {
        uint256 n = bal[msg.sender];
        bal[msg.sender] = 0;
        (bool s,) = msg.sender.call{value: n}("");
        require(s);
    }
}
