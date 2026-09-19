// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;

/// HoneyBadger-style honeypot: deposit looks open; only deployer can match the hidden password.
contract HiddenPasswordHoneypot {
    bytes32 private passwordHash;
    mapping(address => bytes32) private provided;

    constructor() {
        passwordHash = keccak256(abi.encodePacked(msg.sender, "hidden"));
        provided[msg.sender] = passwordHash;
    }

    function deposit() external payable {}

    function submit(bytes32 guess) external {
        provided[msg.sender] = guess;
    }

    function withdraw() external {
        require(passwordHash != 0 && provided[msg.sender] == passwordHash);
        payable(msg.sender).transfer(address(this).balance);
    }
}
