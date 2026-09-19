// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;

contract Broken {
    function nope() public {
        uint256 x = @@@ not-valid-solidity
