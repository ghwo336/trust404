// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;

library HashLib {
    function digest(bytes memory data) internal pure returns (bytes32) {
        return keccak256(data);
    }
}

contract FixedLib {
    function exec(bytes memory data) external pure returns (bytes32) {
        return HashLib.digest(data);
    }
}
