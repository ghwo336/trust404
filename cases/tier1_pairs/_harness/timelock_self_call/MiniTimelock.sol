// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;

contract MiniTimelock {
    event NewAdmin(address indexed newAdmin);
    event NewPendingAdmin(address indexed newPendingAdmin);
    event QueueTransaction(bytes32 indexed txHash, address indexed target, uint value, bytes data, uint eta);
    event ExecuteTransaction(bytes32 indexed txHash, address indexed target, uint value, bytes data, uint eta);

    address public admin;
    address public pendingAdmin;
    uint public delay;
    mapping(bytes32 => bool) public queued;

    constructor(address admin_, uint delay_) {
        admin = admin_;
        delay = delay_;
    }

    function setPendingAdmin(address pendingAdmin_) external {
        require(msg.sender == address(this), "Timelock: call must come from Timelock");
        pendingAdmin = pendingAdmin_;
        emit NewPendingAdmin(pendingAdmin_);
    }

    function acceptAdmin() external {
        require(msg.sender == pendingAdmin, "Timelock: call must come from pendingAdmin");
        admin = msg.sender;
        pendingAdmin = address(0);
        emit NewAdmin(admin);
    }

    function queueTransaction(address target, uint value, bytes calldata data, uint eta) external returns (bytes32) {
        require(msg.sender == admin, "Timelock: call must come from admin");
        require(eta >= block.timestamp + delay, "Timelock: eta must satisfy delay");
        bytes32 txHash = keccak256(abi.encode(target, value, data, eta));
        queued[txHash] = true;
        emit QueueTransaction(txHash, target, value, data, eta);
        return txHash;
    }

    function executeTransaction(address target, uint value, bytes calldata data, uint eta) external payable returns (bytes memory) {
        require(msg.sender == admin, "Timelock: call must come from admin");
        bytes32 txHash = keccak256(abi.encode(target, value, data, eta));
        require(queued[txHash], "Timelock: transaction hasn't been queued");
        require(block.timestamp >= eta, "Timelock: transaction hasn't surpassed time lock");
        queued[txHash] = false;
        (bool success, bytes memory returnData) = target.call{value: value}(data);
        require(success, "Timelock: transaction execution reverted");
        emit ExecuteTransaction(txHash, target, value, data, eta);
        return returnData;
    }
}
