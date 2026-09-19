// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;

/// @dev Reflection/tax token: excludeFromFee feeds the fee amount (not a revert gate).
///      maxTx is floored at 1% of supply and only enforced during a time-limited window.
contract ReflectionToken {
    string public constant name = "ReflectionToken";
    string public constant symbol = "RFL";
    uint8 public constant decimals = 18;

    uint256 private constant _tTotal = 1_000_000 * 10 ** 18;
    uint256 private _rTotal = (type(uint256).max - (type(uint256).max % _tTotal));

    mapping(address => uint256) private _rOwned;
    mapping(address => mapping(address => uint256)) private _allowances;
    mapping(address => bool) public excludeFromFee;

    address public owner;
    uint256 public taxFee = 2;
    uint256 public maxTxAmount;
    uint256 public maxTxUntil;

    event Transfer(address indexed from, address indexed to, uint256 value);
    event Approval(address indexed owner, address indexed spender, uint256 value);

    modifier onlyOwner() {
        require(msg.sender == owner, "ReflectionToken: not owner");
        _;
    }

    constructor() {
        owner = msg.sender;
        _rOwned[msg.sender] = _rTotal;
        excludeFromFee[msg.sender] = true;
        maxTxAmount = _tTotal;
        maxTxUntil = block.timestamp + 7 days;
        emit Transfer(address(0), msg.sender, _tTotal);
    }

    function totalSupply() public pure returns (uint256) {
        return _tTotal;
    }

    function balanceOf(address account) public view returns (uint256) {
        return (_rOwned[account] * _tTotal) / _rTotal;
    }

    function allowance(address holder, address spender) external view returns (uint256) {
        return _allowances[holder][spender];
    }

    function approve(address spender, uint256 amount) external returns (bool) {
        _allowances[msg.sender][spender] = amount;
        emit Approval(msg.sender, spender, amount);
        return true;
    }

    function transfer(address to, uint256 amount) external returns (bool) {
        _transfer(msg.sender, to, amount);
        return true;
    }

    function transferFrom(address from, address to, uint256 amount) external returns (bool) {
        uint256 allowed = _allowances[from][msg.sender];
        require(allowed >= amount, "ReflectionToken: allowance");
        if (allowed != type(uint256).max) {
            _allowances[from][msg.sender] = allowed - amount;
        }
        _transfer(from, to, amount);
        return true;
    }

    function setExcludeFromFee(address account, bool excluded) external onlyOwner {
        excludeFromFee[account] = excluded;
    }

    function setTaxFee(uint256 v) external onlyOwner {
        require(v <= 10, "ReflectionToken: fee cap 10%");
        taxFee = v;
    }

    function setMaxTxAmount(uint256 v) external onlyOwner {
        require(v >= totalSupply() / 100, "ReflectionToken: maxTx floor 1%");
        maxTxAmount = v;
    }

    function setMaxTxUntil(uint256 until) external onlyOwner {
        maxTxUntil = until;
    }

    function _transfer(address from, address to, uint256 tAmount) internal {
        require(from != address(0) && to != address(0), "ReflectionToken: zero address");
        require(tAmount > 0, "ReflectionToken: zero amount");
        if (block.timestamp <= maxTxUntil) {
            require(tAmount <= maxTxAmount, "ReflectionToken: maxTx");
        }

        bool takeFee = !excludeFromFee[from] && !excludeFromFee[to] && taxFee > 0;
        uint256 tFee = takeFee ? (tAmount * taxFee) / 100 : 0;
        uint256 tTransferAmount = tAmount - tFee;

        uint256 rate = _rTotal / _tTotal;
        uint256 rAmount = tAmount * rate;
        require(_rOwned[from] >= rAmount, "ReflectionToken: balance");
        _rOwned[from] -= rAmount;
        _rOwned[to] += tTransferAmount * rate;
        if (tFee > 0) {
            _rTotal -= tFee * rate;
        }
        emit Transfer(from, to, tTransferAmount);
    }
}
