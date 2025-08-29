// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract Allowlist {
    address public owner;
    mapping(address => bool) private _allowed;

    event Allowed(address indexed account, bool isAllowed);

    modifier onlyOwner() {
        require(msg.sender == owner, "Not owner");
        _;
    }

    constructor(address[] memory initial) {
        owner = msg.sender;
        for (uint256 i = 0; i < initial.length; i++) {
            _allowed[initial[i]] = true;
            emit Allowed(initial[i], true);
        }
    }

    function setAllowed(address account, bool isAllowed) external onlyOwner {
        _allowed[account] = isAllowed;
        emit Allowed(account, isAllowed);
    }

    function isAllowed(address account) external view returns (bool) {
        return _allowed[account];
    }
}
