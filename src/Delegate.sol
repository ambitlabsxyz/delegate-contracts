// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.28;

import { Address } from "@openzeppelin/contracts/utils/Address.sol";
import { Clones } from "@openzeppelin/contracts/proxy/Clones.sol";

/// @notice Minimal executor contract deployed as an EIP-1167 clone.
contract Delegate {
  error RevertCallSuccess(bytes result);
  error RevertCallFailure(bytes result);

  receive() external payable {}

  function owner() public view returns (address) {
    return abi.decode(Clones.fetchCloneArgs(address(this)), (address));
  }

  function send(address payable to, uint256 value) external {
    require(msg.sender == owner());
    Address.sendValue(to, value);
  }

  function call(address target, bytes calldata data) external returns (bytes memory) {
    require(msg.sender == owner());
    return Address.functionCall(target, data);
  }

  function call(address target, bytes calldata data, uint256 value) external returns (bytes memory) {
    require(msg.sender == owner());
    return Address.functionCallWithValue(target, data, value);
  }

  function revertCall(address target, bytes calldata data) external {
    revertCall(target, data, 0);
  }

  function revertCall(address target, bytes calldata data, uint256 value) public {
    require(msg.sender == owner());
    (bool success, bytes memory result) = target.call{ value: value }(data);
    if (success) {
      revert RevertCallSuccess(result);
    }
    revert RevertCallFailure(result);
  }
}
