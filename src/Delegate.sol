// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.28;

import { Address } from "@openzeppelin/contracts/utils/Address.sol";
import { Clones } from "@openzeppelin/contracts/proxy/Clones.sol";

/// @notice Minimal executor contract deployed as an EIP-1167 clone.
contract Delegate {
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

  /// @dev Used for on-chain previewing via the Uniswap Quoter revert-call pattern — the caller
  /// wraps this in a try/catch to capture the return value without committing state changes.
  function revertCall(address target, bytes calldata data) external returns (bytes memory) {
    return revertCall(target, data, 0);
  }

  /// @dev Used for on-chain previewing via the Uniswap Quoter revert-call pattern — the caller
  /// wraps this in a try/catch to capture the return value without committing state changes.
  function revertCall(address target, bytes calldata data, uint256 value) public returns (bytes memory) {
    require(msg.sender == owner());
    bytes memory result = Address.functionCallWithValue(target, data, value);
    assembly {
      revert(add(result, 0x20), mload(result))
    }
  }
}
