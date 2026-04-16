// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.28;

import { IERC20 } from "@openzeppelin/contracts/interfaces/IERC20.sol";
import { Clones } from "@openzeppelin/contracts/proxy/Clones.sol";
import { Delegate } from "./Delegate.sol";

library DelegateLib {
  function deploy(address implementation, uint256 salt) internal returns (address payable) {
    return deploy(implementation, bytes32(salt));
  }

  function deploy(address implementation, bytes32 salt) internal returns (address payable) {
    return payable(Clones.cloneDeterministicWithImmutableArgs(implementation, abi.encode(address(this)), salt));
  }

  function predict(address implementation, uint256 salt, address deployer) internal view returns (address payable) {
    return predict(implementation, bytes32(salt), deployer);
  }

  function predict(
    address implementation,
    bytes32 salt,
    address deployer
  ) internal view returns (address payable addr) {
    addr = payable(
      Clones.predictDeterministicAddressWithImmutableArgs(implementation, abi.encode(address(this)), salt, deployer)
    );
  }

  function safeTransfer(Delegate delegate, address token, address to, uint256 amount) internal {
    bytes memory result = delegate.call(token, abi.encodeCall(IERC20.transfer, (to, amount)));
    require(checkReturn(result, token));
  }

  function safeTransferFrom(Delegate delegate, address token, address from, address to, uint256 amount) internal {
    bytes memory result = delegate.call(token, abi.encodeCall(IERC20.transferFrom, (from, to, amount)));
    require(checkReturn(result, token));
  }

  function checkReturn(bytes memory result, address token) private view returns (bool) {
    if (result.length == 0) {
      return token.code.length > 0;
    }
    return result.length >= 32 && abi.decode(result, (bool));
  }

  function safeApprove(Delegate delegate, address token, address spender, uint256 amount) internal {
    bool success;
    try delegate.call(token, abi.encodeCall(IERC20.approve, (spender, amount))) returns (bytes memory result) {
      success = checkReturn(result, token);
    } catch {
      success = false;
    }

    if (success == false) {
      // USDT-style: some tokens require resetting allowance to 0 before changing a non-zero allowance.
      // Both the reset and the retry must succeed.
      bytes memory result = delegate.call(token, abi.encodeCall(IERC20.approve, (spender, 0)));
      require(checkReturn(result, token));

      result = delegate.call(token, abi.encodeCall(IERC20.approve, (spender, amount)));
      require(checkReturn(result, token));
    }
  }
}
