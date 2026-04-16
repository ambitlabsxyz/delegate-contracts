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

  function predict(address implementation, uint256 salt) internal view returns (address payable) {
    return predict(implementation, bytes32(salt));
  }

  function predict(address implementation, bytes32 salt) internal view returns (address payable addr) {
    addr = payable(
      Clones.predictDeterministicAddressWithImmutableArgs(
        implementation,
        abi.encode(address(this)),
        salt,
        address(this)
      )
    );
  }

  function safeTransfer(Delegate delegate, address token, address to, uint256 amount) internal {
    bytes memory result = delegate.call(token, abi.encodeCall(IERC20.transfer, (to, amount)));
    require((result.length == 0 && token.code.length > 0) || abi.decode(result, (bool)));
  }

  function safeTransferFrom(Delegate delegate, address token, address from, address to, uint256 amount) internal {
    bytes memory result = delegate.call(token, abi.encodeCall(IERC20.transferFrom, (from, to, amount)));
    require((result.length == 0 && token.code.length > 0) || abi.decode(result, (bool)));
  }

  function safeApprove(Delegate delegate, address token, address spender, uint256 amount) internal {
    bytes memory result = delegate.call(token, abi.encodeCall(IERC20.approve, (spender, amount)));
    bool success = (result.length == 0 && token.code.length > 0) || abi.decode(result, (bool));

    // USDT-style: if approve fails, reset to 0 first then set
    if (success == false) {
      delegate.call(token, abi.encodeCall(IERC20.approve, (spender, 0)));
      result = delegate.call(token, abi.encodeCall(IERC20.approve, (spender, amount)));
      require((result.length == 0 && token.code.length > 0) || abi.decode(result, (bool)));
    }
  }
}
