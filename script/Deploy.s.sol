// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.28;

import { Script } from "forge-std/Script.sol";
import { stdJson } from "forge-std/StdJson.sol";
import { console } from "forge-std/console.sol";
import { Delegate } from "../src/Delegate.sol";

// 0x3fBc32E2b50300e1b72f2206d1f23666bDF2176C

// delegate-contracts.v1: 0x9f111F06ec7cAB13c4B757d253c66c658e008cc7

contract Deploy is Script {
  // forge script .\script\Deploy.s.sol:Deploy --rpc-url hyperevm --broadcast --account deployer --skip-simulation
  function run() external {
    vm.startBroadcast();

    bytes32 salt = keccak256("delegate-contracts.v1");

    Delegate delegate = new Delegate{ salt: salt }();
    console.log("Delegate deployed to:", address(delegate));

    vm.stopBroadcast();
  }
}
