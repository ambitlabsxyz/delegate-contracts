// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.28;

import { Script } from "forge-std/Script.sol";
import { stdJson } from "forge-std/StdJson.sol";
import { console } from "forge-std/console.sol";
import { Delegate } from "../src/Delegate.sol";

// 0x3fBc32E2b50300e1b72f2206d1f23666bDF2176C

// delegate-contracts.v1: 0xb85fe8D2c4eFFf7AD8E76F9Be80Bd2049F637DBe

address constant DEPLOYER = 0x6B887caC2e0Ef29306E1B6F22E716796105137a0;

interface ICreateX {
  function deployCreate3(bytes32 salt, bytes memory initCode) external payable returns (address newContract);
}

contract Deploy is Script {
  // forge script .\script\Deploy.s.sol:Deploy --rpc-url hyperevm --broadcast --account deployer --skip-simulation
  function run() external {
    vm.startBroadcast();

    ICreateX createX = ICreateX(0xba5Ed099633D3B313e4D5F7bdc1305d3c28ba5Ed);

    bytes32 salt = bytes32(abi.encodePacked(DEPLOYER, hex"00", bytes11(keccak256("delegate-contracts.v1"))));

    bytes memory initCode = abi.encodePacked(type(Delegate).creationCode);

    address delegate = createX.deployCreate3(salt, initCode);

    console.log("Delegate deployed to:", delegate);

    vm.stopBroadcast();
  }
}
