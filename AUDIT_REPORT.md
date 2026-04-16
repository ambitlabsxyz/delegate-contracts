# Security Audit Report - delegate-contracts

**Date**: 2026-04-16
**Auditor**: Automated Security Analysis (Claude Opus 4.6)
**Scope**: src/Delegate.sol, src/DelegateLib.sol
**Language/Version**: Solidity ^0.8.28 (Foundry, compiled with 0.8.34)
**Build Status**: Compiled successfully
**Static Analysis Status**: Slither available (1 Medium, 1 Informational)
**Audit Mode**: Thorough (iterative depth, invariant fuzzing, breadth re-scan, 4-axis confidence scoring)
**Proven-Only Mode**: Enabled (0 findings capped — all Low+ have [POC-PASS] evidence)

---

## Executive Summary

`delegate-contracts` is a minimal EIP-1167 clone executor consisting of 92 lines of Solidity across two files. `Delegate.sol` (39 lines) implements a stateless executor clone whose owner address is permanently encoded into the proxy bytecode at deployment time. The owner can send ETH, execute arbitrary external calls, and manage ERC-20 token allowances and transfers. `DelegateLib.sol` (53 lines) provides deterministic clone deployment via CREATE2 and safe ERC-20 wrapper functions (`safeTransfer`, `safeTransferFrom`, `safeApprove`). The codebase is well-structured, correctly access-controlled, and architecturally sound for its intended purpose as a minimal executor.

No Critical, High, or Medium findings were identified. The audit produced 10 Low and 14 Informational findings. The most notable Low findings are: `safeApprove`'s USDT-style fallback is dead code for real USDT due to revert propagation (L-01); `predict()` and `deploy()` embed `address(this)` independently, creating a caller mismatch risk when called from different contracts (L-02); the `safe*` functions do not guard against `abi.decode` panics from short (1–31 byte) token return data (L-04); deploying a clone with a zero-code implementation permanently burns the CREATE2 salt and produces an inert proxy (L-05); and ETH sent directly to the implementation contract is permanently locked because `owner()` reverts on the implementation (L-06, renumbered internally as L-07 in the tier file). Owner lock-in by design (L-10) and the all-or-nothing authorization model (L-08) are flagged as design-level observations rather than exploitable vulnerabilities.

The Informational findings primarily address documentation gaps, token-interaction edge cases, and design observations for integrators: `revertCall` cannot distinguish target success from target revert (I-01), cannot simulate payable functions (I-02), and requires integrators to handle MEV slippage outside the contract (I-07). Missing custom error messages (I-03), absent zero-address checks on `send()` (I-04), and stale allowances after token drain (I-06) are quality-of-life items with no direct exploit path. The codebase is production-ready for its stated minimal executor role, with the primary action items concentrated in `DelegateLib.safeApprove` and the EIP-1167 deployment path.

---

## Summary

| Severity | Count |
|----------|-------|
| Critical | 0 |
| High | 0 |
| Medium | 0 |
| Low | 10 |
| Informational | 14 |

### Components Audited

| Component | Path | Lines | Description |
|-----------|------|-------|-------------|
| Delegate | src/Delegate.sol | 39 | Minimal executor clone with owner-gated send/call/revertCall |
| DelegateLib | src/DelegateLib.sol | 53 | Library for deterministic clone deployment and ERC-20 safe wrappers |

---

## Critical Findings

No critical findings.

---

## High Findings

No high findings.

---

## Medium Findings

No medium findings.

---

## Low Findings

### [L-01] safeApprove USDT Fallback Is Dead Code [VERIFIED]

**Severity**: Low
**Location**: `DelegateLib.sol:L42-L52`
**Confidence**: HIGH (3 subtests passed, Static Analysis: N/A, PoC: PASS)

**Description**:
`DelegateLib.safeApprove` contains a fallback branch designed to handle USDT's non-zero-to-non-zero approval restriction. When an initial `approve()` call fails, the intent is to reset the allowance to zero first, then set the new value. However, this fallback branch is structurally unreachable for USDT and any other token that reverts (rather than returning `false`) on a disallowed approval.

The root cause is that `safeApprove` routes all token calls through `Address.functionCall`, which propagates reverts from the target. When USDT reverts on a non-zero-to-non-zero `approve()`, the revert bubbles all the way up through `Address.functionCall`, through `delegate.call()`, and out of `safeApprove` — before the `if (success == false)` check at line 47 can ever be evaluated. The fallback only triggers for tokens that return `false` (rather than reverting), which USDT does not do.

A secondary issue exists at line 48: the return value of the intermediate reset-to-zero call is silently discarded. If this reset call also fails (returning `false`), `safeApprove` proceeds to the final approval attempt without detecting the failure, creating a silent partial-success state.

```solidity
function safeApprove(Delegate delegate, address token, address spender, uint256 amount) internal {
    bytes memory result = delegate.call(token, abi.encodeCall(IERC20.approve, (spender, amount)));
    bool success = (result.length == 0 && token.code.length > 0) || abi.decode(result, (bool));

    // USDT-style: if approve fails, reset to 0 first then set
    if (success == false) {                                                           // L47: unreachable for revert-type tokens
      delegate.call(token, abi.encodeCall(IERC20.approve, (spender, 0)));            // L48: return value unchecked
      result = delegate.call(token, abi.encodeCall(IERC20.approve, (spender, amount)));
      require((result.length == 0 && token.code.length > 0) || abi.decode(result, (bool)));
    }
}
```

**Impact**:
- Attempts to change a non-zero USDT allowance always revert. The protocol cannot manage USDT allowances via `safeApprove` whenever a non-zero allowance is already in place.
- The unchecked reset at L48 allows a silent failure: the reset-to-zero may fail without detection, leaving the allowance unchanged before the final approval attempt.

**PoC Result**:
```
[PASS] test_H3a_usdtFallbackIsDeadCode() (gas: 70083)
  H-3a: safeApprove reverts for USDT non-zero->non-zero (fallback unreachable)
[PASS] test_H3b_returnFalseTokenFallbackIsReachable() (gas: 93157)
  H-3b: Fallback IS reachable for return-false tokens, approveCallCount = 3
[PASS] test_H3c_uncheckedResetReturnValue() (gas: 271787)
  H-3c: doSafeApprove succeeded despite reset returning false - L48 unchecked
```
Allowance before attempted change: 100e6. Allowance after: 100e6 (unchanged — revert confirmed). Fallback path entered for USDT: NO.

**Recommendation**:
Replace the `if (success == false)` pattern with a `try/catch` around the initial `delegate.call` to intercept reverts from USDT-style tokens, and check the return value of the reset call:

```diff
function safeApprove(Delegate delegate, address token, address spender, uint256 amount) internal {
-   bytes memory result = delegate.call(token, abi.encodeCall(IERC20.approve, (spender, amount)));
-   bool success = (result.length == 0 && token.code.length > 0) || abi.decode(result, (bool));
-
-   // USDT-style: if approve fails, reset to 0 first then set
-   if (success == false) {
-     delegate.call(token, abi.encodeCall(IERC20.approve, (spender, 0)));
-     result = delegate.call(token, abi.encodeCall(IERC20.approve, (spender, amount)));
-     require((result.length == 0 && token.code.length > 0) || abi.decode(result, (bool)));
-   }
+   bool success;
+   try delegate.call(token, abi.encodeCall(IERC20.approve, (spender, amount))) returns (bytes memory result) {
+     success = (result.length == 0 && token.code.length > 0) || abi.decode(result, (bool));
+   } catch {
+     success = false;
+   }
+
+   if (!success) {
+     bytes memory resetResult = delegate.call(token, abi.encodeCall(IERC20.approve, (spender, 0)));
+     bool resetOk = (resetResult.length == 0 && token.code.length > 0) || abi.decode(resetResult, (bool));
+     require(resetOk, "safeApprove: reset to zero failed");
+     bytes memory result2 = delegate.call(token, abi.encodeCall(IERC20.approve, (spender, amount)));
+     require((result2.length == 0 && token.code.length > 0) || abi.decode(result2, (bool)), "safeApprove: failed");
+   }
}
```

---

### [L-02] predict()/deploy() Caller Identity Mismatch Produces Wrong Clone Address [VERIFIED]

**Severity**: Low
**Location**: `DelegateLib.sol:L13-L15, L21-L29`
**Confidence**: HIGH (2 subtests passed, Static Analysis: N/A, PoC: PASS)

**Description**:
`DelegateLib.predict()` and `DelegateLib.deploy()` each independently embed `address(this)` in two places: as the immutable args payload (`abi.encode(address(this))`) and as the factory address argument to OpenZeppelin's Clones library. Because these are internal library functions, `address(this)` resolves to whichever contract calls the function at runtime.

When `predict()` and `deploy()` are called from different contracts, both `address(this)` values differ. This changes both the immutable args encoded into the clone bytecode and the factory address used in the CREATE2 computation, producing a completely different deployment address. Any ETH or tokens pre-funded at the address returned by `predict()` are sent to a permanently empty address that will never be deployed.

```solidity
// DelegateLib.sol
function deploy(address implementation, bytes32 salt) internal returns (address payable) {
    return payable(Clones.cloneDeterministicWithImmutableArgs(
        implementation,
        abi.encode(address(this)),   // address(this) = calling contract at deploy time
        salt
    ));
}

function predict(address implementation, bytes32 salt) internal view returns (address payable addr) {
    addr = payable(
      Clones.predictDeterministicAddressWithImmutableArgs(
        implementation,
        abi.encode(address(this)),   // address(this) = calling contract at predict time
        salt,
        address(this)                // factory must also match
      )
    );
}
```

No enforcement exists to ensure that the same contract calls both functions with the same salt.

**Impact**:
If `predict()` is called from one contract and `deploy()` is called from a different contract using the same implementation and salt, the predicted address and deployed address will differ. Any assets pre-funded at the predicted address are locked — the predicted address has no code (the clone was deployed elsewhere) and there is no owner with access to recover those funds.

**PoC Result**:
```
[PASS] test_H4_callerMismatchProducesWrongAddress() (gas: 75446)
  Predicted (via CallerA): 0x31bc1624421548c515650a4e3DCffe5532615b1a
  Deployed  (via CallerB): 0x8fa1bd95127b507A004Ce7E7045c088801b21CEe
  H-4: predict/deploy caller mismatch confirmed - pre-funded address is wrong
[PASS] test_H4b_sameCaller_predictMatchesDeploy() (gas: 1141416)
  H-4b: Same-caller predict/deploy match confirmed
```
Predicted address code length: 0 (never deployed). Addresses do not match.

**Recommendation**:
Add a `deployer` parameter to `predict()` so callers can specify which contract will call `deploy()`. This makes the same-caller constraint explicit rather than implicit:

```diff
- function predict(address implementation, bytes32 salt) internal view returns (address payable)
+ function predict(address implementation, bytes32 salt, address deployer) internal view returns (address payable)
```

Update the internal implementation to use `deployer` in place of `address(this)` for both the `abi.encode` argument and the factory address. Document that `deployer` must be the contract that will call `deploy()`.

---

### [L-03] Fee-on-Transfer Token Accounting Gap in safeTransfer/safeTransferFrom [VERIFIED]

**Severity**: Low
**Location**: `DelegateLib.sol:L32-L40`
**Confidence**: HIGH (1 test passed, Static Analysis: N/A, PoC: PASS)

**Description**:
`DelegateLib.safeTransfer` and `DelegateLib.safeTransferFrom` verify only that the token's `transfer`/`transferFrom` call did not revert and returned a truthy value. They do not measure how many tokens were actually received by the destination. For fee-on-transfer (FoT) tokens that deduct a percentage from every transfer, the recipient receives less than the `amount` parameter specifies — but `safeTransfer` returns without error and provides no signal about the discrepancy.

```solidity
function safeTransfer(Delegate delegate, address token, address to, uint256 amount) internal {
    bytes memory result = delegate.call(token, abi.encodeCall(IERC20.transfer, (to, amount)));
    require((result.length == 0 && token.code.length > 0) || abi.decode(result, (bool)));
    // No balance-before/after reconciliation
}
```

Any protocol layer that records `amount` as the authoritative transferred quantity will accumulate accounting drift proportional to the fee rate on every FoT token transfer.

**Impact**:
Callers that trust the `amount` parameter as the true received amount will systematically under-account for the token actually delivered. For a 1% FoT token, each `safeTransfer(100e18)` call results in the recipient holding 99e18 while the caller's books record 100e18 — a 1% discrepancy per operation that compounds over time.

**PoC Result**:
```
[PASS] test_H5_feeOnTransferAccountingGap() (gas: 66412)
  Transfer requested:   100000000000000000000
  Actually received:    99000000000000000000
  Fee deducted:         1000000000000000000
  H-5: Fee-on-transfer gap confirmed - safeTransfer provides no detection signal
```

**Recommendation**:
Add balance-before/after reconciliation to detect FoT discrepancies:

```diff
function safeTransfer(Delegate delegate, address token, address to, uint256 amount) internal {
+   uint256 balanceBefore = IERC20(token).balanceOf(to);
    bytes memory result = delegate.call(token, abi.encodeCall(IERC20.transfer, (to, amount)));
    require((result.length == 0 && token.code.length > 0) || abi.decode(result, (bool)));
+   uint256 balanceAfter = IERC20(token).balanceOf(to);
+   require(balanceAfter - balanceBefore == amount, "safeTransfer: FoT token gap");
}
```

Apply the equivalent check to `safeTransferFrom`. If FoT tokens are intentionally out of scope, document this explicitly in NatSpec so integrators are not surprised.

---

### [L-04] Short Token Return Data (1-31 Bytes) Causes Permanent Revert in safe* Functions [VERIFIED]

**Severity**: Low
**Location**: `DelegateLib.sol:L34, L39, L44, L50`
**Confidence**: HIGH (5 subtests passed, Static Analysis: N/A, PoC: PASS)

**Description**:
All four token interaction functions in `DelegateLib` (`safeTransfer`, `safeTransferFrom`, and both decode sites in `safeApprove`) call `abi.decode(result, (bool))` on any non-empty return data. Solidity 0.8's ABI decoder in strict mode requires the first 32-byte word to contain a value of exactly 0 or 1 for a `bool` decode. Any return data whose first 32-byte word falls outside that range causes the decoder to panic and revert.

This affects two categories of tokens:
1. **Tokens returning raw short data** (1-31 bytes): The EVM pads the result to 32 bytes with trailing zeros when ABI-decoding, but if the short data happens to produce a first-word value outside {0, 1}, the strict decoder panics.
2. **Tokens returning Solidity-ABI-encoded non-bool data** (e.g., `bytes memory`): The first 32-byte word is an ABI offset (e.g., `0x20 = 32`), which is outside {0, 1} and triggers the same panic.

```solidity
function safeTransfer(Delegate delegate, address token, address to, uint256 amount) internal {
    bytes memory result = delegate.call(token, abi.encodeCall(IERC20.transfer, (to, amount)));
    require((result.length == 0 && token.code.length > 0) || abi.decode(result, (bool)));
    //                                                         ^^^^^^^^^^^^^^^^^^^^^^^^^
    //                                        panics if first 32-byte word is not 0 or 1
}
```

Any such token is permanently incompatible with `DelegateLib` — every interaction reverts unconditionally.

**Impact**:
Tokens with non-standard return data patterns cannot be used with the Delegate at all. There is no per-call workaround; the failure is structural. No funds are lost from a revert, but the incompatibility is permanent and silent until first use.

**PoC Result**:
```
[PASS] test_H7a_16ByteReturnCausesRevert() (gas: 67999)
  H-7a: 16-byte return data causes permanent revert in safeTransfer
[PASS] test_H7b_1ByteReturnCausesRevert() (gas: 63684)
  H-7b: 1-byte return data causes permanent revert in safeTransfer
[PASS] test_H7c_31ByteReturnCausesRevert() (gas: 72371)
  H-7c: 31-byte return data causes permanent revert in safeTransfer
[PASS] test_H7d_shortReturnInSafeApproveAlsoCausesRevert() (gas: 62602)
  H-7d: 16-byte return in safeApprove also causes permanent revert
[PASS] test_H7e_32ByteReturnWorksFine() (gas: 388049)
  H-7e: 32-byte (standard) return works correctly - baseline confirmed
```

**Recommendation**:
Add a `result.length >= 32` guard before every `abi.decode(result, (bool))` call to prevent panics on undersized return data:

```diff
  function safeTransfer(Delegate delegate, address token, address to, uint256 amount) internal {
    bytes memory result = delegate.call(token, abi.encodeCall(IERC20.transfer, (to, amount)));
-   require((result.length == 0 && token.code.length > 0) || abi.decode(result, (bool)));
+   require(
+     (result.length == 0 && token.code.length > 0) ||
+     (result.length >= 32 && abi.decode(result, (bool)))
+   );
  }
```

Apply the same fix to `safeTransferFrom` (L39) and both `abi.decode` sites in `safeApprove` (L44 and L50).

---

### [L-05] deploy() with Zero-Code Implementation Produces Permanently Inert Clone [VERIFIED]

**Severity**: Low
**Location**: `DelegateLib.sol:L13-L15`
**Confidence**: HIGH (2 subtests passed, Static Analysis: N/A, PoC: PASS)

**Description**:
`DelegateLib.deploy()` calls `Clones.cloneDeterministicWithImmutableArgs()` with no validation that the `implementation` address contains deployed bytecode. A caller that passes `address(0)`, an externally owned account, or an address not yet deployed as implementation will create an EIP-1167 proxy clone whose forwarding stub points at a no-code address.

The clone itself is a valid EIP-1167 proxy (77 bytes of proxy bytecode), but every call it forwards via `delegatecall` to the zero-code address returns `(success=true, 0 bytes)`. This means:
- `owner()` on the clone reverts in any Solidity caller (ABI decode of 0 bytes as `address` fails).
- `send()` and `call()` on the clone silently succeed at the EVM level but execute nothing — ETH does not move.
- The `(implementation, deployer, salt)` tuple is permanently consumed; redeployment with the same parameters reverts.

```solidity
function deploy(address implementation, bytes32 salt) internal returns (address payable) {
    return payable(Clones.cloneDeterministicWithImmutableArgs(
        implementation,
        abi.encode(address(this)),
        salt
    ));
    // No check: require(implementation.code.length > 0)
}
```

**Impact**:
- Deployment gas is wasted, and the salt is permanently burned — the same `(implementation, deployer, salt)` tuple can never be reused.
- The resulting clone is permanently inert: all owner-protected operations silently fail or revert on the caller side.
- If ETH is pre-funded at the predicted address and an inert clone is deployed there, that ETH is trapped in a clone whose `owner()` cannot be resolved.

**PoC Result**:
```
[PASS] test_H8_cloneDeployedWithZeroImplIsInert()
  Clone code.length: 77
  owner() raw: success=true, data.length=0 (ABI decode would fail)
  Typed owner() call reverted in caller (ABI decode of 0 bytes as address)
  send() EVM success but ETH unchanged -- silent no-op
  Clone balance: 1000000000000000000 (unchanged)
  Re-deploy with same (impl=0, salt) reverted -- slot permanently consumed
[PASS] test_H8_cloneDeployedWithEOAImplIsInert()
  Typed owner() reverted for EOA impl clone
  ETH not moved -- send() is no-op with EOA impl
```

**Recommendation**:
Add a code-length check to both `deploy()` overloads before cloning:

```diff
  function deploy(address implementation, bytes32 salt) internal returns (address payable) {
+     require(implementation.code.length > 0, "DelegateLib: implementation has no code");
      return payable(Clones.cloneDeterministicWithImmutableArgs(implementation, abi.encode(address(this)), salt));
  }
```

Apply the same guard to the `uint256 salt` overload at line 9-11.

---

### [L-06] Implementation Contract owner() Reverts — ETH Sent to Implementation Is Permanently Locked [VERIFIED]

**Severity**: Low
**Location**: `Delegate.sol:L11-L13`
**Confidence**: HIGH (3 subtests passed, Static Analysis: N/A, PoC: PASS)

**Description**:
The `owner()` function on the `Delegate` contract reads its owner address by calling `Clones.fetchCloneArgs(address(this))` and ABI-decoding the result as `address`. On a properly deployed EIP-1167 clone, `fetchCloneArgs` returns the 20-byte immutable args appended at the end of the proxy bytecode. On the implementation contract itself (not a clone), `fetchCloneArgs` returns the implementation's own deployed bytecode starting from a fixed offset. The first 32 bytes of Delegate's deployed bytecode (`0x6080604052...`) have non-zero upper bytes, making it an invalid ABI-encoded address, so `abi.decode` reverts.

```solidity
function owner() public view returns (address) {
    return abi.decode(Clones.fetchCloneArgs(address(this)), (address));
    // On a clone: fetchCloneArgs returns 20-byte owner — decodes correctly.
    // On the implementation: fetchCloneArgs returns bytecode bytes — abi.decode reverts.
}
```

Because `send()` and `call()` both call `owner()` as their access check, all owner-protected functions are permanently inaccessible on the implementation. The implementation's `receive()` function still accepts ETH without restriction. Any ETH sent to the implementation address is permanently locked with no recovery path.

**Impact**:
ETH accidentally sent to the implementation address cannot be recovered. All calls to `send()`, `call()`, and `revertCall()` revert before executing, so there is no escape path. The implementation address is visible on-chain and may attract accidental transfers, particularly from tools or scripts that confuse implementation addresses with clone addresses.

**PoC Result**:
```
[PASS] test_H10_ownerRevertsOnImplementation()
  Implementation code.length: 2706
  owner() reverts on implementation: confirmed
[PASS] test_H10_ethSentToImplementationIsLocked()
  ETH in implementation: 1000000000000000000
  send() recovery succeeded: false
  ETH permanently locked: 1000000000000000000
  Recipient received: 0
[PASS] test_H10_noCallRecoveryEither()
  call() also reverts -- no escape path
```

**Recommendation**:
Guard `receive()` — and optionally all functions — against direct calls to the implementation using an immutable flag set in the constructor:

```diff
  contract Delegate {
+     bool private immutable isImplementation;
+
+     constructor() { isImplementation = true; }
+
+     modifier notImplementation() {
+         require(!isImplementation, "Delegate: call via clone only");
+         _;
+     }

-     receive() external payable {}
+     receive() external payable notImplementation {}
  }
```

Alternatively, add a NatSpec warning to the implementation documentation so deployers are aware of this pitfall and can exclude the implementation address from any ETH-receiving integrations.

---

### [L-07] No Event Emissions for Any Operation [VERIFIED]

**Severity**: Low
**Location**: `Delegate.sol` and `DelegateLib.sol` (entire codebase)
**Confidence**: HIGH (1 test passed, Static Analysis: confirmed via code review, PoC: PASS)

**Description**:
Neither `Delegate` nor `DelegateLib` defines or emits any events. All operations — clone deployment, ETH transfers via `send()`, arbitrary external calls via `call()`, token transfers, token approvals, and on-chain simulations via `revertCall()` — are completely invisible to off-chain infrastructure. No `event` declarations exist anywhere in the codebase.

```solidity
// Delegate.sol — no event declarations
contract Delegate {
  receive() external payable {}          // no event
  function owner() public view returns (address) { ... }
  function send(address payable to, uint256 value) external { ... }    // no event
  function call(address target, bytes calldata data) external returns (bytes memory) { ... }  // no event
  function call(address target, bytes calldata data, uint256 value) external returns (bytes memory) { ... }  // no event
  function revertCall(address target, bytes calldata data) external returns (bytes memory) { ... }  // no event
}
```

**Impact**:
All Delegate activity is invisible to blockchain indexers, subgraphs, monitoring dashboards, and event-driven off-chain systems. Protocol integrators that rely on events to track clone deployments, ETH movements, token operations, or call executions will receive no signals. This creates gaps in:
- Accounting systems that credit/debit based on emitted transfer events
- Security monitoring tools that alert on privileged operations
- Front-end applications that display transaction history

**PoC Result**:
```
[PASS] test_H11_noEventsEmittedByDelegate()
  Total logs: 0
  Logs from Delegate: 0
  CONFIRMED: Delegate emits zero events. All operations invisible to indexers.
```

**Recommendation**:
Add events for the primary observable state changes. At minimum, emit events in `Delegate` for ETH sends and external calls:

```solidity
event Called(address indexed target, bytes data, uint256 value, bytes result);
event Sent(address indexed to, uint256 value);
```

For `DelegateLib`, emit events on clone deployment (or document clearly that the calling contract is responsible for emitting deployment events). If zero-event design is intentional for gas minimization, document this trade-off explicitly in NatSpec so integrators know to rely on raw transaction traces rather than event logs.

---

### [L-08] All-or-Nothing Owner Authorization — No Access Control Granularity [VERIFIED]

**Severity**: Low
**Location**: `Delegate.sol:L9, L15-L38`
**Confidence**: HIGH (3 subtests passed, Static Analysis: confirmed via code review, PoC: PASS)

**Description**:
All four protected functions in `Delegate` (`send`, `call` with data, `call` with value, `revertCall`) use an identical binary guard: `require(msg.sender == owner())`. There is no sub-role system, no function-selector allowlist, no value cap on ETH transfers, no target address allowlist, and no per-function permission differentiation.

```solidity
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

function revertCall(address target, bytes calldata data) external returns (bytes memory) {
    require(msg.sender == owner());
    ...
}
```

The owner has unrestricted simultaneous access to all capabilities. A non-owner is blocked from all capabilities simultaneously. No intermediate permission state is possible within the Delegate itself.

**Impact**:
The owner contract holds full unmediated control over every Delegate capability. If the owner contract ever needs to delegate a subset of its capabilities to a sub-system or operator (e.g., allowing a keeper to execute specific token operations but not arbitrary ETH transfers), the Delegate provides no enforcement surface for such distinctions. All such restrictions must be re-implemented in the owner contract for every owner that deploys a Delegate, increasing the risk of incomplete access control in the owner layer.

**PoC Result**:
```
[PASS] test_H12_ownerCanDoEverything()
  CONFIRMED: Owner has unrestricted access to all Delegate functions
[PASS] test_H12_nonOwnerCanDoNothing()
  CONFIRMED: Binary gate - non-owner blocked from ALL functions identically
[PASS] test_H12_singleGateAllFunctions()
  No sub-roles, selector restrictions, value caps, or target allowlists found
```

**Recommendation**:
If least-privilege access control is desired, consider adding an optional selector-level allowlist or a tiered role (e.g., a `caller` role that may invoke `call()` but not `send()`). If the current binary design is intentional, document it explicitly — including the expectation that owner contracts must implement any finer-grained access control themselves — so integrators are not surprised.

---

### [L-09] Pre-Deployment Fund Reception Window — Unrecoverable if CREATE2 Salt Burned [VERIFIED]

**Severity**: Low
**Location**: `DelegateLib.sol:L13-L15, L21-L29`
**Confidence**: HIGH (2 subtests passed, Static Analysis: N/A, PoC: PASS)

**Description**:
`DelegateLib.predict()` computes the deterministic CREATE2 address where a clone will be deployed before deployment occurs. A common pattern is to pre-fund this predicted address with ETH or tokens before calling `deploy()`. This creates a window during which the pre-funded address holds assets but has no owner-protected functions.

The risk arises when the pre-funding party is a different entity from the deployer. Once `deploy()` is called with the matching `(implementation, salt)` tuple:
1. The clone is created at the predicted address, with the **deployer** embedded as the immutable owner.
2. The salt is permanently consumed — redeployment with the same tuple is impossible.
3. All ETH in the clone is controlled exclusively by the clone's owner (the deployer). The pre-funder has no `send()` or `call()` access and cannot recover their funds.

```solidity
// DelegateLib.sol
function predict(address implementation, bytes32 salt) internal view returns (address payable addr) {
    addr = payable(
      Clones.predictDeterministicAddressWithImmutableArgs(
        implementation, abi.encode(address(this)), salt, address(this)
      )
    );
}
// No documentation that the pre-funder must be the same as the deployer
```

**Impact**:
If a third party pre-funds a predicted address expecting to own the resulting clone (or expecting the funds to be recoverable), and the clone is subsequently deployed by a different contract (or the deployer deploys with a different owner than expected), the pre-funder's ETH is permanently locked in the clone, accessible only to the embedded owner. The ETH is not destroyed but is effectively lost to the pre-funder.

**PoC Result**:
```
[PASS] test_H13_saltBurnedBlocksRedeployment()
  ETH pre-funded: 2000000000000000000
  Deployed to predicted address. Salt now permanently consumed.
  Second deploy with same salt: REVERTED
  Clone balance (locked from pre-funder's perspective): 2000000000000000000
  Clone owner: 0x5615dEB... (harness)
  Pre-funder: 0x7FA938... (test contract, different from owner)
  Pre-funder send() recovery: REVERTED
  HARM: 2 ETH pre-funded. Salt consumed. Pre-funder != owner. ETH inaccessible to pre-funder.
[PASS] test_H13_happyPathStillWorks()
  Happy path: deploy to predicted address works. Clone balance: 1000000000000000000
```

**Recommendation**:
Add NatSpec documentation to `predict()` warning that any pre-funding party must be the same entity that will call `deploy()`, or must coordinate with the deployer to ensure they control the resulting clone:

```diff
+ /// @notice Returns the deterministic address where a clone will be deployed.
+ /// @dev WARNING: Pre-funding the predicted address before deployment is risky.
+ /// The resulting clone's owner is set to address(this) of the contract calling deploy().
+ /// If a different contract calls deploy(), the pre-funder will not be the owner and
+ /// cannot recover pre-funded assets. The salt is permanently consumed after deployment.
  function predict(address implementation, bytes32 salt) internal view returns (address payable addr) {
```

---

### [L-10] Permanent Owner Lock-in with No Recovery Path [VERIFIED]

**Severity**: Low
**Location**: `Delegate.sol` (entire contract)
**Confidence**: HIGH (5 subtests passed, Static Analysis: N/A, PoC: PASS)

**Description**:
The `Delegate` contract encodes its owner address permanently into the clone bytecode at deployment time via `abi.encode(address(this))` in `DelegateLib.deploy()`. The `owner()` function decodes this immutable value from the clone's own bytecode on every call. There is no `transferOwnership()` function, no guardian mechanism, no rescue function, and no administrative override — the owner binding is as immutable as the EIP-1167 proxy bytecode itself.

```solidity
// DelegateLib.sol
function deploy(address implementation, bytes32 salt) internal returns (address payable) {
    return payable(Clones.cloneDeterministicWithImmutableArgs(
        implementation,
        abi.encode(address(this)),   // owner encoded permanently into clone bytecode
        salt
    ));
}

// Delegate.sol
function owner() public view returns (address) {
    return abi.decode(Clones.fetchCloneArgs(address(this)), (address));
    // Returns the bytecode-embedded address; cannot be changed after deployment
}
```

If the owner contract becomes inoperable — due to a bug, a failed upgrade, a governance breakdown, or any other cause — all assets (ETH and tokens) held by every delegate clone deployed by that owner become permanently inaccessible. No other address can authorize recovery operations.

**Impact**:
Any ETH or tokens held by a delegate clone at the time the owner becomes inoperable are permanently locked. There is no third-party recovery path, no timelock override, and no emergency exit. All funds remain in the clone, inaccessible to anyone. The severity is contingent on the likelihood of the owner contract becoming inoperable, which is low for well-audited owner contracts but non-zero for any sufficiently complex system.

**PoC Result**:
```
[PASS] test_H1_fundsLockedWhenOwnerBricked() (gas: 147145)
[PASS] test_H1_noTransferOwnership() (gas: 8644)
[PASS] test_H1_nonOwnerCannotWithdrawETH() (gas: 15442)
[PASS] test_H1_nonOwnerCannotWithdrawTokens() (gas: 20638)
[PASS] test_H1_ownerIsImmutable() (gas: 11635)
Suite result: ok. 5 passed; 0 failed; 0 skipped
```
Key evidence: Before bricking, owner withdraws 1 ETH and 100e18 tokens successfully. After bricking, remaining 4 ETH and 900e18 tokens are permanently inaccessible — no recovery path confirmed.

**Recommendation**:
No code change is required within the Delegate itself. This is a deliberate design trade-off: immutable ownership eliminates an entire class of ownership-transfer vulnerabilities and is appropriate for the minimal executor model.

Owner contract implementers should consider adding recovery mechanisms at the owner level — for example, a migration function that deploys a new delegate and transfers assets before the owner is decommissioned. If in-clone recovery is desired, the simplest addition is a documentation note in NatSpec:

```diff
  /// @notice Minimal executor contract deployed as an EIP-1167 clone.
+ /// @dev The owner is permanently set at deployment time via immutable args.
+ /// There is no ownership transfer mechanism. If the owner contract becomes
+ /// inoperable, assets held by this delegate are permanently locked.
+ /// Owner contracts should implement their own recovery/migration logic.
  contract Delegate {
```

---

## Informational Findings

### [I-01] revertCall Cannot Distinguish Success from Target Revert [VERIFIED]

**Severity**: Informational
**Location**: `Delegate.sol:32-38`
**Confidence**: HIGH (code trace confirmed, design-level ambiguity)

**Description**:
`revertCall` is documented as a Uniswap Quoter-style simulation helper — the caller wraps it in a `try/catch` to capture the target's return value without committing state. The function calls the target via `Address.functionCall`, then unconditionally reverts with the result data using inline assembly. The limitation is that both the success path and the failure path produce a revert caught by the caller's `try/catch`, with no way to distinguish between the two.

When the target succeeds, `Address.functionCall` returns the ABI-encoded return data, which the assembly then forwards as the revert payload. When the target reverts, OpenZeppelin's internal `bubbleRevert` re-reverts immediately with the target's own error data — the assembly is never reached. In both cases the outer caller receives a revert; without an out-of-band convention such as a sentinel prefix or a wrapper error type, the caller cannot determine whether the data it decoded was a valid return value or the target's own revert reason.

The NatSpec comment (`/// @dev Used for on-chain previewing via the Uniswap Quoter revert-call pattern`) describes only the success path. The failure path and the resulting ambiguity are undocumented. Integrators who rely on `revertCall` for simulation must implement their own success/failure disambiguation in the `catch` branch, which is not signalled anywhere in the contract's interface.

**Impact**:
Incorrect interpretation of `revertCall` output can lead an integrator to treat a target revert as a successful simulation result or vice versa. The consequence is off-chain misprediction, not on-chain state corruption, since `revertCall` always reverts.

**Recommendation**:
Document the ambiguity in NatSpec. If disambiguation is required, consider wrapping the successful return data in a custom error before reverting (e.g., `revert SimulationResult(result)`), so callers can distinguish it from a raw target revert in the `catch` branch.

---

### [I-02] revertCall Cannot Simulate Payable Target Functions [VERIFIED]

**Severity**: Informational
**Location**: `Delegate.sol:32-38`
**Confidence**: HIGH (code trace confirmed)

**Description**:
`revertCall` uses `Address.functionCall(target, data)`, which internally calls `Address.functionCallWithValue(target, data, 0)` with a hardcoded value of zero. Any payable function on the target that inspects `msg.value` or requires `msg.value > 0` will behave differently during simulation than it would in a real execution. The simulation result will therefore be inaccurate for any payable target function that depends on ETH input.

The contract already provides `Delegate.call(address, bytes, uint256)` at line 25, which correctly forwards a value amount via `Address.functionCallWithValue`. However, no equivalent `revertCall(address, bytes, uint256)` overload exists, leaving payable simulation unsupported. This is especially notable because the Uniswap Quoter pattern — explicitly cited in the NatSpec — is commonly used to preview swap outputs that may involve ETH.

**Impact**:
Simulations of payable functions using `revertCall` will silently execute with `msg.value = 0`, producing incorrect preview results. There is no on-chain harm since `revertCall` always reverts, but callers may act on inaccurate off-chain previews.

**Recommendation**:
Add a value-forwarding overload: `revertCall(address target, bytes calldata data, uint256 value)` that uses `Address.functionCallWithValue`. Document the current overload as suitable only for non-payable targets.

---

### [I-03] Missing require() Error Messages [VERIFIED]

**Severity**: Informational
**Location**: `Delegate.sol:16, 21, 26, 33`; `DelegateLib.sol:34, 39, 50`
**Confidence**: HIGH (all seven instances confirmed by code trace)

**Description**:
The contract contains seven `require` statements across `Delegate.sol` and `DelegateLib.sol`, none of which include an error string or custom error. In `Delegate.sol`, all four externally callable functions (`send`, both `call` overloads, and `revertCall`) guard against unauthorized callers with `require(msg.sender == owner())` and no message. In `DelegateLib.sol`, three `require` statements validate token transfer return values at lines 34, 39, and 50, also without strings.

When any of these conditions fails, the EVM returns an empty revert reason, providing no diagnostic information to the calling context. This makes it difficult to distinguish, for example, between an access control failure and a token transfer failure during debugging or monitoring. Solidity 0.8+ supports custom errors (e.g., `error Unauthorized()`) that are more gas-efficient than strings and provide equally useful type information.

**Impact**:
No security impact. Degrades debuggability and operator experience during failed transactions and revert analysis.

**Recommendation**:
Replace bare `require(msg.sender == owner())` with a custom error: `if (msg.sender != owner()) revert Unauthorized();`. Similarly, replace token validation `require` statements with descriptive custom errors such as `TransferFailed()`. Custom errors are cheaper than string messages and produce better structured revert data.

---

### [I-04] Missing Zero-Address Check on send() Target [VERIFIED]

**Severity**: Informational
**Location**: `Delegate.sol:15-18`
**Confidence**: HIGH (code trace confirmed, EVM behavior verified)

**Description**:
The `send` function forwards ETH to a caller-specified `address payable to` with no validation that `to != address(0)`. The call chain is `send(to, value)` → `Address.sendValue(to, value)` → `LowLevelCall.callNoReturn(address(0), amount, "")`. At the EVM level, a low-level call to address(0) succeeds and transfers the specified ETH amount to the zero address, where it is permanently inaccessible. The function returns normally with no indication that the funds were destroyed.

`Address.sendValue` checks only that the contract's balance is sufficient before initiating the transfer. It performs no validation on the recipient address. The owner is the only caller permitted to invoke `send`, so this scenario requires the owner to supply `address(0)` either accidentally (e.g., an uninitialized variable) or through an upstream encoding error.

**Impact**:
ETH sent to address(0) is permanently burned with no error. The impact is bounded by the owner acting on a misconfigured call, but recovery is impossible once executed.

**Recommendation**:
Add a zero-address guard: `require(to != address(0), "Delegate: zero address")` or `if (to == address(0)) revert ZeroAddress();` before the `Address.sendValue` call.

---

### [I-05] safeTransferFrom Allowance Precondition Undocumented [VERIFIED]

**Severity**: Informational
**Location**: `DelegateLib.sol:37-40`
**Confidence**: HIGH (code trace confirmed)

**Description**:
`DelegateLib.safeTransferFrom` issues an ERC-20 `transferFrom(from, to, amount)` call through the delegate. Because the call is executed from the delegate's address context, the token contract checks `allowance[from][delegate]` — the token holder must have previously approved the specific delegate instance for at least `amount`. No approval setup exists in `DelegateLib` itself, and neither the function signature nor any NatSpec comment documents this precondition.

If a caller invokes `safeTransferFrom` without first establishing an allowance (via `safeApprove` or a direct `approve` call from the token holder to the delegate), the ERC-20 token will revert, which propagates as a revert in `safeTransferFrom` with no explanation. The error is particularly confusing because the failure happens inside the delegate's external call, and the propagated revert reason (if any) comes from the token contract rather than from `DelegateLib`.

**Impact**:
Operational confusion for integrators who call `safeTransferFrom` without understanding the allowance dependency. No funds are at risk — the call simply reverts. Integrators must discover the precondition by reading ERC-20 internals rather than from the library's interface.

**Recommendation**:
Add NatSpec to `safeTransferFrom` documenting the precondition: `/// @dev Requires `from` to have approved `delegate` for at least `amount` on `token` before calling.` Consider also adding an inline comment referencing `safeApprove` as the companion function.

---

### [I-06] Stale Allowances After Token Drain [VERIFIED]

**Severity**: Informational
**Location**: `DelegateLib.sol:32-35`
**Confidence**: HIGH (code trace confirmed)

**Description**:
`DelegateLib.safeTransfer` moves tokens out of the delegate using `IERC20.transfer`, which draws from the delegate's own token balance. It does not clear or reduce any existing ERC-20 allowances that third-party spenders may hold over the delegate's token balance. After a complete drain of a token from the delegate, previously granted allowances remain recorded in the token contract's storage with their original approved amounts.

These orphaned allowances are not immediately exploitable — a spender cannot transfer tokens that are no longer in the delegate. However, if tokens of the same type are later re-deposited into the same delegate address (e.g., because the delegate is reused across operations), the stale allowance resumes its authorized value without any explicit re-approval by the owner. This is a subtle allowance hygiene issue that can surprise integrators who expect allowances to reflect the current token balance.

**Impact**:
No immediate exploit under current usage. The risk materializes only if: (1) the owner grants an allowance, (2) all tokens are transferred out, and (3) tokens of the same type are later re-deposited. In that scenario, the previously approved spender can immediately spend up to the original allowance without any new authorization step.

**Recommendation**:
When performing a complete transfer that drains the delegate's balance of a token, explicitly revoke outstanding allowances with `safeApprove(delegate, token, knownSpender, 0)` as part of the drain sequence. Document this hygiene requirement in the library's NatSpec.

---

### [I-07] MEV Exposure on Delegate External Calls [VERIFIED]

**Severity**: Informational
**Location**: `Delegate.sol:20-28`
**Confidence**: HIGH (code trace confirmed)

**Description**:
`Delegate.call` and `Delegate.call(address, bytes, uint256)` execute arbitrary external calls with no on-chain slippage protection, deadline enforcement, or MEV mitigation. The `data` parameter is opaque calldata that the owner encodes off-chain; any slippage parameters (e.g., `amountOutMin`) or deadline parameters must be embedded by the owner before submission. The contract provides no enforcement or validation of such parameters.

Transactions submitted through the public mempool are visible to MEV searchers before confirmation. A swap call with permissive or absent slippage parameters is susceptible to sandwich attacks: a searcher frontruns the transaction to move the price, the swap executes at an unfavorable rate, and the searcher backruns to profit from the spread. The Delegate's minimal executor design intentionally delegates this responsibility to the owner, but the contract provides no documentation of this requirement.

**Impact**:
No on-chain state corruption. An owner that submits unprotected swap calls through the public mempool may receive worse execution than expected. The impact is bounded by the owner's own operations.

**Recommendation**:
Document in NatSpec that callers are responsible for encoding slippage and deadline parameters within `data`. For MEV-sensitive operations, recommend using private transaction relays (e.g., Flashbots Protect) or ensuring that `data` encodes adequate slippage limits.

---

### [I-08] Revert Data Propagation Confusion [VERIFIED]

**Severity**: Informational
**Location**: `Delegate.sol:20-28`; `DelegateLib.sol:42-52`
**Confidence**: HIGH (code trace confirmed)

**Description**:
`DelegateLib.safeApprove` contains a USDT-style fallback intended to handle tokens that revert on non-zero allowance changes. However, there are two distinct error propagation paths that produce different caller experiences depending on the failure mode of the token. When a token returns `false` (non-revert failure), `success` evaluates to `false` and the fallback branch (reset to 0, then retry) is entered. When a token reverts outright — as actual mainnet USDT does — `Address.functionCall` inside `delegate.call()` invokes `bubbleRevert`, which immediately re-reverts with the token's own error data before the `success` evaluation is ever reached.

The practical consequence is that the USDT fallback branch is dead code for real USDT on Ethereum mainnet (which reverts rather than returning false), and the two failure modes produce structurally different reverts visible to the caller: one is the library's own `require` failure, the other is the token's raw revert data bubbled through OZ. This inconsistency makes error handling and monitoring more complex for integrators.

**Impact**:
No security impact in isolation. The confusion contributes to the root cause of the dead-code issue in `safeApprove` (see L-01). Integrators cannot write a uniform `catch` handler for `safeApprove` failures without understanding this split.

**Recommendation**:
Document the two failure modes clearly in `safeApprove`'s NatSpec. If uniform error propagation is desired, wrap the token's revert data in a custom error before re-reverting, so callers always receive a consistent error type regardless of which token failure mode triggered.

---

### [I-09] owner() Public Visibility [VERIFIED]

**Severity**: Informational
**Location**: `Delegate.sol:11-13`
**Confidence**: HIGH (code trace confirmed)

**Description**:
`owner()` is declared `public`, which generates both an internal Solidity-accessible function and an external ABI-visible selector. Since `owner()` is a pure read function that decodes the immutable args embedded in the clone's bytecode, `external` visibility would be more appropriate — it restricts the generated function to external calls only, avoids an unnecessary internal entry point, and saves a small amount of bytecode and gas on external invocations.

The practical security impact is negligible. The owner address is embedded as immutable args appended to the EIP-1167 proxy bytecode and is recoverable by anyone with the clone's address via `extcodecopy` regardless of whether `owner()` is `public` or `external`. The visibility modifier does not control whether the information is accessible — it only controls how Solidity generates the internal call path.

**Impact**:
No security impact. Minor bytecode and gas inefficiency (~3 gas per external call) from generating an internal entry point that is not needed for this function.

**Recommendation**:
Change `owner()` to `external view` to accurately reflect its intended use (external callers only) and to follow the principle of minimal ABI surface. This is a cosmetic improvement with no behavioral change.

---

### [I-10] Owner Self-Call Self-Protecting [VERIFIED]

**Severity**: Informational
**Location**: `Delegate.sol:20-28`
**Confidence**: HIGH (code trace confirmed)

**Description**:
The owner is permitted to call `Delegate.call(address(delegate), ...)`, directing the delegate to issue an external call back to itself. This creates a recursive call pattern: the outer `call` passes the owner check (`msg.sender == owner()`), then `Address.functionCall` issues an external call to the delegate, which invokes one of the delegate's own functions. At that inner call, `msg.sender` is the delegate itself — not the original owner — so `require(msg.sender == owner())` reverts.

The self-call path is therefore self-protecting: no function on the delegate can be re-entered or bypassed by routing a call through `Delegate.call`. The access control check on every public function ensures that the delegate cannot be made to act as its own caller. This is an architectural property worth documenting, as developers unfamiliar with the pattern might attempt self-calls expecting them to work, or conversely, might not realize the protection is already in place.

**Impact**:
No exploit path exists. The observation is provided for documentation clarity — integrators should understand why self-calls silently fail without constructing a dedicated guard.

**Recommendation**:
Consider adding a NatSpec note to `call()` indicating that `target == address(this)` will always revert due to the access control structure, so integrators are not surprised by this behavior.

---

### [I-11] Boolean Comparison Style [VERIFIED]

**Severity**: Informational
**Location**: `DelegateLib.sol:47`
**Confidence**: HIGH (confirmed by static analysis and code trace)

**Description**:
Line 47 of `DelegateLib.sol` contains `if (success == false)`, comparing a boolean variable to the literal `false` using the equality operator. The idiomatic Solidity (and general programming) style is `if (!success)`. The two forms are semantically and functionally equivalent — the EVM compiles them to the same opcodes — but the `== false` form is flagged by Slither and solhint as a style violation and reduces readability.

**Impact**:
No functional or security impact.

**Recommendation**:
Replace `if (success == false)` with `if (!success)` for consistency with idiomatic Solidity style.

---

### [I-12] Multiple Pragma Versions [VERIFIED]

**Severity**: Informational
**Location**: `src/Delegate.sol:1`; `src/DelegateLib.sol:1`; OpenZeppelin dependency files
**Confidence**: HIGH (confirmed by static analysis and file inspection)

**Description**:
The in-scope source files (`Delegate.sol` and `DelegateLib.sol`) declare `pragma solidity ^0.8.28`, while the OpenZeppelin dependency files (`Address.sol`, `Clones.sol`, and others in `lib/openzeppelin-contracts/`) declare `pragma solidity ^0.8.20`. In practice this compiles without issue — the effective compiler is pinned to `^0.8.28` by the project configuration, and `^0.8.20` is satisfied by any compiler `>= 0.8.20`. The version ranges are compatible.

The inconsistency is cosmetic but can make it harder to audit which compiler version-specific behaviors are in effect, or to identify which OZ version's semantic guarantees the in-scope code is relying on. Auditors and reviewers must mentally resolve the version matrix rather than reading a uniform pragma.

**Impact**:
No security implication. Standard practice when using versioned dependency libraries, but worth noting for documentation hygiene.

**Recommendation**:
Where feasible, align pragma ranges between in-scope source files and dependencies, or pin a specific compiler version in `foundry.toml` (e.g., `solc = "0.8.34"`) to make the effective compiler explicit and unambiguous.

---

### [I-13] Unbounded Return Data Gas Griefing — Design Note [VERIFIED]

**Severity**: Informational
**Location**: `Delegate.sol:20-28`; `Delegate.sol:32-38`
**Confidence**: HIGH (PoC executed, gas ratio confirmed 33x at 128 KB)

**Description**:
`Delegate.call` and `revertCall` use OpenZeppelin's `Address.functionCall`, which copies the entirety of the target's return data into a memory `bytes` array. EVM memory expansion costs are super-linear: a target returning 128 KB costs approximately 33 times more gas than one returning 32 bytes (856,147 gas vs 25,900 gas, confirmed by test execution). A malicious or malfunctioning target could return an arbitrarily large payload, consuming all gas forwarded to the call and causing the transaction to run out of gas.

This is classified Informational rather than Low because the attack requires the fully-trusted owner to direct the delegate at a malicious target. The owner controls which targets are called and is responsible for selecting trustworthy call targets per the protocol's stated trust model. The concern is documented here as a design consideration for protocol integrators who may evolve the delegate to accept target addresses from less-trusted sources in the future.

**Impact**:
Under the current trust model, the only party who can trigger this behavior is the owner. The risk becomes material if the protocol is extended to allow third parties to specify call targets without restriction.

**Recommendation**:
Document in NatSpec that callers should not forward calls to untrusted targets without a return-data size cap. If untrusted targets become part of the design, consider capping return data with a `call{gas: gasLimit}` assembly pattern and discarding data beyond a defined maximum size.

---

### [I-14] Missing Reentrancy Guard — Informational Design Note [VERIFIED]

**Severity**: Informational
**Location**: `Delegate.sol:20-28`
**Confidence**: HIGH (PoC executed: callback window confirmed real; harm at Delegate level not demonstrated)

**Description**:
During execution of `Delegate.call` followed by a token transfer, an ERC-777 or ERC-1363 token's callback mechanism can return execution control to the caller (the owner contract) before the delegate's call completes. Test execution confirmed that this callback window is mechanically real: a test ERC-777 token successfully triggered a re-entry into the owner contract during `safeTransfer` execution, setting `callbackTriggered = true`.

The delegate itself is immune to reentrancy-induced state corruption because it holds no mutable storage — its only state is the immutable owner address embedded in clone bytecode. However, the callback window is a genuine execution interleave that owner contract implementers must account for. If an owner contract violates Checks-Effects-Interactions (CEI) ordering and uses the delegate to interact with callback-capable tokens, its own state can be corrupted. Solidity 0.8's arithmetic overflow/underflow protection blocks the most common exploitation pattern (balance underflow double-withdraw), but owners using `unchecked` blocks or non-arithmetic state machines remain at risk.

Adding a reentrancy guard to the delegate would be architectural overreach — the delegate is a stateless minimal executor, and reentrancy protection is the responsibility of the owner contract per the stated trust model. This finding is reported as a design note for owner contract implementers.

**PoC Result**:
Compiled: YES (2 attempts). Three tests passed: callback window existence confirmed (`callbackTriggered = true`); state corruption with unsafe owner blocked by Solidity 0.8 underflow protection; delegate immunity to reentrancy confirmed (owner address unchanged). Evidence tag: [POC-PASS] for mechanism; harm assertion at Delegate level: NOT DEMONSTRATED.

**Impact**:
No impact at the delegate level. Owner contracts that interact with ERC-777 or ERC-1363 tokens via the delegate must follow CEI ordering or use their own reentrancy guards to protect their internal state.

**Recommendation**:
Document in NatSpec on `call()` that the function provides no reentrancy protection and that owner contracts using callback-capable tokens (ERC-777, ERC-1363) are responsible for implementing their own reentrancy guards. A brief warning such as `/// @dev No reentrancy guard. Owner contracts interacting with callback tokens must enforce CEI ordering.` is sufficient.

---

## Priority Remediation Order

1. **L-01**: safeApprove USDT fallback is unreachable — rewrite with try/catch — Before launch
2. **L-04**: Short return data panic — add length guard before abi.decode — Before launch
3. **L-02**: predict/deploy caller mismatch — add deployer parameter to predict() — Before launch
4. **L-05**: Zero-code implementation check — add require(implementation.code.length > 0) — Before launch
5. **L-06**: Implementation ETH lock — guard receive() against implementation calls — Before launch
6. **L-03**: Fee-on-transfer gap — add balance reconciliation or document exclusion — Before launch
7. **L-07**: Missing events — add events for send/call operations — Before launch
8. **L-09**: Pre-deployment fund window — document risk in NatSpec — Before launch
9. **L-10**: Owner lock-in — document in NatSpec — Before launch
10. **L-08**: Binary authorization — document or add optional role system — Post-launch

---

## Appendix A: Internal Audit Traceability

> This appendix is for internal reference only. It maps internal pipeline IDs to report IDs and lists excluded findings that were refuted during verification.

### Master Finding Index

| Report ID | Internal Hypothesis | Verification | Agent Sources |
|-----------|-------------------|--------------|---------------|
| L-01 | H-3 | CONFIRMED [POC-PASS] | CS-1, ED-1, RS1-1, DST-1, DST-4, DE-4 |
| L-02 | H-4 | CONFIRMED [POC-PASS] | DEC-4, BLIND-5, DST-2-stress |
| L-03 | H-5 | CONFIRMED [POC-PASS] | ED-3, DTF-1 |
| L-04 | H-7 | CONFIRMED [POC-PASS] | RS2-1, DTF-3 |
| L-05 | H-8 | CONFIRMED [POC-PASS] | PC2-1, DEC-2 |
| L-06 | H-10 | CONFIRMED [POC-PASS] | CS-2, ED-6, DEC-1 |
| L-07 | H-11 | CONFIRMED [POC-PASS] | CS-3, GS-5 |
| L-08 | H-12 | CONFIRMED [POC-PASS] | DST-3-stress |
| L-09 | H-13 | CONFIRMED [POC-PASS] | DST-4-stress |
| L-10 | H-1 | CONFIRMED [POC-PASS] | DST-1-stress |
| I-01 | H-14 | CONFIRMED [CODE-TRACE] | RS1-2 |
| I-02 | H-15 | CONFIRMED [CODE-TRACE] | PC1-1 |
| I-03 | H-16 | CONFIRMED [CODE-TRACE] | BLIND-1 |
| I-04 | H-17 | CONFIRMED [CODE-TRACE] | BLIND-4 |
| I-05 | H-18 | CONFIRMED [CODE-TRACE] | BLIND-3 |
| I-06 | H-19 | CONFIRMED [CODE-TRACE] | BLIND-6 |
| I-07 | H-21 | CONFIRMED [CODE-TRACE] | DE-3 |
| I-08 | H-22 | CONFIRMED [CODE-TRACE] | ED-8 |
| I-09 | H-23 | CONFIRMED [CODE-TRACE] | PC1-2 |
| I-10 | H-25 | CONFIRMED [CODE-TRACE] | ED-5 |
| I-11 | H-26 | CONFIRMED [CODE-TRACE] | SLITHER-4 |
| I-12 | H-27 | CONFIRMED [CODE-TRACE] | SLITHER-5 |
| I-13 | H-9 (trust-downgraded from Low) | CONFIRMED [POC-PASS], trust −1 tier | GS-3, DEC-3, DE-5 |
| I-14 | H-2 | CONFIRMED [POC-PASS] | ED-4, GS-1, DST-3, DE-1, DA-1 |

### Severity Adjustments Applied

**Trust Assumption Downgrade**: H-9 (Unbounded Return Data Gas Griefing) downgraded from Low → Informational. Attack requires the fully-trusted owner to self-grief by calling an untrusted target. Appears as I-13 in this report.

**Consolidation**: H-24 (deploy() silently deploys zero-code clone) subsumed into H-8 (same root cause, H-8 carries concrete impact proof). Both appear as L-05.

### Excluded Findings

| Internal ID | Severity | Title | Exclusion Reason |
|-------------|----------|-------|------------------|
| CS-4 | Informational | revertCall Assembly Correctness Verification | REFUTED — assembly verified correct (not a vulnerability) |
| CS-5 | Informational | Access Control Completeness Verification | REFUTED — access control verified complete (not a vulnerability) |
| CS-6 | Informational | CREATE2 Deterministic Address and Salt Collision Safety | REFUTED — CREATE2 safety verified (not a vulnerability) |
| ED-7 | N/A | safeApprove Does Not Mitigate ERC-20 Approve Race Condition | REFUTED — race condition not applicable (atomic tx) |
| GS-2 | Informational | ETH Sent to Delegate Can Be Trapped if Owner Cannot Receive ETH | REFUTED — external precondition (bricked owner, out of scope) |
| GS-6 | Informational | No Reentrancy Risk to Delegate Internal State | REFUTED — delegate is architecturally stateless |
| GS-7 | Informational | Implementation Contract Can Be Called Directly | REFUTED — standard EIP-1167 behavior (not a vulnerability) |
| GS-8 | Informational | Front-Running Deploy with Same Salt Causes Revert | REFUTED — CREATE2 deployer-bound prevents front-run |
| GS-9 | Informational | No Integer Overflow/Underflow Concerns | REFUTED — no arithmetic in codebase |
| GS-10 | Informational | DoS via Implementation Destruction Not Possible Post-Dencun | REFUTED — EIP-6780 prevents selfdestruct |
| GS-11 | Informational | Value Extraction by Non-Owner is Not Possible | REFUTED — access control verified complete |
| DTF-5 | Informational | No Internal Accounting to Corrupt | REFUTED — delegate has no internal state |
| DST-5 (state) | Informational | Access Control Invariant Verified | REFUTED — access control verified |
| DA-2 | Informational | CREATE2 Collision Infeasible | REFUTED — CREATE2 collision mathematically infeasible |
| DST-6-stress | Informational | Front-Running Verified Safe | REFUTED — CREATE2 prevents front-run |
| DST-7-stress | Informational | Gas Limits Verified Not an Issue | REFUTED — gas limits not a concern |
| BLIND-2 | Informational | No Unchecked Blocks | REFUTED — no unchecked blocks found |
| BLIND-9 | Informational | No Missing Access Controls | REFUTED — access control verified complete |
| RS2-2 | Informational | Crafted Bytecode Bypass | FALSE_POSITIVE — agent refuted this finding |