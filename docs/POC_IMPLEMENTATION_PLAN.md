# Proof of Concept Implementation Plan: Input-Guessing Attack

## Overview

This document outlines the implementation plan for a proof-of-concept (PoC) demonstrating the input-guessing attack vulnerability in the Song et al. NDSS'24 shuffle protocol implementation.

## Goals

1. **Primary Goal**: Demonstrate that a malicious party can cause the MAC check to behave differently based on the honest party's input values
2. **Secondary Goal**: Show information can be extracted about the honest party's inputs through abort/success patterns
3. **Stretch Goal**: Implement a full attack that recovers specific input bits

## Design Principle: Clean Separation

**The honest party runs completely unmodified original code.** This makes the PoC more convincing because:

- It demonstrates the attack works against the real implementation
- No modifications to the victim's code are needed
- The attack is realistic - a malicious party only controls their own binary

**Architecture:**

- **Honest Party**: Runs unmodified `NDSS_online_example` binary
- **Malicious Party**: Runs new `attack_poc` binary with attack logic

Both binaries communicate over the network using the existing `--alone=0` mode.

---

## Phase 1: Code Modifications

### 1.1 Add SetKey Method to Protocol Class

**File**: `mosac/ss/protocol.h`

The `Protocol` class currently has `key_` as private with only a getter. We need to add a setter:

```cpp
// Current (line 41):
PTy GetKey() const { return key_; }

// Add after GetKey():
void SetKey(PTy key) { key_ = key; }
```

**Rationale**: This allows the malicious party to modify their key share after the offline phase.

### 1.2 Create Malicious Party Binary

**New File**: `mosac/example/attack_poc.cc`

This binary is based on `NDSS_online_example.cc` but adds attack logic. The honest party continues to run the unmodified `NDSS_online_example` binary.

Key additions to the malicious binary:

```cpp
// Additional command line flag for attack
llvm::cl::opt<uint64_t> cl_delta(
    "delta", llvm::cl::init(1),
    llvm::cl::desc("Key modification delta for attack (default: 1)"));

// Modified shuffle function with attack injection
auto NDSS_shuffle2k_attack(/* same params as original */ uint64_t delta) {
  // ... same setup as NDSS_online_example ...

  auto prot = context->GetState<Protocol>();
  auto cr = context->GetState<Correlation>();

  // Cache population (identical to original)
  if (cache) {
    auto shares = prot->RandA(num, true);
    auto shuffle = prot->ShuffleA_2k(T, shares, true);
    auto result = prot->A2P(shuffle, true);
    context->GetState<Correlation>()->force_cache();
  }

  // Online phase (identical to original up to shuffle)
  auto shares = prot->RandA(num);
  auto shuffle = prot->ShuffleA_2k(T, shares);

  // >>> ATTACK INJECTION POINT <<<
  if (delta != 0) {
    PTy original_key = prot->GetKey();
    PTy new_key = original_key + PTy(delta);

    SPDLOG_WARN("[ATTACK] Modifying key by delta = {}", delta);

    prot->SetKey(new_key);
    cr->SetKey(new_key);
  }

  // MAC check - will now fail due to key mismatch
  bool check_result = prot->NdssDelayCheck();

  SPDLOG_INFO("[ATTACK] NdssDelayCheck result: {}",
              check_result ? "PASS" : "FAIL");

  // ... rest same as original ...
}
```

**Note**: The only differences from `NDSS_online_example.cc` are:

1. Added `--delta` command line flag
2. Attack injection between `ShuffleA_2k()` and `NdssDelayCheck()`
3. Additional logging for attack demonstration

### 1.3 Add BUILD Target

**File**: `mosac/example/BUILD.bazel`

```python
mosac_cc_binary(
    name = "attack_poc",
    srcs = ["attack_poc.cc"],
    deps = [
        "//mosac/context:register",
        "//mosac/ss:protocol",
        "//mosac/utils:test_util",
        "//mosac/utils:vec_op",
        "@yacl//yacl/base:int128",
        "@yacl//yacl/link",
        "@yacl//yacl/utils:serialize",
        "@yacl//yacl/utils:parallel",
        "@llvm-project//llvm:Support",
        "@com_google_absl//absl/strings",
        ":macro",
    ],
)
```

---

## Phase 2: Understanding the Attack Math

### 2.1 Normal MAC Check (Honest Execution)

In `NdssDelayCheck()`, the check works as follows:

**Setup**:
- Global MAC key: `α = key_0 + key_1`
- Each authenticated share `[x]` has: `val_0 + val_1 = x` and `mac_0 + mac_1 = x * α`

**Check Computation** (protocol.cc:319-346):

1. Generate random authenticated share `r` via `RandA(1)`
2. Accumulate: `r_val += Σ(coef_i * val_i)`, `r_mac += Σ(coef_i * mac_i)`
3. Exchange and reconstruct: `real_val = r_val_0 + r_val_1`
4. Compute: `zero_mac_i = r_mac_i - real_val * key_i`
5. Party 0 negates: `zero_mac_0 = -zero_mac_0`
6. Exchange with commitment and compare

**Why it works (honest case)**:
```
zero_mac_0 + zero_mac_1
  = -(r_mac_0 - real_val * key_0) + (r_mac_1 - real_val * key_1)
  = -r_mac_0 + real_val * key_0 + r_mac_1 - real_val * key_1
  = -(r_mac_0 + r_mac_1) + real_val * (key_0 + key_1)
  = -real_val * α + real_val * α
  = 0
```

### 2.2 Attack Scenario (Key Modification)

When the malicious party (P0) modifies their key:

**Before attack**:
- Cached correlations use `key_0` (original)
- Global key for cached shares: `α = key_0 + key_1`

**After attack**:
- P0 sets `key_0' = key_0 + Δ`
- `RandA(1)` generates new `r` with `α' = key_0' + key_1 = α + Δ`

**The check now computes**:

For the new `r`:
- `r` is authenticated w.r.t. `α' = α + Δ`
- So `r_mac_0 + r_mac_1 = r_val * α'`

For the buffered shares (from shuffle):
- Still authenticated w.r.t. `α`
- So `Σ mac_i = Σ val_i * α`

The accumulated values:
```
r_mac = r_mac_original + Σ(coef_i * mac_i)
      = (contribution from r w.r.t. α') + (contribution from buffer w.r.t. α)
```

The check computation:
```
zero_mac_0 = -(r_mac_0 - real_val * key_0')
zero_mac_1 = r_mac_1 - real_val * key_1

zero_mac_0 + zero_mac_1
  = -r_mac_0 + real_val * key_0' + r_mac_1 - real_val * key_1
  = -(r_mac_0 + r_mac_1) + real_val * (key_0' + key_1)
  = -(r_mac_0 + r_mac_1) + real_val * α'
```

Now, `r_mac_0 + r_mac_1` contains:
- From `r`: `r_val * α'` (consistent with `α'`)
- From buffer: `Σ(coef_i * val_i) * α` (inconsistent - uses old `α`)

So:
```
r_mac_0 + r_mac_1 = r_val * α' + Σ(coef_i * val_i) * α

zero_mac_0 + zero_mac_1
  = -(r_val * α' + Σ(coef_i * val_i) * α) + real_val * α'
  = -r_val * α' - Σ(coef_i * val_i) * α + (r_val + Σ(coef_i * val_i)) * α'
  = -r_val * α' - Σ(coef_i * val_i) * α + r_val * α' + Σ(coef_i * val_i) * α'
  = Σ(coef_i * val_i) * (α' - α)
  = Σ(coef_i * val_i) * Δ
```

### 2.3 Key Insight

**The error term is**: `Σ(coef_i * val_i) * Δ`

Where:
- `coef_i` are random coefficients (known to both parties via synced seed)
- `val_i` are the VALUE shares in the buffer (depend on honest party's input!)
- `Δ` is the key modification (controlled by attacker)

**For the check to pass**: `Σ(coef_i * val_i) * Δ = 0`

This happens when:
1. `Δ = 0` (no attack), OR
2. `Σ(coef_i * val_i) = 0` (depends on the actual values!)

Since `coef_i` are random but deterministic (from synced seed), the check result depends on the buffered values, which in turn depend on the honest party's inputs.

---

## Phase 3: PoC Implementation Steps

### 3.1 Basic Demonstration (Milestone 1)

**Goal**: Show that modifying the key causes the check to fail in a predictable way.

**Steps**:
1. Run honest vs honest - verify check passes
2. Run malicious vs honest with `Δ = 1` - observe check fails
3. Verify the failure is due to the key mismatch

**Expected Output**:
```
[Honest vs Honest] NdssDelayCheck: PASS
[Malicious vs Honest, Δ=1] NdssDelayCheck: FAIL
```

### 3.2 Input-Dependent Behavior (Milestone 2)

**Goal**: Demonstrate that the check result depends on the honest party's input values.

**Approach**:
1. Create a controlled input where we know the honest party's values
2. Run multiple times with different `Δ` values
3. Observe pattern in pass/fail

**Challenge**: The values in the buffer are transformed by the shuffle, so we need to understand the relationship between input and buffer contents.

**Simplification for PoC**:
- Use a very small input (e.g., `num = 8`, `T = 4`)
- Have the honest party use known input values
- The malicious party observes abort patterns

### 3.3 Information Extraction (Milestone 3)

**Goal**: Actually extract information about the honest party's input.

**Approach**:
1. Run the protocol multiple times with the same honest input
2. Each run, use a different `Δ` value
3. Collect the pass/fail results
4. Analyze to deduce information about the input

**Mathematical basis**:
- The error term `Σ(coef_i * val_i) * Δ` is linear in `Δ`
- If we can find a `Δ` where the check passes (error = 0), we learn that `Σ(coef_i * val_i) = 0`
- Multiple such equations can potentially solve for individual values

---

## Phase 4: Test Harness

### 4.1 Running the Attack (Two Separate Terminals)

The attack uses two separate Docker terminals - one for each party. This demonstrates that the honest party runs completely unmodified code.

**Terminal 1 - Honest Party (runs unmodified NDSS_online_example):**

```bash
docker exec mosac-dev bazel run -c opt --jobs=4 \
  --copt=-Wno-error=mismatched-new-delete \
  //mosac/example:NDSS_online_example -- \
  --alone=0 --rank=1 \
  --parties=127.0.0.1:9530,127.0.0.1:9531 \
  --small_power=3 --big_power=4 --cache=1
```

**Terminal 2 - Malicious Party (runs attack_poc with delta):**

```bash
docker exec mosac-dev bazel run -c opt --jobs=4 \
  --copt=-Wno-error=mismatched-new-delete \
  //mosac/example:attack_poc -- \
  --alone=0 --rank=0 \
  --parties=127.0.0.1:9530,127.0.0.1:9531 \
  --small_power=3 --big_power=4 --cache=1 \
  --delta=1
```

### 4.2 Expected Output

**Honest party (Terminal 1) - unmodified code:**

```text
[info] PROTOCOL START
[info] [P1] T 8 && num 16, working mode: Fake Correlated Randomness && Cache
... normal protocol execution ...
[error] NdssDelayCheck failed!  <-- Attack detected as MAC failure
```

**Malicious party (Terminal 2) - attack binary:**

```text
[info] PROTOCOL START
[info] [P0] T 8 && num 16, working mode: Fake Correlated Randomness && Cache
[warn] [ATTACK] Modifying key by delta = 1
[warn] [ATTACK] Original key: 0x1234567890abcdef
[warn] [ATTACK] New key:      0x1234567890abcdf0
[info] [ATTACK] NdssDelayCheck result: FAIL

This demonstrates the vulnerability: the check failed due to
key inconsistency between cached correlations and on-demand generation.
```

### 4.3 Control Experiment (Honest vs Honest)

To verify the protocol works correctly without attack:

```bash
# Terminal 1
docker exec mosac-dev bazel run ... //mosac/example:NDSS_online_example -- \
  --alone=0 --rank=1 --parties=127.0.0.1:9530,127.0.0.1:9531 ...

# Terminal 2 (also honest - using delta=0)
docker exec mosac-dev bazel run ... //mosac/example:attack_poc -- \
  --alone=0 --rank=0 --parties=127.0.0.1:9530,127.0.0.1:9531 ... \
  --delta=0
```

With `--delta=0`, no attack occurs and both parties should complete successfully.

---

## Phase 5: File Structure

```text
mosac/example/
├── NDSS_online_example.cc  # UNMODIFIED - honest party runs this
├── attack_poc.cc           # Malicious party binary (based on NDSS_online_example)
└── BUILD.bazel             # Updated with attack_poc target

mosac/ss/
└── protocol.h              # Add SetKey() method

docs/
├── SECURITY_VULNERABILITY_REPORT.md  # Existing report
└── POC_IMPLEMENTATION_PLAN.md        # This document
```

---

## Phase 6: Validation Checklist

### Pre-Implementation
- [ ] Verify build system works (`bazel build //mosac/example:NDSS_online_example`)
- [ ] Run existing example to understand normal behavior
- [ ] Understand the network setup (ports, connection order)

### Milestone 1: Basic Key Modification
- [ ] Add `SetKey` to Protocol class
- [ ] Create attack_poc.cc skeleton
- [ ] Verify honest-vs-honest still works
- [ ] Implement key modification
- [ ] Verify malicious-vs-honest causes check failure

### Milestone 2: Controlled Demonstration
- [ ] Add logging to show error term computation
- [ ] Demonstrate input-dependent behavior with small examples
- [ ] Document specific inputs that cause pass vs fail

### Milestone 3: Information Extraction
- [ ] Implement multi-run attack framework
- [ ] Collect and analyze abort patterns
- [ ] Demonstrate partial input recovery

---

## Appendix A: Key Code Locations

| Component | File | Lines | Purpose |
|-----------|------|-------|---------|
| Protocol key storage | `protocol.h` | 27 | `PTy key_` member |
| Protocol GetKey | `protocol.h` | 41 | Getter for key |
| Correlation SetKey | `true_cr.h` | 101-107 | Already exists |
| NdssDelayCheck | `protocol.cc` | 305-353 | The vulnerable check |
| RandA | `ashare.cc` | 199-201 | Calls RandomAuth |
| RandomAuth | `cr.cc` | 45-64 | Cache or on-demand |
| RandomSet (uses key) | `true_cr.cc` | 230-246 | MAC computation |

## Appendix B: Attack Timeline

```
Time →
─────────────────────────────────────────────────────────────────────────────
│         OFFLINE          │      ONLINE      │     ATTACK      │   CHECK   │
├──────────────────────────┼──────────────────┼─────────────────┼───────────┤
│ SetupContext()           │ RandA(num)       │ SetKey(k + Δ)   │ RandA(1)  │
│ force_cache() with key_0 │ ShuffleA_2k()    │ CR.SetKey(k+Δ)  │ Compare   │
│                          │ NdssBufferAppend │                 │           │
├──────────────────────────┼──────────────────┼─────────────────┼───────────┤
│ Uses: key_0              │ Uses: cached     │ Modifies key    │ Uses: k+Δ │
│ Global α = k0 + k1       │ correlations     │                 │ NEW r     │
─────────────────────────────────────────────────────────────────────────────
                                                                      ↑
                                                               VULNERABILITY:
                                                               r uses α+Δ but
                                                               buffer uses α
```

## Appendix C: Expected Effort

| Phase | Estimated Time | Dependencies |
|-------|---------------|--------------|
| Phase 1: Code Mods | 1-2 hours | None |
| Phase 2: Math Understanding | 1-2 hours | Phase 1 |
| Phase 3.1: Basic Demo | 2-3 hours | Phase 1, 2 |
| Phase 3.2: Input-Dependent | 3-4 hours | Phase 3.1 |
| Phase 3.3: Information Extraction | 4-8 hours | Phase 3.2 |
| Phase 4: Test Harness | 2-3 hours | Phase 3.1 |

**Total**: ~15-22 hours for complete implementation

**Minimum viable PoC** (Milestone 1 only): ~4-6 hours
