# Selective Failure Attack PoC

This document describes the selective failure attack against MOSAC and how to reproduce it.

---

## Part 1: Attack Details

### Overview

The attack exploits a vulnerability in the SPDZ-style blind MAC verification used by MOSAC. After participating honestly in the shuffle protocol, the malicious party modifies their local MAC key share before the final MAC check. This causes the check to pass or fail depending on whether the secret-shared inputs are zero or non-zero. This leaks information that should remain private.

### Attack Steps

1. Both parties run the shuffle protocol honestly
2. The malicious party modifies their MAC key share by adding 1
3. The MAC check is performed with the modified key
4. **Zero inputs**: The check passes (the error term is 0 regardless of the key)
5. **Non-zero inputs**: The check fails (the key mismatch produces a non-zero error)

This differential behavior allows the attacker to learn whether the honest party's inputs are zero.

### PoC Parameters

The PoC uses the following settings:

| Parameter | Value | Why It Matters |
|-----------|-------|----------------|
| `--cache=0` | No caching | Forces on-demand correlation generation during the online phase. This parameter means that multiplication triples are generated whenever they are needed, and consequently correlations generated after the key modification use the modified key. This simplifies the attack, though it is not essential since MOSAC supports on-demand preprocessing even if it is batched and cached.
| `--CR=0` | Fake correlations | Uses PRG-based correlations (the default in the original repo). Simpler than securely generating correlations and sufficient for demonstrating the vulnerability.|
| `T=8` | Repetition parameter | Hardcoded in the binaries - the recommended default in the original implementation. |
| `NUM=16` | Number of elements | Number of elements being shuffled. Hardcoded in the binaries. Shuffles 16 elements. |

---

## Part 2: Reproducing the Attack

### Prerequisites

You need Docker installed. The build runs inside a container.

### Step 1: Start the Docker Container

From the repository root:

```bash
docker run -d --name mosac-dev -v "$(pwd)":/workspace -w /workspace secretflow/ubuntu-base-ci:latest tail -f /dev/null
```

If the container already exists but is stopped:

```bash
docker start mosac-dev
```

### Step 2: Build the Binaries

```bash
docker exec mosac-dev bazel build //mosac/example:NDSS_online_example //mosac/example:attack_poc
```

This may take some time.

### Step 3: Run the Attack

Open two terminals.

#### Test 1: Zero Inputs — MAC check should PASS

**Terminal 1 — Honest Party (P1):**
```bash
docker exec mosac-dev bazel-bin/mosac/example/NDSS_online_example --rank=1 --cache=0 --input_mode=1
```

**Terminal 2 — Malicious Party (P0):**
```bash
docker exec mosac-dev bazel-bin/mosac/example/attack_poc --rank=0 --input_mode=1
```

Expected output:
```
MAC check PASSED => inputs are ALL ZEROS
```

#### Test 2: Random Inputs — MAC check should FAIL

**Terminal 1 — Honest Party (P1):**
```bash
docker exec mosac-dev bazel-bin/mosac/example/NDSS_online_example --rank=1 --cache=0 --input_mode=0
```

**Terminal 2 — Malicious Party (P0):**
```bash
docker exec mosac-dev bazel-bin/mosac/example/attack_poc --rank=0 --input_mode=0
```

Expected output:
```
MAC check FAILED => inputs are NON-ZERO
```

### Interpreting Results

The attack succeeds if you observe the differential behavior: PASS for zero inputs, FAIL for random inputs. This proves the attacker can distinguish between these cases, violating the protocol's privacy guarantees.

---

## Troubleshooting

### "Fail to listen" error

Kill lingering processes from a previous run:

```bash
docker exec mosac-dev pkill -9 -f "NDSS_online_example\|attack_poc"
```

### Mismatched behavior

Both parties must use the same `--input_mode` value.

### Build hangs or crashes

On systems with limited memory (e.g., Docker Desktop with default settings), the build may hang or crash during linking. Limit the number of parallel jobs:

```bash
docker exec mosac-dev bazel build --jobs=4 //mosac/example:NDSS_online_example //mosac/example:attack_poc
```

If the build still hangs, try increasing Docker's memory allocation in Docker Desktop settings.

### Docker container not running error
If the Docker container says it is not running when building the image, for example:
`Error response from daemon: container <container-id> is not running`

Try out an entrypoint via `/bin/bash`:
```
docker run -d \
  --name mosac-dev \
  --entrypoint /bin/bash \
  -v "$(pwd)":/workspace \
  -w /workspace \
  secretflow/ubuntu-base-ci:latest \
  -lc 'while true; do sleep 3600; done'
```
