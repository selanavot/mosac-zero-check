# Selective Failure Attack PoC

## Docker Setup

Start the Docker container (from the repository root):

```bash
docker run -d --name mosac-dev -v "$(pwd)":/workspace -w /workspace secretflow/ubuntu-base-ci:latest tail -f /dev/null
```

If the container already exists but is stopped:

```bash
docker start mosac-dev
```

## Building

Build both binaries inside the Docker container:

```bash
docker exec mosac-dev bazel build //mosac/example:NDSS_online_example //mosac/example:attack_poc
```

## Running the Attack

The protocol shuffles 16 elements with T=8.

### Test 1: Attack with Zero Inputs (PASS expected)

**Terminal 1 - Honest Party (P1):**
```bash
docker exec mosac-dev bazel-bin/mosac/example/NDSS_online_example --rank=1 --cache=0 --input_mode=1
```

**Terminal 2 - Malicious Party (P0):**
```bash
docker exec mosac-dev bazel-bin/mosac/example/attack_poc --rank=0 --input_mode=1
```

The MAC check should **PASS** with zero inputs.

### Test 2: Attack with Random Inputs (FAIL expected)

**Terminal 1 - Honest Party (P1):**
```bash
docker exec mosac-dev bazel-bin/mosac/example/NDSS_online_example --rank=1 --cache=0 --input_mode=0
```

**Terminal 2 - Malicious Party (P0):**
```bash
docker exec mosac-dev bazel-bin/mosac/example/attack_poc --rank=0 --input_mode=0
```

The MAC check should **FAIL** with random (non-zero) inputs.

## Interpreting Results

The attack is successful when:

1. **Zero inputs**: MAC check **PASSES**
2. **Random inputs**: MAC check **FAILS**

This differential behavior demonstrates that the attacker can distinguish input values.

## Notes

- Start the honest party (Terminal 1) before the malicious party (Terminal 2)
- If you get a "Fail to listen" error, kill any lingering processes:

  ```bash
  docker exec mosac-dev pkill -9 -f "NDSS_online_example\|attack_poc"
  ```

- Both parties must use the same `--input_mode` value
