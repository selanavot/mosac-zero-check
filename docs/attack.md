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

By default, the protocol shuffles **16 elements** (2^4, controlled by `--big_power`).

### Test 1: Attack with Zero Inputs (PASS expected)

**Terminal 1 - Honest Party (P1):**
```bash
docker exec mosac-dev bazel-bin/mosac/example/NDSS_online_example --rank=1 --cache=0 --input_mode=1
```

**Terminal 2 - Malicious Party (P0):**
```bash
docker exec mosac-dev bazel-bin/mosac/example/attack_poc --rank=0 --cache=0 --delta=1 --input_mode=1
```

The MAC check should **PASS** with zero inputs.

### Test 2: Attack with Random Inputs (FAIL expected)

**Terminal 1 - Honest Party (P1):**
```bash
docker exec mosac-dev bazel-bin/mosac/example/NDSS_online_example --rank=1 --cache=0 --input_mode=0
```

**Terminal 2 - Malicious Party (P0):**
```bash
docker exec mosac-dev bazel-bin/mosac/example/attack_poc --rank=0 --cache=0 --delta=1 --input_mode=0
```

The MAC check should **FAIL** with random (non-zero) inputs.

## Command-Line Options

| Option | Default | Description |
|--------|---------|-------------|
| `--rank=N` | 0 | Party identity (0 or 1) |
| `--cache=N` | 1 | 0 = no cache, 1 = pre-compute offline randomness |
| `--input_mode=N` | 0 | 0 = random inputs, 1 = all zeros |
| `--delta=N` | 1 | (attack_poc only) Key modification amount. 0 = no attack, non-zero = attack |

## How Zero Shares Work

The `ZerosA` function generates **random shares that sum to zero**:

1. Both parties use a shared PRG to generate identical random values
2. Party 0 negates its shares: `(-r_val, -r_mac)`
3. Party 1 keeps positive values: `(r_val, r_mac)`
4. Reconstruction: `(-r_val + r_val) = 0`

The shares themselves are random, but they always sum to zero.

## Interpreting Results

The attack is successful when:
1. **Zero inputs + attack (delta=1)**: MAC check **PASSES**
2. **Random inputs + attack (delta=1)**: MAC check **FAILS**

This differential behavior demonstrates that the attacker can distinguish input values.

### Control Experiment

With `--delta=0`, the attack is disabled and the MAC check should always pass regardless of input values.

## Notes

- Start the honest party (Terminal 1) before the malicious party (Terminal 2)
- If you get a "Fail to listen" error, kill any lingering processes: `docker exec mosac-dev pkill -9 -f "NDSS_online_example\|attack_poc"`
- Both parties must use the same `--cache` and `--input_mode` values
