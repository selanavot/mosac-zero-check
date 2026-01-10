# MOSAC macOS Build Migration Plan

## Problem Summary

The MOSAC benchmarking code (from a cryptographic shuffle paper) fails to build on macOS due to:
- brpc dependency uses `objc_library` which is broken with Xcode 15+ and Bazel 6.x
- Bazel 7 requires explicit apple_support toolchain registration
- The original YACL fork is outdated

## Goal

Get MOSAC building natively on macOS for active development.

---

## Staged Migration Plan

### Stage 0: Verify Original Code in Docker
**Time estimate: 15-30 minutes**
**Risk level: Low - this is the authors' tested configuration**

**Objective:** Confirm the original code builds and tests pass in Docker (Linux).

**Steps:**
1. Build Docker image
2. Run `bazel build //...` and `bazel test //...`
3. Optionally run an example benchmark

**Success criteria:** Compiles and tests pass.

**If this fails:** Environment issue - debug Docker/Bazel setup before proceeding.

---

### Stage 1: Validate YACL API Compatibility (Docker)
**Time estimate: 1-2 hours**
**Risk level: Medium - this is the key gate**

**Objective:** Confirm that the Sept 2024 YACL (last WORKSPACE-compatible version) works with MOSAC code.

**Steps:**
1. Build Docker image with Bazel 6.5
2. Update `bazel/repositories.bzl`:
   - Change YACL commit to `5535111ffafbc123f189f13b4a6b141796bb7f58`
   - Change remote to `https://github.com/secretflow/yacl.git`
3. Update BUILD.bazel files with new YACL paths (see path mapping below)
4. Update C++ #include statements if needed
5. Run `bazel build //...` and `bazel test //...`

**Success criteria:** Compiles and tests pass in Docker.

**If this fails:** API incompatibility - need to analyze specific errors and decide if fixes are tractable.

---

### Stage 2: Migrate to bzlmod (Docker)
**Time estimate: 2-3 hours**
**Risk level: Low-Medium**

**Objective:** Migrate from WORKSPACE to MODULE.bazel with newest YACL.

**Steps:**
1. Create MODULE.bazel with dependencies:
   - yacl (newest)
   - boost
   - bazel_skylib
   - rules_python, rules_pkg, rules_foreign_cc
2. Update .bazelversion to 7.4.0
3. Update .bazelrc (remove incompatible flags if needed)
4. Update BUILD.bazel paths for any additional changes in newest YACL
5. Run `bazel build //...` and `bazel test //...`

**Success criteria:** Compiles and tests pass in Docker with bzlmod.

**If this fails:** Isolated to bzlmod configuration - can debug dependency resolution.

---

### Stage 3: Native macOS Build
**Time estimate: 1-2 hours**
**Risk level: Low (if Stages 1-2 passed)**

**Objective:** Run the bzlmod build natively on macOS.

**Steps:**
1. Copy working configuration from Stage 2
2. Run `bazel build //...` on macOS
3. If apple_support issues arise, verify toolchain registration

**Success criteria:** Compiles and runs on macOS.

**If this fails:** Isolated to macOS toolchain - newest YACL should include apple_support v2.1.0.

---

## YACL Path Mapping (Old -> New)

### OT Primitives (crypto/primitives/ot -> kernel/algorithms)
```
@yacl//yacl/crypto/primitives/ot:base_ot      -> @yacl//yacl/kernel/algorithms:base_ot
@yacl//yacl/crypto/primitives/ot:kos_ote      -> @yacl//yacl/kernel/algorithms:kos_ote
@yacl//yacl/crypto/primitives/ot:gywz_ote     -> @yacl//yacl/kernel/algorithms:gywz_ote
@yacl//yacl/crypto/primitives/ot:sgrr_ote     -> @yacl//yacl/kernel/algorithms:sgrr_ote
@yacl//yacl/crypto/primitives/ot:softspoken_ote -> @yacl//yacl/kernel/algorithms:softspoken_ote
@yacl//yacl/crypto/primitives/ot:ot_store     -> @yacl//yacl/kernel/type:ot_store
```

### Code (crypto/primitives/code -> kernel/code)
```
@yacl//yacl/crypto/primitives/code:linear_code -> @yacl//yacl/kernel/code:linear_code
```

### Crypto Utils (crypto/utils -> crypto/rand)
```
@yacl//yacl/crypto/utils:rand -> @yacl//yacl/crypto/rand
```

### Hash (crypto/base/hash -> crypto/hash)
```
@yacl//yacl/crypto/base/hash:hash_utils -> @yacl//yacl/crypto/hash:hash_utils
```

### AES (crypto/base/aes -> crypto/aes)
```
@yacl//yacl/crypto/base/aes:aes_opt        -> @yacl//yacl/crypto/aes:aes_opt
@yacl//yacl/crypto/base/aes:aes_intrinsics -> @yacl//yacl/crypto/aes:aes_intrinsics
```

### Unchanged paths (verify these still exist)
```
@yacl//yacl/base:exception
@yacl//yacl/base:int128
@yacl//yacl/base:dynamic_bitset
@yacl//yacl/base:aligned_vector
@yacl//yacl/base:buffer
@yacl//yacl/base:byte_container_view
@yacl//yacl/crypto/tools:prg
@yacl//yacl/crypto/tools:common
@yacl//yacl/crypto/tools:crhash
@yacl//yacl/crypto/tools:rp
@yacl//yacl/math/mpint
@yacl//yacl/math:gadget
@yacl//yacl/link
@yacl//yacl/utils:parallel
@yacl//yacl/utils:serialize
@yacl//yacl/utils:thread_pool
```

---

## Files to Modify

### BUILD.bazel files
- `mosac/cr/utils/BUILD.bazel` - heaviest changes (OT deps)
- `mosac/utils/BUILD.bazel`
- `mosac/context/BUILD.bazel`
- `mosac/ss/BUILD.bazel`
- `mosac/example/BUILD.bazel`

### Build configuration
- `bazel/repositories.bzl` - YACL commit and remote
- `WORKSPACE` - may need apple_support (Stage 2: replace with MODULE.bazel)
- `.bazelversion` - 6.5.0 for Stage 1, 7.4.0 for Stage 2+
- `.bazelrc` - may need flag updates

### C++ source files (if include paths changed)
- Grep for `#include "yacl/crypto/primitives/`
- Grep for `#include "yacl/crypto/utils/`
- Grep for `#include "yacl/crypto/base/`

---

## Rollback Plan

If migration fails at any stage:
1. Git stash or revert changes
2. Use Docker with original configuration for immediate work
3. Revisit migration later or accept Docker as primary dev environment

---

## Current Status

- [x] Stage 0: Verify Original Code in Docker (PASSED - 11/11 tests + benchmark)
- [ ] Stage 1: YACL API Compatibility (Docker) - **DEFERRED**
- [ ] Stage 2: bzlmod Migration (Docker) - **DEFERRED**
- [ ] Stage 3: Native macOS Build - **DEFERRED**

**Decision:** Using Docker for development. Stages 1-3 deferred until Docker becomes a problem.

---

## Stage 0 Findings

Required fixes for Docker build:

1. Use `FROM ubuntu:22.04` (not `ubuntu:latest` which pulls 24.04)
   - Ubuntu 24.04 has GCC 13+ which has stricter warnings and breaks LLVM compilation
   - Ubuntu 22.04 has GCC 11 which is compatible

2. Add build flag: `--copt=-Wno-error=mismatched-new-delete`
   - The msgpack library has a malloc/delete mismatch warning that GCC 11 treats as error
   - This flag suppresses that specific warning-as-error

3. Add `g++` and `git` to apt-get install
   - Original Dockerfile only had `gcc`, missing C++ compiler
   - `git` needed for fetching dependencies

### Updated Dockerfile

```dockerfile
FROM ubuntu:22.04

WORKDIR /MOSAC

# install dependency
RUN apt-get update
RUN apt-get install -y gcc g++ cmake nasm iproute2 npm ninja-build git

# install bazelisk
RUN npm install -g @bazel/bazelisk
RUN alias bazel='bazelisk'

# copy source code
COPY . /MOSAC

# Build command (run manually):
# bazel build -c opt --jobs=4 --copt=-Wno-error=mismatched-new-delete //...
# bazel test -c opt --jobs=4 --copt=-Wno-error=mismatched-new-delete //...
```

### Build commands

```bash
# Build Docker image (one-time)
docker build -t mosac:latest .

# Create persistent container with volume mount (recommended for development)
docker run -d --name mosac-dev -m 8g \
  -v /path/to/Code:/MOSAC \
  mosac:latest sleep infinity

# Run builds inside container (uses cache, incremental builds are fast)
docker exec mosac-dev bazel build -c opt --jobs=4 --copt=-Wno-error=mismatched-new-delete //...
docker exec mosac-dev bazel test -c opt --jobs=4 --copt=-Wno-error=mismatched-new-delete //...

# Interactive shell
docker exec -it mosac-dev bash

# Stop/start container
docker stop mosac-dev
docker start mosac-dev

# Remove container (loses Bazel cache)
docker rm mosac-dev
```

**Note:** With volume mount + persistent container:
- First build: ~7 minutes (populates cache)
- Incremental builds: <1 second (uses cache)

### Benchmark Validation

Successfully ran the NDSS shuffle benchmark:

```bash
docker exec mosac-dev bazel run -c opt --jobs=4 --copt=-Wno-error=mismatched-new-delete \
  //mosac/example:NDSS_online_example -- --alone=1 --small_power=4 --big_power=8
```

Output:
```
[P0] T 16 && num 256, working mode: Fake Correlated Randomness && Cache
NDSS_shuffle_online need 7 ms (0.007 s)
send bytes: 344208 && recv bytes: 344208
Double Check Done ✓
```

**Confirmed working:**
- Two-party protocol runs correctly (both P0 and P1)
- Shuffle operation completes in 7ms for 256 elements
- Verification ("Double Check") passes
- Communication: ~344KB sent/received per party

---

## Notes

- Original YACL fork: `liang-xiaojian/yacl` commit `c33e02d10739d42a5f71ce7c78ae4bcbc97b11df`
- Sept 2024 YACL: `secretflow/yacl` commit `5535111ffafbc123f189f13b4a6b141796bb7f58`
- Newest YACL: `secretflow/yacl` commit `77b215ddfd5c0b14abc5d30d69e1c2c22937ffd1` (uses bzlmod)
