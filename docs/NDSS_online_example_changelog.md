# NDSS_online_example.cc Modifications

This document describes modifications made to the honest party binary (`NDSS_online_example.cc`) to support attack testing. Ideally there would be no changes, since we got to be abl to attack a party running a normal part of the protocol, but we needed a way to control the input and we added significant logging to make implementing the attack easier.

## New Command-Line Option

### `--input_mode`

```cpp
llvm::cl::opt<uint32_t> cl_input_mode(
    "input_mode", llvm::cl::init(0),
    llvm::cl::desc("0 = random inputs, 1 = all zeros"));
```

- `--input_mode=0` (default): Generate random authenticated shares using `RandA()`
- `--input_mode=1`: Generate shares of zero using `ZerosA()`

## Input Generation

The original code always used random inputs:

```cpp
auto shares = prot->RandA(num);
```

Modified to support both random and zero inputs:

```cpp
std::vector<internal::ATy> shares;
if (input_mode == 0) {
  shares = prot->RandA(num);
} else {
  shares = prot->ZerosA(num);
}
```

## Debug Logging

Added logging to display the first 4 input shares:

```cpp
SPDLOG_INFO("[P{}] === INPUT SHARES (first 4) ===", rank);
for (size_t i = 0; i < std::min((size_t)4, shares.size()); ++i) {
  SPDLOG_INFO("[P{}] shares[{}]: val=0x{:016x}, mac=0x{:016x}",
              rank, i, shares[i].val.GetVal(), shares[i].mac.GetVal());
}
```

Added logging around shuffle operation:

```cpp
SPDLOG_INFO("[P{}] === SHUFFLE START ===", rank);
auto shuffle = prot->ShuffleA_2k(T, shares);
SPDLOG_INFO("[P{}] === SHUFFLE END ===", rank);
```

Added logging to display the first 4 shuffle outputs:

```cpp
SPDLOG_INFO("[P{}] === SHUFFLE OUTPUT (first 4) ===", rank);
for (size_t i = 0; i < std::min((size_t)4, shuffle.size()); ++i) {
  SPDLOG_INFO("[P{}] shuffle[{}]: val=0x{:016x}, mac=0x{:016x}",
              rank, i, shuffle[i].val.GetVal(), shuffle[i].mac.GetVal());
}
```

## Additional Communication Rounds

Added 4 extra Exchange calls to reconstruct and log shuffle values:

```cpp
SPDLOG_INFO("[P{}] === RECONSTRUCTING SHUFFLE VALUES (first 4) ===", rank);
{
  auto conn = context->GetConnection();
  for (size_t i = 0; i < std::min((size_t)4, shuffle.size()); ++i) {
    auto remote_val = conn->Exchange(shuffle[i].val.GetVal());
    auto reconstructed = shuffle[i].val + internal::PTy(remote_val);
    SPDLOG_INFO("[P{}] shuffle[{}] reconstructed value = 0x{:016x}", rank, i, reconstructed.GetVal());
  }
}
```

**Note**: These Exchange calls add 4 additional communication rounds to the protocol. Both parties (honest and attack_poc) must have matching Exchange calls to maintain protocol synchronization.

## Impact on Protocol

These modifications do not affect the core protocol logic or the attack mechanism. The debug logging and extra Exchange calls can be removed from both `NDSS_online_example.cc` and `attack_poc.cc` without breaking the attack, as long as they are removed from both binaries to maintain protocol synchronization.

The logging is kept for maintainability and debugging purposes.

| Aspect | Change |
|--------|--------|
| Communication rounds | +4 (for debug reconstruction) |
| Computation | Minimal (logging only) |
| Security | No impact (debug logging only) |
| Compatibility | Requires matching attack_poc binary |
