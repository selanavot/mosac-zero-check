# NDSS_online_example.cc Modifications

This document describes modifications made to the honest party binary (`NDSS_online_example.cc`) to support attack testing. Ideally there would be no changes, since we want to attack a party running a normal part of the protocol, but we needed a way to control the input.

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