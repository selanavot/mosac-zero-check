# Selective Failure Attack on MOSAC

This repository demonstrates a selective failure attack against MOSAC, the shuffle protocol implementation by [Song et al. (NDSS 2024)](https://eprint.iacr.org/2023/1794). The attack is introduced in our paper:

> **FLOSS: Fast Linear Online Secret-Shared Shuffling**

Please see our paper (FLOSS) for details regarding the vulnerability.

## Background

We obtained the MOSAC implementation directly from Song et al., whom we thank for sharing it with us and allowing us to distribute it. Note that the code was never made public by the original authors.

Our goal in this repository is to demonstrate that the attack works against the honest party's code **exactly as we obtained it**, without any modifications to the protocol logic. This is important because:

1. It proves the vulnerability exists in the real implementation, not a weakened version
2. It shows the attack is practical—the adversary only needs to deviate from the protocol on their own side

## Implementation Approach

To achieve this, we used the pre-existing `NDSS_online_example.cc`, which was included in the original repository as a secret-shared shuffling example. We use an honest party executing that code as the victim of the proof of concept.

- **Left the honest party's protocol code completely unmodified.** The only change to `NDSS_online_example.cc` is a command-line flag (`--input_mode`) that controls whether the parties use shares of zero or shares of random field elements. The attack distinguishes between these two cases using the result of the blind authentication check.

- **Implemented the attack in a separate binary** (`attack_poc.cc`) that acts as the malicious party. This binary participates honestly in the offline phase, then modifies its MAC key share before the online verification, causing selective failures that leak information about the secret shared data - namely whether it is zero or not.

See [docs/NDSS_online_example_changelog.md](docs/NDSS_online_example_changelog.md) for the exact (minimal) modifications we made.

## Repository Structure

The only files that are relevant for our attack are below.

```text
mosac/example/
├── attack_poc.cc           # Malicious party binary
└── NDSS_online_example.cc  # Honest party binary (protocol unmodified)
```

The rest of the repo contains the entire MOSAC protocol, as well as other examples and benchmarking code that are irrelevant.

## Documentation

- [docs/attack.md](docs/attack.md) — Attack details, including instructions for reproducing the attack
- [docs/NDSS_online_example_changelog.md](docs/NDSS_online_example_changelog.md) — Complete changelog of the (minimal) changes we made to the honest party's code.
- [docs/original_README.md](docs/original_README.md) — Original (unmodified) MOSAC documentation from Song et al., which used to be at the root of the repo.

## Quick Start

See [docs/attack.md](docs/attack.md) for Docker setup and step-by-step instructions to reproduce the attack.
