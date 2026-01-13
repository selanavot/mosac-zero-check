# MOSAC - Selective Failure Attack PoC

This repository contains a proof-of-concept implementation of a selective failure attack against the Song et al. NDSS'24 shuffle protocol.

## Quick Start

See [docs/attack.md](docs/attack.md) for instructions on running the attack.

## Documentation

- [docs/attack.md](docs/attack.md) - How to run the selective failure attack
- [docs/NDSS_online_example_changelog.md](docs/NDSS_online_example_changelog.md) - Modifications made to the honest party binary
- [docs/original_README.md](docs/original_README.md) - Original MOSAC project documentation

## Attack Implementation

The attack is implemented in:

- [mosac/example/attack_poc.cc](mosac/example/attack_poc.cc) - Malicious party binary
- [mosac/example/NDSS_online_example.cc](mosac/example/NDSS_online_example.cc) - Honest party binary (modified for testing)
