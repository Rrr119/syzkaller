# Subsystem generation benchmark

Target: `linux/amd64`; programs per mode: 1200; target calls: 16; seed: 38818; weight: 8.0x.

All modes generate program `i` from `seed + 1009*i`. Coverage is deterministic description-space coverage, not kernel PC coverage.

| Subsystem | Calls baseline | Weighted | Combined | Coverage gain (pp) | Relative gain | Pair baseline → combined | Template hits | Reproducible |
|---|---:|---:|---:|---:|---:|---:|---:|:---:|
| `bpf` | 78/91 (85.71%) | 89 (97.80%) | 89 (97.80%) | +12.09 / +12.09 | +14.1% / +14.1% | 48 → 775 | 431/1200 | true |
| `io-uring` | 65/83 (78.31%) | 82 (98.80%) | 83 (100.00%) | +20.48 / +21.69 | +26.2% / +27.7% | 6 → 519 | 434/1200 | true |
| `kvm` | 117/207 (56.52%) | 207 (100.00%) | 207 (100.00%) | +43.48 / +43.48 | +76.9% / +76.9% | 43 → 1221 | 434/1200 | true |

Reproducibility hashes are SHA-256 of serialized program generated from the base seed in each mode.
