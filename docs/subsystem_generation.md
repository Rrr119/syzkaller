# Subsystem-aware generation

Syzkaller's default `ChoiceTable` already combines static resource priorities and
dynamic corpus priorities. The optional subsystem layer multiplies the column
corresponding to every call assigned to a configured subsystem, then renormalizes
each priority row. It does not replace corpus priorities, program parsing, or
mutation, so existing corpus databases and text programs remain compatible.

## Manager configuration

```json
{
  "subsystem_weights": {
    "bpf": 8,
    "io_uring": 8,
    "kvm": 8
  },
  "call_template_probability": 35,
  "call_templates": [
    {
      "name": "kvm-device-run",
      "selectors": ["openat$kvm", "ioctl$KVM_CREATE_VM", "ioctl$KVM_RUN"],
      "weight": 1
    }
  ]
}
```

Weights are relative multipliers. `1.0` is the default, `8.0` is a strong focus,
and values below `1.0` de-emphasize a subsystem. `io_uring` and `io-uring` are
equivalent. Selectors are exact call names or shell-like patterns such as
`ioctl$KVM_*`. Template selectors are resolved when the configuration is loaded;
missing or `no_generate` selectors are configuration errors.

When `subsystem_weights` is enabled for Linux, built-in structural templates are
available for `bpf`, `io_uring`/`io-uring`, and `kvm`. Resource-creation calls
required by template calls are still produced by the normal argument generator.

Call descriptions can also carry an explicit label, for example:

```
bpf$MAP_CREATE(...) fd_bpf_map (subsystem["bpf"])
```

If the attribute is absent, the generator falls back to the MAINTAINERS-derived
subsystem call map and built-in call-name patterns.

## Deterministic comparison

`tools/syz-subsystem-bench` generates program `i` from `seed + 1009*i` in every
mode. Thus the baseline, weighted, and combined modes use the same seeds, and a
fixed seed always produces the same serialized program.

Print a reproducible program directly with:

```bash
go run ./tools/syz-mutate -os linux -arch amd64 \
  -seed 38818 -len 16 -subsystems kvm
```

```bash
go run ./tools/syz-subsystem-bench \
  -programs 1200 -calls 16 -seed 38818 -weight 8 \
  -format markdown \
  -out artifacts/subsystem-generation-report.md
```

The checked run for `linux/amd64` gives the following description-space coverage:

| Subsystem | Baseline calls | Weighted calls | Weighted + templates | Gain |
|---|---:|---:|---:|---:|
| `bpf` | 78/91 (85.71%) | 89/91 (97.80%) | 89/91 (97.80%) | +12.09 pp |
| `io-uring` | 65/83 (78.31%) | 82/83 (98.80%) | 83/83 (100.00%) | +21.69 pp |
| `kvm` | 117/207 (56.52%) | 207/207 (100.00%) | 207/207 (100.00%) | +43.48 pp |

The same run increases unique in-subsystem adjacent-call pairs from `48` to
`775` for BPF, `6` to `519` for io_uring, and `43` to `1221` for KVM. All modes
report `reproducible: true`; JSON output includes the SHA-256 of the program
generated from the base seed.

These numbers measure syscall-description and sequence coverage. They are a fast
host-side acceptance signal, not kernel PC coverage.

## Existing corpus

Use `-corpus-dir` to build dynamic priorities from serialized text programs:

```bash
go run ./tools/syz-subsystem-bench \
  -corpus-dir /path/to/corpus-text \
  -subsystems bpf,io_uring,kvm
```

For example, the amd64-compatible files in `sys/linux/test` load successfully;
architecture-specific files that contain calls absent from `linux/amd64` are
reported and skipped by the benchmark loader. Production `corpus.db` files do not
need migration because program serialization is unchanged.

## Kernel coverage A/B

For kernel PC coverage, run two managers with the same kernel, image, VM count,
execution budget, and starting corpus:

1. Baseline configuration without `subsystem_weights`.
2. Treatment configuration with the desired subsystem weights.
3. Stop both after the same number of executions or elapsed time.
4. Fetch `/rawcover` from each manager and run:

```bash
./bin/syz-cover -config baseline.cfg -exports subsystem,json baseline.rawcover
./bin/syz-cover -config weighted.cfg -exports subsystem,json weighted.rawcover
```

Compare the subsystem JSON entries for `bpf`, `io-uring`, and `kvm`. The
deterministic benchmark should be used to catch generator regressions quickly;
the VM A/B should be used for final kernel-coverage acceptance.
