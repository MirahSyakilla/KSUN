# KernelSU-Next Validation Suite

Runtime and static validation for the ARM64 branch-link migration
(`susfs+nomount-hookless` branch).

## Directory structure

```
validation/
├── tests/                          Device-side shell tests (run via adb shell su)
│   ├── test_branch_link_inventory.sh  Kallsyms + dmesg inventory, READY state
│   ├── test_faccessat.sh              faccessat/faccessat2 semantics
│   ├── test_readlink.sh               readlink/readlinkat + /proc fd links
│   ├── test_stat_statfs.sh            stat/newfstatat/statx/statfs
│   ├── test_open.sh                   openat/creat/O_* + open_redirect lifecycle
│   ├── test_exec.sh                   execve/execveat + sucompat
│   ├── test_mount.sh                  mount/namespace + SUSFS mount rules
│   ├── test_lifecycle.sh              concurrency stress + fallback invariant
│   ├── t02_sucompat.sh                sucompat deep-dive + SUSFS feature list
│   └── run_all_branch_link_tests.sh   Run all tests, collect results
├── audit/
│   ├── audit_scan_boundaries.sh       Static Image scan-boundary audit
│   └── thinlto-scan-audit.txt         ThinLTO image audit results (archived)
└── README.md                          This file
```

## Running tests on device

```bash
# 1. Push the suite
adb shell mkdir -p /data/local/tmp/bl-tests
adb push validation/tests/*.sh /data/local/tmp/bl-tests/

# 2. Run all tests
adb shell su -c 'sh /data/local/tmp/bl-tests/run_all_branch_link_tests.sh'

# 3. Or run individual tests
adb shell su -c 'sh /data/local/tmp/bl-tests/test_branch_link_inventory.sh'
```

## Running the static image audit (on host)

```bash
# Requires aarch64-linux-gnu-objdump (or set CROSS_OBJDUMP)
export CROSS_OBJDUMP=aarch64-linux-gnu-objdump
sh validation/audit/audit_scan_boundaries.sh \
    <path-to-System.map> \
    <path-to-Image> \
    validation/audit/scan-audit-results.txt
```

## Interpreting results

Each test script outputs individual PASS/FAIL/SKIP lines and a summary.
`run_all_branch_link_tests.sh` aggregates everything and writes a timestamped
log to `/data/local/tmp/bl-test-results-<timestamp>.log`.

### Inventory verdicts

The inventory test (`test_branch_link_inventory.sh`) reads the kernel's
`branch_link: readiness` dmesg line and reports READY / NOT-READY per family:

| Family    | Fallback when NOT-READY                     |
|-----------|---------------------------------------------|
| faccess   | __NR_faccessat dispatcher (no-op passthrough gate) |
| readlink  | NoMount getname_* probes (always active)     |
| stat-path | __NR_newfstatat dispatcher (no-op passthrough gate) |
| stat-fd   | vfs_getattr_nosec return probe (mandatory)   |
| statfs    | NoMount vfs_statfs kretprobe (mandatory)     |
| exec      | __NR_execve dispatcher (no-op passthrough gate) |
| mount     | SUSFS kretprobe fallback (mandatory)         |

NOT-READY for stat-fd is expected on non-LTO builds (all-optional enrichment).
All other NOT-READY statuses mean the corresponding fallback is the active
provider and should be tested via its own path.

## Adding new tests

Each test script must:
1. Use `PASS` / `FAIL` / `SKIP` per check via the `record()` helper.
2. Print a summary line matching `PASS=N FAIL=N SKIP=N`.
3. Clean up test artifacts.
4. Avoid destructive operations unless explicitly documented.
