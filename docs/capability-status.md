# Capability status

## Auditable Run Pack v1

**Evidence state:** locally reproduced in the Task 10 closeout gate; see the Task 10 closeout receipt for exact commands, outcomes, scope, and limitations.

The supported, tested local boundary is an exported terminal run pack whose
manifest binds the copied receipts, chain metadata, referenced artifacts, and
descriptive provenance files. The ledger verifies the pack from its own bytes;
the runner performs recorded-evidence replay only after that verification.

This status does **not** claim production readiness, provider-backed execution
or replay, remote execution, deployment support, hosted operation, or general
security certification. It also does not make `OPERATOR_REPORT.json` or
provenance documents authoritative over canonical receipt/lifecycle evidence.

## Operator commands

```bash
ra pack export --run <run-dir> --out <empty-pack-dir>
ra pack verify --pack <pack-dir>
ra pack replay --pack <pack-dir>
./scripts/verify-run-pack.sh
```

`verify-run-pack.sh` is a local acceptance wrapper. It requires `strace` and
fails `69` with `BLOCKED` when that syscall-observation prerequisite is absent.
