# Task 10 rollback and quarantine

## Scope

The Run Pack sprint is additive. It changes contracts/ledger/runner/CLI-facing behavior, focused tests, an acceptance wrapper, and truthful documentation. It does not migrate existing run directories or rewrite source run evidence.

## Rollback

1. Keep the Task 10 closeout packet and any failed/positive test logs; do not rewrite historical receipt or pack bytes.
2. Revert only the Task 7–10 plan-owned paths from the checkpoint commit boundary, including the Run Pack source, tests, `scripts/verify-run-pack.sh`, `README.md`, `docs/capability-status.md`, and Task 5.5 Run Pack receipts.
3. Do not use `git clean`, `git reset --hard`, or broad staging to remove unrelated pre-existing paths.
4. Re-run the workspace and focused gate matrix after rollback.

## Quarantine triggers

Immediately quarantine the active change rather than publish or broaden claims if verification consults a source run or ambient state, replay invokes an executor/provider/tool/MCP/scheduler/network path, a non-successful lifecycle can export successfully, a manifest/report overrides receipt evidence, a traversal/symlink is accepted, or atomic no-replace publication is weakened.

## Current external-effect state

No commit, push, merge, release, deployment, service activation, provider credential change, or network effect was performed by this closeout.
