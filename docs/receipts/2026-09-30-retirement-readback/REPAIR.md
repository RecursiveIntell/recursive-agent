# Retirement lost-ACK observation: reproduced mechanism and fixture repair

## Source and scope

Base: `recursive-agent@06d468adeb81883d82bb0d80ff23f60d4df3778e`. Its executable source is identical to historical candidate `2297e9444922ff0aef1eb21358084dbfe3e13ec4`; only README differs. Libraries remains pinned to `0b099ec416de60f6adafb182f1d1e83795d05c56`. Original IPC test blob: `838275556f118bf3eeb5d97da22378fc23f85376`.

This is a fixture synchronization repair. Product daemon dispatch, policy locking/persistence, authority/signature checks, permits, and production configuration are unchanged. No live operator store, credential, enrollment, service activation, package release, or deployment is involved.

## Preserved historical failure

[Ares run 36737828471, job 109964075513](https://github.com/RecursiveIntell/Ares/actions/runs/36737828471/job/109964075513) failed the original five-second `retirement did not persist` assertion. A same-source replay was cancelled; later passing qualification was never treated as repair. That uninstrumented log proves a matching receipt was not observed by the deadline, but cannot uniquely attribute the original occurrence.

The test's independently opened reader and retirement writer both take the same exclusive flock. Each reader poll reloads and validates the complete authority state/history under that lock, then immediately tries again after `yield_now`. The observer can therefore delay the operation it is trying to observe.

## Hosted falsification

[Native run 36763736628, job 110052530421](https://github.com/RecursiveIntell/recursive-agent/actions/runs/36763736628/job/110052530421), at diagnostic commit `c5801b59ec51b7592a4b8d95c8851d18e29a23e8`, reproduced the original fixture's five-second timeout on repetition attempt 3:

- The reader completed 401 missing-receipt polls and failed the unchanged five-second decision
- After polling stopped, the retirement writer acquired the exclusive flock after 5,008,347 microseconds of waiting
- The locked operation completed at 5,057,530 microseconds total with `result_ok=true`; dispatch reported `error=None`
- The ACK write then returned the expected `Broken pipe`, because the caller deliberately dropped its stream

The diagnostic retained the fixture for 500ms only after freezing the original failure decision, so a waiting writer could report its outcome. A late commit could not make the failed gate pass. Pre-acquisition logging was removed for this pass to reduce timing perturbation. The failed run and skipped relocation remain failed/skipped.

This establishes observer-induced writer lock starvation in a reproduced instance of the real IPC fixture. It supplies a matching mechanism without claiming unique attribution of the earlier uninstrumented Ares occurrence.

Earlier evidence is retained: [run 36762721299](https://github.com/RecursiveIntell/recursive-agent/actions/runs/36762721299) passed the first 24 instrumented repetitions, which was inconclusive. Disposable real-policy-owner probes observed contention but did not reproduce the five-second IPC failure; they were leads, not substitutes for the hosted proof.

## Repair and preserved invariants

Before submission, the fixture confirms its sole established IPC connection is accounted for. It writes retirement and drops the socket without reading the ACK. It then waits for that connection's existing accounting to close, sleeping 5ms between observations and never taking the permit-store lock during the wait.

The server creates `ActiveGuard` before `handle_connection` and closes its accounting only after that synchronous handler returns. Retirement dispatch/persistence therefore finishes before this barrier closes. No other connection is opened in this fixture during the wait.

Connection accounting is synchronization only, never persistence or authority proof. After closure, the fixture independently requires the exact durable transition receipt. Rejection or a missing receipt still fails. The original five-second budget and subsequent restart readback, exact idempotence, consumed-obligation inventory, historical settlement, and old-verifier fencing assertions remain unchanged.

The repair removes observer contention rather than increasing a timeout. It does not certify fairness under arbitrary production reader load.

## Sensitivity and validation

[Run 36764722513, job 110055887291](https://github.com/RecursiveIntell/recursive-agent/actions/runs/36764722513/job/110055887291), at temporary qualification commit `6dd70fdfe6301ffc1b35ac17ad927915d53d1462`, passed:

- Original repaired lost-ACK/restart/fence fixture
- 128 repetitions of that repaired fixture
- Rejected-retirement mutation: required the exact missing-durable-receipt assertion after connection closure
- Six-second dispatch-delay mutation: required the exact five-second timeout assertion
- Existing full workspace gates and paired-root relocation

The mutation tests checked the expected failure messages, not merely any failure. All temporary server fault hooks, timing logs, and repetition scaffolding are removed from the final delivery tree. Product `server.rs` and policy `lib.rs` retain their baseline blobs.

Local Rust 1.94 validation passed: locked compilation of the IPC target, `cargo fmt --all -- --check`, targeted IPC Clippy with `-D warnings`, `git diff --check`, and all 13 original policy context-authority tests. The linker used the environment's existing libseccomp 2.6.0 through a task-local alias.

Local IPC execution is blocked at private Unix socket binding with EPERM, including reviewed escalation; ptrace is also prohibited. Those restrictions were preserved. Hosted evidence supplies runtime qualification. The final clean delivery head must independently pass the unchanged paired-root workflow; its PR checks are the exact-head receipt, separate from the temporary diagnostic/mutation runs above.

## Rollback

Revert only this fixture/document change. There is no runtime or state migration. Other open owner work is untouched, and failed, blocked, and passing attempts retain their original classifications.
