# Retirement observer repair: temporary sensitivity qualification

Do not merge this diagnostic phase. It contains explicit synthetic-request fault hooks solely to establish negative-test sensitivity. Final delivery must remove all instrumentation/fault hooks and repetition scaffolding.

## Confirmed reproduction

[Hosted run36763736628, job110052530421](https://github.com/RecursiveIntell/recursive-agent/actions/runs/36763736628/job/110052530421), commit c5801b59ec51b7592a4b8d95c8851d18e29a23e8, failed repetition attempt3 of the original lost-ACK fixture:

- The unchanged five-second decision failed after401 exact durable-state polls.
- The retirement writer acquired the exclusive permit lock after5,008,347 microseconds, once that polling stopped.
- The locked operation then completed successfully at5,057,530 microseconds total; dispatch reported error=None.
- The subsequent ACK write returned Broken pipe, expected because the caller intentionally dropped its socket.
- The frozen original failure decision remained a failure, despite the late successful commit.

This reproduces observer-induced writer lock starvation in the exact fixture workload. The historical Ares run36737828471/job109964075513 had no such trace, so unique attribution of that earlier occurrence remains unproved. A later green result was never treated as repair. The first instrumented run36762721299 passed24 repetitions; the second lower-perturbation pass above supplied the falsifying evidence.

## Current temporary candidate

The fixture now waits for its sole established connection's existing runtime accounting to close, without reading the ACK or repeatedly taking the permit-store lock. It then requires exact durable transition readback and retains all restart/idempotence/settlement/old-verifier checks. The five-second deadline remains unchanged. Connection accounting is synchronization only, not persistence or authority proof.

The current diagnostic server has two synthetic test-only-purpose request IDs: one rejects retirement before dispatch; the other delays dispatch six seconds. Dedicated tests must observe the exact missing-receipt assertion and original five-second completion timeout respectively, rather than simply accepting any failure. Another bounded test repeats the repaired original fixture128 times. All existing workflow gates remain enabled.

These hooks are dangerous if retained in product source and must be removed before final qualification. No live runtime, operator store, key, enrollment, deployment, or package release is involved.

## Source and local limits

Base native main06d468adeb81883d82bb0d80ff23f60d4df3778e differs only in README from historical candidate2297e9444922ff0aef1eb21358084dbfe3e13ec4. Libraries remains0b099ec416de60f6adafb182f1d1e83795d05c56. Other open owner work is untouched.

The original and proposed IPC targets compile with Rust1.94 and locked dependencies; formatting and diff checks pass. Original policy authority tests pass13/13 locally. Full local IPC execution is blocked at Unix socket binding with EPERM despite reviewed escalation, and ptrace is also prohibited. Those restrictions were preserved. Hosted tests supply the IPC evidence. Disposable policy-only probes supported contention as a lead but were not presented as IPC reproduction.
