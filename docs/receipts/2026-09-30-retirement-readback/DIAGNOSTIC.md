# Diagnostic only: retirement readback timeout

Do not merge this instrumentation as a repair. Ares qualification run36737828471/job109964075513 failed the existing lost-ACK retirement test after its five-second polling deadline. A later pass is not a repair.

This temporary branch starts from native main06d468adeb81883d82bb0d80ff23f60d4df3778e. Its executable source is identical to historical candidate2297e9444922ff0aef1eb21358084dbfe3e13ec4; only README differs. Libraries remains pinned0b099ec416de60f6adafb182f1d1e83795d05c56 by the existing workflow.

The existing test still closes the socket without reading its ACK, polls the exact transition, and keeps its five-second deadline, restart/readback/idempotence/settlement/old-verifier assertions. Added observations record admission, writer lock wait/result, and reader poll count. An additional test repeats that exact fixture up to24 times, stopping on failure. No timeouts, gates, authority rules, or dependencies changed. Logging may perturb scheduling, so an observed run must be interpreted accordingly.

Local Rust1.94 compilation passed after providing a task-local linker alias to installed libseccomp2.6.0. Execution is blocked at private Unix socket binding with EPERM even with reviewed escalation; ptrace is also denied. The local gate is blocked, not passing. Hosted CI is the diagnostic execution target. No live daemon, operator store, enrollment, credential, or deployment is involved.

The lock-starvation hypothesis remains unproved until a failing attempt's admission and lock observations distinguish contention from rejection or missing dispatch. Once identified, remove diagnostic-only code and qualify the smallest repair separately. Parent review and explicit merge remain separate.

## Second bounded diagnostic pass

The first hosted run36762721299 passed the original fixture and24 repetitions, all workspace gates, and relocation. It did not reproduce or repair the historical timeout. A local policy-only probe demonstrated lock waits up to2.287s but no five-second failure in256 traced trials; an earlier untraced probe observed a4.575s readback delay. Neither is an IPC failure reproduction.

The second pass removes pre-acquisition/pre-dispatch output that could perturb scheduling and repeats the original fixture up to128 times. If the original five-second condition fails, that failure decision is frozen, polling stops, and the fixture is retained for500ms to collect any waiting writer's outcome before the unchanged failure is reported. It cannot convert a late commit into a passing gate. This is failure-time diagnostic collection, not a timeout increase.
