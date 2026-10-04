# Closed command profile

`ra-daemon serve --closed-commands-file <owned-json> --max-concurrent 1
--root <dedicated-receipts> --socket <dedicated-private-socket>` opts into an
operator-owned list of one or two exact V1 operation envelopes. The array must
be a bounded (128 KiB), same-user, single-link mode-0600 regular file opened
without following a symlink. The file is read once; changing it requires a new
process. This is a capability canary, not a general coding-agent integration.

Each operation is one `shell` step, with actor `recursive-agent`, execute-once
intent, no frozen clocks, no network, an absolute executable, at most 3000 ms
wall time, at most 16 KiB captured output per stream, and 64 KiB admitted output
and tool-payload artifact ceilings. The entire operation must equal an approved
startup template before admission or scheduler persistence. Altering argv,
roots, actor, causality, provenance, budgets, clocks or replay intent is denied.

The canonical runtime and prepared Bubblewrap dispatcher own execution,
permits, stdout/stderr observations, exit status and receipt verification.
The descriptor never executes a subprocess itself. This profile threads the
single operation's admitted budget into the existing lifecycle/effect permits;
legacy compositions retain their existing budget derivation. Oversized failed
observations retain an explicit digest/length record instead of oversized
payload bytes. That fallback applies only to this closed command path.

Parent/child, provider/autonomous execution, and external permit/context writes
are denied by this runtime facade. Daemon startup refuses audit, production
verifier, or context enrollment flags alongside a closed command profile.
The ordinary daemon remains echo plus its optional existing audit tool.

## Approval and limitations

Use fresh task-owned receipt/socket directories and a separate process. Do not
restart or reconfigure a shared daemon/service. Source review/build authorization
does not authorize launching the process, installing a persistent capability or
submitting work. At action time pin source/dependency commits, built artifact
SHA256, the exact configuration SHA256, executable/payload file hashes, socket
and receipt roots, commands and bounds. Obtain approval for those exact facts.
A health-check approval is not work approval. Never retry an uncertain accepted
submission; use its exact native run identity for documented status/verification.

16 KiB is per stream, not a combined cap. 64 KiB bounds tool output/artifact
payloads, not the aggregate size of native receipt/permit metadata or all disk
writes. The native launcher provides network socket denial, a private PID
namespace, executable-byte/root identity binding and deadline supervision.
It does not impose native CPU, memory, file-size or process-count quotas. A fixed
Python driver's RLIMITs/audit hook are application safeguards, not native proof.
Read-only input mounts do not freeze source bytes against same-user modification.
Inspect and hash any fixed payload immediately before approval/execution, report
that race explicitly, and do not claim immutable input attestation. Native runtime
mounts include `/usr`, loader metadata, `/dev` and private `/tmp`.

## Reversible deployment

Keep the shared daemon and Ares configuration untouched. The candidate process
uses only the approved private socket and receipt root. Rollback stops only that
process; preserve receipts and return to the already-installed shared client.
No systemd unit, installed plugin, global verifier key or credential change is
needed. Revert the focused source commit to remove the opt-in profile.

## Verification

The new unit tests are data-only: full-envelope tampering rejection before any
persistence, startup configuration bounds, lifecycle/effect budget binding, and
oversized failure evidence degradation. They do not launch a daemon or shell.
Existing provider and default-runtime tests must remain green. An independent
review, the paired-root build and exact action-time approval remain separate from
an actual native command receipt. Report no executed-command claim until that
command's terminal state, stdout, exit status and strict native chain verification
are observed.
