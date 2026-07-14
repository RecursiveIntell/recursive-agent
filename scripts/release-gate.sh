#!/usr/bin/env bash
# M0 build + test gate. All output captured for receipts.
set -euo pipefail

cd "$(dirname "$0")/.."

LOG_DIR="docs/receipts"
mkdir -p "$LOG_DIR"

run() {
    local name="$1"
    shift
    local out="$LOG_DIR/$name.log"
    echo "::group::$name"
    echo "+ $*" | tee "$out"
    if "$@" >>"$out" 2>&1; then
        echo "ok: $name"
    else
        local rc=$?
        echo "FAIL: $name (exit $rc)" | tee -a "$out"
        echo "::endgroup::"
        exit "$rc"
    fi
    echo "::endgroup::"
}

run "fmt" cargo fmt --all -- --check
run "clippy" cargo clippy --workspace --all-targets --locked -- -D warnings
run "test" cargo test --workspace --locked --all-targets --no-fail-fast

# A live run on the canned fixture.
echo "::group::ra doctor"
cargo run -q -p recursive-agent-cli -- doctor | tee "$LOG_DIR/ra-doctor.log"
echo "::endgroup::"

echo "::group::ra run fixtures/hello-run.json"
RUN_OUT=$(cargo run -q -p recursive-agent-cli -- run --spec fixtures/hello-run.json)
echo "$RUN_OUT" | tee "$LOG_DIR/ra-run.log"
RUN_DIR=$(echo "$RUN_OUT" | awk '/^run_dir:/ {print $2}')
if [ -z "${RUN_DIR:-}" ]; then
    echo "FAIL: could not parse run_dir from ra run output" >&2
    exit 1
fi
echo "::endgroup::"

echo "::group::ra verify <run-dir>"
cargo run -q -p recursive-agent-cli -- verify --run "$RUN_DIR" | tee "$LOG_DIR/ra-verify.log"
echo "::endgroup::"

echo "::group::ra replay <run-dir>"
cargo run -q -p recursive-agent-cli -- replay --run "$RUN_DIR" | tee "$LOG_DIR/ra-replay.log"
echo "::endgroup::"

# Negative test: tamper a single hex character of the second receipt's
# `prev_chain_digest` and expect non-zero exit with a precise
# divergence report.
echo "::group::negative-tamper-test"
RECEIPTS="$RUN_DIR/receipts.ndjson"
cp "$RECEIPTS" "$RUN_DIR/receipts.ndjson.clean"
python3 scripts/tamper.py "$RUN_DIR" | tee "$LOG_DIR/ra-tamper.log"
set +e
VERIFY_OUT=$(cargo run -q -p recursive-agent-cli -- verify --run "$RUN_DIR" 2>&1)
RC=$?
set -e
echo "$VERIFY_OUT" | tee "$LOG_DIR/ra-verify-tampered.log"
if [ "$RC" -eq 0 ]; then
    echo "FAIL: verify accepted tampered chain" >&2
    exit 1
fi
echo "ok: verify rejected tampered chain (exit $RC)"
# Restore the original chain so subsequent iterations of the gate are
# clean.
cp "$RUN_DIR/receipts.ndjson.clean" "$RECEIPTS"
rm "$RUN_DIR/receipts.ndjson.clean"
echo "::endgroup::"

echo "all gates green"
