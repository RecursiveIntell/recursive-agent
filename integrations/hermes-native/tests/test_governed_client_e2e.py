"""Real V2 client -> real daemon, synthetic no-send lifecycle only."""
from datetime import datetime, timedelta, timezone
import importlib
import importlib.util
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import time

from blake3 import blake3

ROOT = Path(__file__).resolve().parents[1]
REPO = ROOT.parents[1]
SPEC = importlib.util.spec_from_file_location("native_client_e2e_package", ROOT / "__init__.py", submodule_search_locations=[str(ROOT)])
assert SPEC and SPEC.loader
package = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = package
SPEC.loader.exec_module(package)
client = importlib.import_module(SPEC.name + ".governed_client")


def test_real_v2_client_exact_begin_status_settle_and_close(tmp_path):
    binary = REPO / "target/debug/ra-daemon"
    assert binary.is_file()
    expires = (datetime.now(timezone.utc) + timedelta(minutes=10)).isoformat()
    generated = subprocess.run([str(binary), "emit-observe-egress-grant", "--ares-home", str(tmp_path),
                                "--expires-at", expires], check=True, capture_output=True, text=True)
    grant = json.loads(generated.stdout)
    assert grant["mode"] == "observe" and grant["content_retention"] == "digest_only"
    grant_file = tmp_path / "grant.json"
    grant_file.write_text(generated.stdout)
    grant_file.chmod(0o600)
    endpoint = tmp_path / "native.sock"
    with (tmp_path / "daemon-stderr.log").open("w+") as log:
        daemon = subprocess.Popen([str(binary), "serve", "--root", str(tmp_path / "runs"),
                                   "--socket", str(endpoint), "--ares-home", str(tmp_path),
                                   "--egress-grant-file", str(grant_file)], stdout=subprocess.DEVNULL,
                                  stderr=log, stdin=subprocess.DEVNULL)
        try:
            rpc = client.NativeGovernanceClient(str(endpoint), timeout=10)
            deadline = time.monotonic() + 10
            while True:
                if endpoint.exists():
                    break
                if daemon.poll() is not None or time.monotonic() >= deadline:
                    log.seek(0)
                    raise AssertionError("daemon readiness failed: " + log.read())
                time.sleep(0.02)
            opened = rpc.session_open("session:synthetic-client-fixture")
            run_id = opened["session_run_id"]
            assert rpc.session_open("session:synthetic-client-fixture")["session_run_id"] == run_id
            body = b"synthetic-not-sent"
            operation = dict(schema="recursive-agent.normal-chat/v2", conversation_ref="session:synthetic-client-fixture",
                             parent_run_id=run_id, materialization_ref="materialization:synthetic-client-fixture",
                             materialization_digest="sha256:" + "a" * 64,
                             policy_basis_ref="normal-chat-grant:revision-1", policy_basis_digest=grant["policy_digest"],
                             source_revision="source:explicit-synthetic-client-fixture", route_class="conversation",
                             provider_identity="openai_compatible:https://provider.test/v1", model_ref="model:fixture",
                             api_mode="chat_completions", request_digest="sha256:" + "b" * 64,
                             request_projection_schema="ares-json-sorted-v1",
                             budget=dict(output_reserve=10, max_wall_time_ms=10000, max_request_bytes=4096),
                             replay="unavailable", provenance=[dict(source="urn:test:synthetic-client-fixture", digest=blake3(body).hexdigest())])
            call = dict(schema="recursive-agent.normal-chat-call-request/v2", operation=operation,
                        provider_request_digest=blake3(body).hexdigest(), provider_request_bytes=len(body),
                        dispatch_intent_ref="intent:synthetic-client-fixture")
            admitted = rpc.attempt_begin(run_id, call)
            assert admitted["send_authorized"] is True
            try:
                rpc.attempt_begin(run_id, call)
            except client.DaemonGovernanceError as error:
                assert error.code == "ADMISSION_NOT_FRESH"
            else:
                raise AssertionError("historical status was promoted into send authority")
            pending = rpc.attempt_readback(run_id, call["dispatch_intent_ref"])
            assert pending["send_authorized"] is False
            assert pending["policy"]["state"] == "consumed"
            report = dict(schema="recursive-agent.normal-chat-executor-report/v2", state="not_sent",
                          duration_ms=0, response=None, usage=None)
            settled = rpc.attempt_settle(run_id, call["dispatch_intent_ref"], admitted["preflight_receipt_digest"], report)
            assert rpc.attempt_settle(run_id, call["dispatch_intent_ref"], admitted["preflight_receipt_digest"], report) == settled
            closed = rpc.run_close(run_id, "session_finalized")
            assert closed["normal_chat_status"]["outcome_evidence"] == "executor_reported"
            assert closed["normal_chat_status"]["state"] == "failed"  # lifecycle closure is not a model success.
        finally:
            daemon.terminate()
            daemon.wait(timeout=10)
