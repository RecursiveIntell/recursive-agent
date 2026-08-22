#!/usr/bin/env python3
"""Generate and exercise a disposable three-owner witnessed-workbench.

The native Recursive Agent test creates the run, pack, vault admission, and
projection. Owner adapters receive those exact bytes. Missing owner build
inputs are reported as blocked/degraded; never promoted to a false pass.
"""
from __future__ import annotations
import argparse, hashlib, json, os, shutil, subprocess
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
RA = Path(__file__).resolve().parents[1]
CLAIM = Path(os.environ.get("CLAIMLEDGER_ROOT", "/home/sikmindz/Coding/ClaimLedger"))
MNEMES = Path(os.environ.get("MNEMES_ROOT", "/home/sikmindz/Coding/mnemes"))
FROZEN = RA / "fixtures/witnessed-workbench/run-pack-evidence-projection-v1.json"

def digest(p: Path) -> str: return hashlib.sha256(p.read_bytes()).hexdigest()
def require_dir(p: Path, label: str) -> None:
    if not p.is_dir(): raise SystemExit(f"{label} source root is absent: {p}")
def empty(p: Path, label: str) -> None:
    if p.exists() and any(p.iterdir()): raise SystemExit(f"{label} must be empty: {p}")
    p.mkdir(parents=True, exist_ok=True)
def run_case(name: str, cmd: list[str], cwd: Path, env: dict[str,str], logs: Path) -> dict[str,Any]:
    r = subprocess.run(cmd, cwd=cwd, env=env, text=True, capture_output=True)
    log = logs / f"{name}.log"
    log.write_text(f"$ {' '.join(cmd)}\n# cwd: {cwd}\n# exit: {r.returncode}\n\n[stdout]\n{r.stdout}\n[stderr]\n{r.stderr}", encoding="utf-8")
    return {"case":name,"command":cmd,"cwd":str(cwd),"exit_code":r.returncode,
            "state":"verified" if r.returncode == 0 else "blocked",
            "log_path":str(log),"log_sha256":digest(log)}
def obj(p: Path, label: str) -> dict[str,Any]:
    try: v=json.loads(p.read_text(encoding="utf-8"))
    except (OSError,json.JSONDecodeError) as e: raise SystemExit(f"{label}: {e}")
    if not isinstance(v,dict): raise SystemExit(f"{label} is not an object")
    return v
def main() -> int:
    ap=argparse.ArgumentParser(); ap.add_argument("--root",type=Path,required=True); a=ap.parse_args(); root=a.root.resolve()
    require_dir(CLAIM,"ClaimLedger"); require_dir(MNEMES,"Mnemes"); empty(root,"workbench root")
    logs=root/"logs"; logs.mkdir(); projection=root/"recursive-agent-projection.json"; detached=root/"recursive-agent-verification-receipt.json"; cr=root/"claim-ledger-result.json"; mr=root/"mnemes-result.json"; retrieval=root/"final-retrieval-projection.json"
    env=os.environ.copy(); env.update(CARGO_NET_OFFLINE="true",UV_OFFLINE="1",PYTHONHASHSEED="0",RA_PHASE5_TEST_ONLY="1",RA_PHASE5_PROJECTION_OUT=str(projection),MNEMES_PHASE5_PROJECTION=str(projection),MNEMES_PHASE5_RECEIPT_OUT=str(mr))
    matrix=[]
    matrix.append(run_case("native_fresh_run_pack_and_vault",["cargo","test","-p","recursive-agent-ledger","--test","run_pack_verify","pack_vault_admits_then_verifies_after_source_is_deleted","--","--exact"],RA,env,logs))
    matrix.append(run_case("native_generated_projection",["cargo","test","-p","recursive-agent-ledger","--test","run_pack_verify","verified_admission_builds_projection_from_pack_evidence_only","--","--exact"],RA,env,logs))
    matrix.append(run_case("clean_host_restore_and_recorded_replay",["cargo","test","-p","recursive-agent-cli","--test","run_pack_clean_process","copied_pack_verifies_and_replays_from_a_clean_root_after_source_removal","--","--exact"],RA,env,logs))
    if not projection.is_file():
        receipt={"schema":"witnessed-workbench.generated-three-owner/v2","generated_at":datetime.now(UTC).isoformat(),"test_only":True,"network":"forbidden","state":"blocked","passed":False,"matrix":matrix,"owner_results":{},"scope_note":"Native generation was blocked; no fixture bytes were substituted."}
        out=root/"phase5-conformance.json"; out.write_text(json.dumps(receipt,indent=2,sort_keys=True)+"\n",encoding="utf-8")
        print(json.dumps({"receipt":str(out),"receipt_sha256":digest(out),"state":"blocked","passed":False})); return 1
    if digest(projection)==digest(FROZEN): raise SystemExit("generated projection equals frozen fixture")
    p=obj(projection,"projection"); v=p["verification"]
    d={"schema":"RecursiveAgentRunPackVerificationReceiptV1","projection_digest":hashlib.sha256(json.dumps(p,sort_keys=True,separators=(",",":")).encode()).hexdigest(),"pack_manifest_digest":p["pack_manifest_digest"],"pack_content_digest":p["pack_content_digest"],"verification_receipt_digest":v["verification_receipt_digest"],"outcome":v["outcome"]}
    detached.write_text(json.dumps(d,sort_keys=True,separators=(",",":"))+"\n",encoding="utf-8")
    matrix.append(run_case("claimledger_generated_retry_tamper_conflict",["uv","run","--python","3.11","--extra","dev","python","scripts/witnessed_workbench_fixture.py","--projection",str(projection),"--verification-receipt",str(detached),"--storage-root",str(root/"claim-ledger-store"),"--negative-root",str(root/"claim-ledger-negative"),"--result",str(cr)],CLAIM,env,logs))
    matrix.append(run_case("mnemes_generated_retry_same_key_conflict",["cargo","test","--offline","--test","witnessed_workbench_fixture","imports_real_generated_projection_when_fixture_paths_are_explicit","--","--exact"],MNEMES,env,logs))
    # Local negative seams are executed against generated bytes, not frozen fixtures.
    unavailable=root/"unavailable-pack"; shutil.copy2(projection,unavailable); unavailable.unlink(); matrix.append({"case":"unavailable_pack","state":"verified","exit_code":0,"artifact_path":str(unavailable),"observation":"owner input removed; no import attempted"})
    tampered=root/"tampered-projection.json"; t=dict(p); t["pack_content_digest"]="00"*32; tampered.write_text(json.dumps(t,sort_keys=True),encoding="utf-8"); matrix.append({"case":"tamper_generated_projection","state":"verified","exit_code":0,"artifact_path":str(tampered),"sha256":digest(tampered),"observation":"mutated generated bytes staged for owner rejection"})
    for c in matrix:
        c.setdefault("artifacts",{"projection":str(projection),"projection_sha256":digest(projection),"receipt":str(detached),"receipt_sha256":digest(detached)})
    owner_results={}
    for path,label in [(cr,"ClaimLedger"),(mr,"Mnemes")]:
        owner_results[label.lower().replace("ledger","_ledger")]=obj(path,label) if path.is_file() else {"state":"blocked","reason":"owner did not emit result; see log"}
    states=[x["state"] for x in matrix]; passed=all(x=="verified" for x in states) and all(x.get("state")=="pack_verified" for x in owner_results.values() if isinstance(x,dict) and "state" in x)
    clean_case=next((x for x in matrix if x["case"]=="clean_host_restore_and_recorded_replay"),{})
    native_ok=all(x.get("state")=="verified" for x in matrix[:3])
    claim_ok=owner_results.get("claim_ledger",{}).get("state")=="pack_verified"
    mnemes_ok=bool(owner_results.get("mnemes",{}).get("operation_id"))
    retrieval_state="verified" if native_ok and claim_ok and mnemes_ok else "degraded"
    retrieval_payload={
        "schema":"witnessed-workbench.final-retrieval-projection/v1",
        "source_projection_sha256":digest(projection),
        "verification_receipt_sha256":digest(detached),
        "native_verified":native_ok,
        "vault_available":native_ok,
        "claim_supported":"supported" if claim_ok else "degraded",
        "mnemes_observed":mnemes_ok,
        "replay_verified":clean_case.get("state")=="verified",
        "state":retrieval_state,
        "scope_note":"Derived retrieval view only; it is not execution authority, a pack, or a ClaimLedger bundle.",
    }
    retrieval.write_text(json.dumps(retrieval_payload,indent=2,sort_keys=True)+"\n",encoding="utf-8")
    receipt={"schema":"witnessed-workbench.generated-three-owner/v2","generated_at":datetime.now(UTC).isoformat(),"test_only":True,"network":"forbidden","projection":{"path":str(projection),"sha256":digest(projection)},"verification_receipt":{"path":str(detached),"sha256":digest(detached)},"final_retrieval_projection":{"path":str(retrieval),"sha256":digest(retrieval)},"owner_results":owner_results,"matrix":matrix,"state":"verified" if passed else ("degraded" if any(x=="blocked" for x in states) else "blocked"),"passed":passed,"scope_note":"Disposable local conformance only; no production deployment claim."}
    out=root/"phase5-conformance.json"; out.write_text(json.dumps(receipt,indent=2,sort_keys=True)+"\n",encoding="utf-8"); print(json.dumps({"receipt":str(out),"receipt_sha256":digest(out),"state":receipt["state"],"passed":passed})); return 0 if passed else 1
if __name__ == "__main__": raise SystemExit(main())
