#!/usr/bin/env python3
"""Independent formal verifier for an AURA P0-0 evidence snapshot."""
from __future__ import annotations
import argparse, hashlib, json, os, re, shutil, subprocess, sys, tempfile
from pathlib import Path
from p0_0_manifest_validate import validate_manifest, ValidationFailure, sha256_file, load_json, safe_snapshot_file

class VerifyFailure(Exception):
    pass

def fail(message: str):
    raise VerifyFailure(message)

def run(cmd: list[str], *, check=False, cwd: Path | None=None):
    p = subprocess.run(cmd, cwd=str(cwd) if cwd else None, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    if check and p.returncode != 0:
        fail(f"Command failed ({p.returncode}): {' '.join(cmd)}\n{p.stdout[-2000:]}")
    return p

def refs_text(repo: Path) -> str:
    p = run(["git", "-C", str(repo), "for-each-ref", "--format=%(refname) %(objectname)"])
    if p.returncode:
        fail(f"git for-each-ref failed in {repo}: {p.stdout}")
    return "".join(x + "\n" for x in sorted(p.stdout.splitlines(), key=lambda s: s.encode("utf-8")))

def fsck(repo: Path) -> tuple[str, int, bool, str]:
    p = run(["git", "-C", str(repo), "fsck", "--full", "--no-reflogs", "--unreachable"])
    out = p.stdout
    unreachable = bool(re.search(r"(?:^|\n)(?:unreachable|dangling)\s+", out, re.I))
    if p.returncode != 0:
        status = "CORRUPTED"
    elif unreachable:
        status = "HAS_UNREACHABLE_OBJECTS"
    elif re.search(r"(?:^|\n)(?:error|fatal|missing|broken)\b", out, re.I):
        status = "ERROR"
    else:
        status = "CLEAN"
    return status, p.returncode, unreachable, out

def verify_signature(manifest: Path, allowed_signers: Path, principal: str, namespace: str, auditor_identity: str):
    if not allowed_signers.is_file():
        fail("R10: required allowed_signers file is missing")
    if not principal.strip() or not namespace.strip():
        fail("R10: principal and namespace are mandatory in formal profile")
    if auditor_identity != principal:
        fail(f"R10: auditor_identity {auditor_identity!r} must equal verified SIGNER_PRINCIPAL {principal!r}")
    sig = Path(str(manifest) + ".sig")
    if not sig.is_file():
        fail(f"R10: required manifest signature is missing: {sig.name}")
    with manifest.open("rb") as signed_input:
        p = subprocess.run(["ssh-keygen", "-Y", "verify", "-f", str(allowed_signers), "-I", principal, "-n", namespace, "-s", str(sig)], stdin=signed_input, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    if p.returncode != 0:
        fail(f"R10: OpenSSH signature verification failed for principal={principal!r}, namespace={namespace!r}: {p.stdout[-1000:]}")

def verify_git(snapshot: Path, manifest: dict):
    restore_root = Path(tempfile.mkdtemp(prefix="aura_p0_restore_"))
    try:
        for r in manifest["repositories"]:
            name = r["repository_name"]
            src = snapshot / "git_source_mirrors" / f"{name}.git"
            bundle_info = r["git_bundle"]
            if Path(bundle_info["file_name"]).name != bundle_info["file_name"]:
                fail(f"{name}: bundle file_name must be a basename")
            bundle = snapshot / "git_bundles" / name / bundle_info["file_name"]
            refs_file = snapshot / "git_bundles" / name / "source_refs.txt"
            if not src.is_dir(): fail(f"{name}: source mirror is missing: {src}")
            if not bundle.is_file(): fail(f"{name}: bundle is missing: {bundle}")
            if not refs_file.is_file(): fail(f"{name}: source_refs.txt is missing")
            if sha256_file(bundle) != bundle_info["sha256"]: fail(f"{name}: bundle SHA-256 mismatch")
            if bundle.stat().st_size != bundle_info["size_bytes"]: fail(f"{name}: bundle size_bytes mismatch")
            if sha256_file(refs_file) != r["git_refs_sha256"]: fail(f"{name}: git_refs_sha256 does not match source_refs.txt")

            source_refs = refs_text(src)
            saved_refs = refs_file.read_text(encoding="utf-8")
            if source_refs != saved_refs: fail(f"{name}: source mirror refs do not match source_refs.txt")
            if hashlib.sha256(source_refs.encode("utf-8")).hexdigest() != r["git_refs_sha256"]:
                fail(f"{name}: source mirror ref digest mismatch")

            source_fsck_status, source_fsck_exit, source_unreachable, source_out = fsck(src)
            declared = r["git_restoration_check"]
            if declared.get("source_fsck_status") != source_fsck_status or declared.get("source_fsck_exit_code") != source_fsck_exit or declared.get("source_unreachable_objects_detected") != source_unreachable:
                fail(f"{name}: manifest source fsck fields differ from independent source fsck")
            if source_fsck_status != "CLEAN" or source_unreachable:
                fail(f"R13: source mirror {name} failed strict fsck policy: status={source_fsck_status}; output={source_out[-1000:]}")

            bverify = run(["git", "-C", str(src), "bundle", "verify", str(bundle)])
            if bverify.returncode != 0 or bundle_info.get("bundle_verify_status") != "PASS":
                fail(f"{name}: independent git bundle verify failed or manifest status is not PASS: {bverify.stdout[-1000:]}")

            dst = restore_root / f"{name}.git"
            clone = run(["git", "clone", "--mirror", "--quiet", str(bundle), str(dst)])
            if clone.returncode != 0: fail(f"{name}: independent clone from bundle failed: {clone.stdout[-1000:]}")
            restored_refs = refs_text(dst)
            if restored_refs != saved_refs: fail(f"{name}: restored refs do not match frozen source refs")
            if declared.get("reference_match_status") != "EXACT_MATCH": fail(f"{name}: manifest reference_match_status is not EXACT_MATCH")

            restored_fsck_status, restored_fsck_exit, restored_unreachable, restored_out = fsck(dst)
            if declared.get("fsck_status") != restored_fsck_status or declared.get("fsck_exit_code") != restored_fsck_exit or declared.get("unreachable_objects_detected") != restored_unreachable:
                fail(f"{name}: manifest restoration fsck fields differ from independently computed values")
            if restored_fsck_status != "CLEAN" or restored_unreachable:
                fail(f"R13: restored repository {name} failed strict fsck policy: status={restored_fsck_status}; output={restored_out[-1000:]}")

            branch = r["default_branch"]
            head = run(["git", "-C", str(dst), "rev-parse", f"refs/heads/{branch}"])
            if head.returncode != 0: fail(f"{name}: default branch refs/heads/{branch} is missing")
            if head.stdout.strip() != r["head_commit_sha"]: fail(f"{name}: head_commit_sha mismatch against restored default branch")
            count = run(["git", "-C", str(dst), "rev-list", "--count", f"refs/heads/{branch}"])
            if count.returncode != 0 or count.stdout.strip() != str(r["total_commits_on_default_branch"]):
                fail(f"{name}: total_commits_on_default_branch mismatch")
    finally:
        shutil.rmtree(restore_root, ignore_errors=True)

def verify(snapshot: Path, schema: Path, allowed: Path, principal: str, namespace: str):
    snapshot = snapshot.resolve(); schema = schema.resolve(); allowed = allowed.resolve()
    if os.environ.get("AURA_TEST_MODE") == "1": fail("formal verifier refuses AURA_TEST_MODE=1")
    if not snapshot.is_dir(): fail("snapshot directory does not exist")
    if allowed == snapshot or snapshot in allowed.parents:
        fail("R10: allowed_signers must be supplied from outside the evidence snapshot")
    manifest = snapshot / "evidence_manifest.json"
    sidecar = snapshot / "evidence_manifest.json.sha256"
    if not manifest.is_file() or not sidecar.is_file(): fail("manifest or relative SHA-256 sidecar is missing")
    sidecar_lines = sidecar.read_text(encoding="utf-8").splitlines()
    if len(sidecar_lines) != 1 or not re.fullmatch(r"[0-9a-f]{64}\s+\*?evidence_manifest\.json", sidecar_lines[0]):
        fail("manifest checksum sidecar must contain exactly one relative evidence_manifest.json entry")
    expected = sidecar_lines[0].split()[0]
    if sha256_file(manifest) != expected: fail("manifest SHA-256 sidecar mismatch")

    validate_manifest(schema, manifest, snapshot)
    data = load_json(manifest, "evidence_manifest.json")
    if data.get("capture_status") != "CAPTURE_COMPLETED": fail("formal profile refuses capture_status other than CAPTURE_COMPLETED")
    verify_signature(manifest, allowed, principal, namespace, data.get("auditor_identity", ""))
    verify_git(snapshot, data)
    print("PASS: formal AURA P0-0 snapshot verified: schema, signature, API artifacts/pagination, source/restored Git, refs and commit metadata")

def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--snapshot-dir", required=True, type=Path)
    p.add_argument("--schema", required=True, type=Path)
    p.add_argument("--allowed-signers", required=True, type=Path)
    p.add_argument("--principal", required=True)
    p.add_argument("--namespace", required=True)
    a = p.parse_args()
    try:
        verify(a.snapshot_dir, a.schema, a.allowed_signers, a.principal, a.namespace)
        return 0
    except (VerifyFailure, ValidationFailure) as exc:
        print(f"FAIL: {exc}", file=sys.stderr)
        return 1
    except Exception as exc:
        print(f"FAIL: unexpected verifier error: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 2
if __name__ == '__main__':
    raise SystemExit(main())
