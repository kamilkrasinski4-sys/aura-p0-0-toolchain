#!/usr/bin/env python3
"""Strict semantic validator for the AURA P0-0 flat manifest contract."""
from __future__ import annotations
import argparse, hashlib, json, os, re, sys
from pathlib import Path
from urllib.parse import parse_qs, urlparse
try:
    import jsonschema
except ImportError:
    print("FATAL: dependency 'jsonschema' is not installed", file=sys.stderr)
    raise SystemExit(2)

EXPECTED_REPOSITORIES = {
    "Aura-vNEXT", "Aura-Guard", "Crystal-panel-Aura-Protection", "aura-guard-v1.3",
    "aura-specification", "Aura-Conformance-Kit", "Authority", "inclusion",
    "acode-plugin-docs", "acodex_server", "termux-packages", "Aura-Release-Management",
    "aura-poc-a-core-v3.3",
}
API_ENDPOINT_PATHS = {"workflows": "actions/workflows", "actions_runs": "actions/runs", "releases": "releases", "tags": "tags", "issues_prs": "issues"}
API_ENDPOINT_REQUIRED_QUERY = {"issues_prs": {"state": "all"}}
API_ENDPOINTS = {
    "workflows": ("workflows.json", "workflows"),
    "actions_runs": ("actions_runs.json", "workflow_runs"),
    "releases": ("releases.json", None),
    "tags": ("tags.json", None),
    "issues_prs": ("issues_prs.json", None),
}
HEX64 = re.compile(r"^[0-9a-f]{64}$")

class ValidationFailure(Exception):
    pass

def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()

def fail(message: str) -> None:
    raise ValidationFailure(message)

def safe_snapshot_file(snapshot: Path, relative: str) -> Path:
    p = Path(relative)
    if p.is_absolute() or ".." in p.parts:
        fail(f"Unsafe relative evidence path: {relative!r}")
    target = (snapshot / p).resolve()
    root = snapshot.resolve()
    if target != root and root not in target.parents:
        fail(f"Evidence path escapes snapshot directory: {relative!r}")
    if not target.is_file():
        fail(f"Required evidence file is missing: {relative}")
    return target

def load_json(path: Path, label: str):
    try:
        with path.open("r", encoding="utf-8") as f:
            return json.load(f)
    except Exception as exc:
        fail(f"Invalid JSON in {label}: {exc}")

def extract_records(payload, array_key: str | None, label: str) -> tuple[list, int | None]:
    if array_key is None:
        if not isinstance(payload, list):
            fail(f"{label} must be a JSON array")
        return payload, None
    if not isinstance(payload, dict) or not isinstance(payload.get(array_key), list):
        fail(f"{label} must be an object containing array {array_key!r}")
    total = payload.get("total_count")
    if isinstance(total, bool) or not isinstance(total, int) or total < 0:
        fail(f"{label}.total_count must be a non-negative integer")
    return payload[array_key], total

def parse_link_next(link_header: str | None) -> str | None:
    if not link_header:
        return None
    # GitHub's Link field contains comma-separated link-values. Only the rel="next" target matters.
    for piece in link_header.split(","):
        m = re.search(r"<([^>]+)>\s*;\s*rel\s*=\s*\"?next\"?", piece, flags=re.I)
        if m:
            return m.group(1)
    return None

def validate_trace(snapshot: Path, repo_name: str, endpoint_key: str, endpoint_file: Path,
                   api: dict, paginated: bool) -> None:
    aggregate_name, array_key = API_ENDPOINTS[endpoint_key]
    count_key = f"{endpoint_key}_record_count"
    page_key = f"{endpoint_key}_page_count"
    trace_file_key = f"{endpoint_key}_pagination_trace_file"
    trace_sha_key = f"{endpoint_key}_pagination_trace_sha256"
    if api.get(f"{endpoint_key}_pagination_complete") is not True:
        fail(f"{repo_name}/{endpoint_key}: pagination_complete is not true")
    rel_trace = api.get(trace_file_key)
    trace_path = safe_snapshot_file(snapshot, rel_trace)
    if sha256_file(trace_path) != api.get(trace_sha_key):
        fail(f"{repo_name}/{endpoint_key}: pagination trace SHA-256 mismatch")
    trace = load_json(trace_path, rel_trace)
    if not isinstance(trace, dict) or trace.get("endpoint_key") != endpoint_key:
        fail(f"{repo_name}/{endpoint_key}: malformed trace or endpoint_key mismatch")
    if trace.get("repository_name") != repo_name or trace.get("aggregate_file") != aggregate_name:
        fail(f"{repo_name}/{endpoint_key}: trace identity does not match manifest")
    pages = trace.get("pages")
    if not isinstance(pages, list) or not pages:
        fail(f"{repo_name}/{endpoint_key}: trace must contain at least one page")
    if trace.get("page_count") != len(pages) or api.get(page_key) != len(pages):
        fail(f"{repo_name}/{endpoint_key}: page_count does not match trace")
    if trace.get("record_count") != api.get(count_key):
        fail(f"{repo_name}/{endpoint_key}: trace record_count does not match manifest")

    flattened: list = []
    wrapper_total = None
    for i, page in enumerate(pages):
        if not isinstance(page, dict):
            fail(f"{repo_name}/{endpoint_key}: page {i+1} is not an object")
        if page.get("http_status") != 200:
            fail(f"{repo_name}/{endpoint_key}: page {i+1} HTTP status is not 200")
        url = page.get("request_url")
        parsed = urlparse(url or "")
        production_origin = parsed.scheme == "https" and parsed.hostname == "api.github.com" and parsed.port is None
        test_origin = (os.environ.get("AURA_TEST_MODE") == "1" and parsed.scheme == "http" and
                       parsed.hostname in {"127.0.0.1", "localhost", "::1"} and parsed.port is not None)
        if not (production_origin or test_origin):
            fail(f"{repo_name}/{endpoint_key}: page {i+1} URL is outside the trusted GitHub API origin")
        expected_path = f"/repos/vaidt/{repo_name}/{API_ENDPOINT_PATHS[endpoint_key]}"
        if parsed.path != expected_path:
            fail(f"{repo_name}/{endpoint_key}: unexpected API path {parsed.path!r}; expected {expected_path!r}")
        query = parse_qs(parsed.query)
        if query.get("per_page") != ["100"]:
            fail(f"{repo_name}/{endpoint_key}: per_page must be 100 on every captured page")
        for required_key, required_value in API_ENDPOINT_REQUIRED_QUERY.get(endpoint_key, {}).items():
            if query.get(required_key) != [required_value]:
                fail(f"{repo_name}/{endpoint_key}: every request URL must explicitly preserve {required_key}={required_value}")
        expected_page = str(i + 1)
        if query.get("page", ["1"])[0] != expected_page:
            fail(f"{repo_name}/{endpoint_key}: expected page={expected_page} in pagination chain")
        body_rel, headers_rel = page.get("body_file"), page.get("headers_file")
        body_path = safe_snapshot_file(snapshot, body_rel)
        headers_path = safe_snapshot_file(snapshot, headers_rel)
        if sha256_file(body_path) != page.get("body_sha256"):
            fail(f"{repo_name}/{endpoint_key}: raw page body hash mismatch on page {i+1}")
        if sha256_file(headers_path) != page.get("headers_sha256"):
            fail(f"{repo_name}/{endpoint_key}: raw page headers hash mismatch on page {i+1}")
        headers_text = headers_path.read_text(encoding="utf-8", errors="replace")
        if not re.search(r"^HTTP/\S+\s+200(?:\s|$)", headers_text, re.M):
            fail(f"{repo_name}/{endpoint_key}: raw headers do not contain HTTP 200 for page {i+1}")
        raw_links = []
        for line in headers_text.splitlines():
            if line.lower().startswith("link:"):
                raw_links.append(line.split(":", 1)[1].strip())
        link_header = ", ".join(raw_links) if raw_links else None
        if link_header != page.get("link_header"):
            fail(f"{repo_name}/{endpoint_key}: trace Link header differs from raw response headers on page {i+1}")
        actual_next = parse_link_next(link_header)
        if actual_next != page.get("next_url"):
            fail(f"{repo_name}/{endpoint_key}: next URL does not agree with Link header on page {i+1}")
        if i < len(pages) - 1:
            if not actual_next or actual_next != pages[i+1].get("request_url"):
                fail(f"{repo_name}/{endpoint_key}: broken pagination chain between pages {i+1} and {i+2}")
        elif actual_next is not None:
            fail(f"{repo_name}/{endpoint_key}: final page still advertises rel=next")
        payload = load_json(body_path, body_rel)
        records, total = extract_records(payload, array_key, body_rel)
        if page.get("record_count") != len(records):
            fail(f"{repo_name}/{endpoint_key}: raw page record_count mismatch on page {i+1}")
        if array_key is not None:
            if total is None:
                fail(f"{repo_name}/{endpoint_key}: total_count missing")
            if wrapper_total is None:
                wrapper_total = total
            elif total != wrapper_total:
                fail(f"{repo_name}/{endpoint_key}: total_count changed across pages")
        flattened.extend(records)

    if len(flattened) != api.get(count_key):
        fail(f"{repo_name}/{endpoint_key}: actual raw-page count does not match manifest")
    if array_key is not None and wrapper_total != len(flattened):
        fail(f"{repo_name}/{endpoint_key}: total_count {wrapper_total} does not match captured record count {len(flattened)}")
    if len(flattened) != trace.get("record_count"):
        fail(f"{repo_name}/{endpoint_key}: flattened trace record count mismatch")

    # Reconstruct aggregate deterministically and require byte-semantic JSON equality.
    aggregated = load_json(endpoint_file, str(endpoint_file))
    if array_key is None:
        expected_aggregate = flattened
    else:
        expected_aggregate = {"total_count": wrapper_total, array_key: flattened}
    if aggregated != expected_aggregate:
        fail(f"{repo_name}/{endpoint_key}: aggregate JSON differs from concatenated raw pages")


def validate_manifest(schema_path: Path, manifest_path: Path, snapshot: Path) -> None:
    if not schema_path.is_file() or not manifest_path.is_file() or not snapshot.is_dir():
        fail("Schema, manifest, or snapshot path does not exist")
    schema = load_json(schema_path, "schema")
    manifest = load_json(manifest_path, "manifest")
    try:
        validator_cls = jsonschema.validators.validator_for(schema)
        validator_cls.check_schema(schema)
        validator = validator_cls(schema, format_checker=jsonschema.FormatChecker())
        validator.validate(manifest)
    except jsonschema.ValidationError as exc:
        fail(f"JSON Schema validation failed at {list(exc.path)}: {exc.message}")
    except Exception as exc:
        fail(f"Schema initialization failed: {exc}")

    timestamp = manifest.get("capture_timestamp_utc", "")
    if not isinstance(timestamp, str) or not timestamp.endswith("Z"):
        fail("capture_timestamp_utc must be expressed in UTC using the RFC 3339 Z suffix")

    declared_artifact = manifest.get("schema_artifact", {})
    if declared_artifact.get("file_name") != schema_path.name:
        fail(f"Schema artifact name mismatch: manifest={declared_artifact.get('file_name')!r}, actual={schema_path.name!r}")
    actual_schema_sha = sha256_file(schema_path)
    if actual_schema_sha != declared_artifact.get("sha256"):
        fail("R14: actual schema SHA-256 does not match schema_artifact.sha256")

    repos = manifest.get("repositories", [])
    names = [r.get("repository_name") for r in repos]
    if len(repos) != 13 or len(set(names)) != 13 or set(names) != EXPECTED_REPOSITORIES:
        missing = sorted(EXPECTED_REPOSITORIES - set(names))
        extra = sorted(set(names) - EXPECTED_REPOSITORIES)
        fail(f"R18: repository set must be exactly 13 unique names; missing={missing}, extra={extra}, count={len(names)}")

    for r in repos:
        name = r["repository_name"]
        if r.get("repository_full_name") != f"vaidt/{name}":
            fail(f"{name}: repository_full_name is not canonical")
        if r.get("source_git_url") != f"https://github.com/vaidt/{name}.git":
            fail(f"{name}: source_git_url is not canonical")
        up = r["upstream_analysis"]
        if not r["is_fork"]:
            if up.get("upstream_tracked") is not False or up.get("delta_status") != "NOT_A_FORK":
                fail(f"{name}: non-fork must have upstream_tracked=false and delta_status=NOT_A_FORK")
            if any(up.get(k) is not None for k in ("upstream_repo", "upstream_default_branch", "upstream_metadata_json_sha256", "ahead_count", "behind_count")):
                fail(f"{name}: non-fork must not claim upstream metadata or delta counts")
        else:
            if up.get("upstream_tracked") is not True or up.get("delta_status") == "NOT_A_FORK":
                fail(f"{name}: fork has inconsistent upstream tracking/delta status")
            if up.get("delta_status") in {"ZERO_DELTA", "FORK_AHEAD", "UPSTREAM_AHEAD", "DIVERGED"}:
                if not isinstance(up.get("upstream_repo"), str) or not isinstance(up.get("upstream_default_branch"), str):
                    fail(f"{name}: resolved upstream status requires upstream repository and default branch")
                if not isinstance(up.get("ahead_count"), int) or not isinstance(up.get("behind_count"), int):
                    fail(f"{name}: resolved upstream status requires integer ahead/behind counts")
                ahead, behind = up["ahead_count"], up["behind_count"]
                expected_delta = "ZERO_DELTA" if ahead == 0 and behind == 0 else "FORK_AHEAD" if ahead > 0 and behind == 0 else "UPSTREAM_AHEAD" if ahead == 0 and behind > 0 else "DIVERGED"
                if up.get("delta_status") != expected_delta:
                    fail(f"{name}: delta_status disagrees with ahead_count/behind_count")
        api_dir = snapshot / "api_snapshots" / name
        metadata = safe_snapshot_file(snapshot, f"api_snapshots/{name}/metadata.json")
        if sha256_file(metadata) != r["github_api_artifacts"]["metadata_json_sha256"]:
            fail(f"{name}: metadata.json SHA-256 mismatch")
        meta = load_json(metadata, str(metadata))
        if meta.get("clone_url") not in (None, f"https://github.com/vaidt/{name}.git"):
            fail(f"{name}: metadata.json clone_url is not canonical")
        for manifest_field, meta_field in [("repository_full_name", "full_name"), ("default_branch", "default_branch"), ("is_fork", "fork"), ("visibility", "visibility")]:
            expected = r.get(manifest_field)
            actual = meta.get(meta_field, False if meta_field == "fork" else None)
            if actual != expected:
                fail(f"{name}: manifest {manifest_field}={expected!r} does not match metadata.json {meta_field}={actual!r}")
        if r["is_fork"] and r["upstream_analysis"].get("upstream_metadata_json_sha256") is not None:
            up_info=r["upstream_analysis"]
            up_meta_path=safe_snapshot_file(snapshot,f"api_snapshots/{name}/upstream_meta.json")
            if sha256_file(up_meta_path) != up_info.get("upstream_metadata_json_sha256"):
                fail(f"{name}: upstream metadata SHA-256 mismatch")
            up_meta=load_json(up_meta_path,str(up_meta_path))
            if up_meta.get("full_name") != up_info.get("upstream_repo") or up_meta.get("default_branch") != up_info.get("upstream_default_branch"):
                fail(f"{name}: upstream metadata does not match upstream_analysis declaration")
        api = r["github_api_artifacts"]
        for key, (filename, array_key) in API_ENDPOINTS.items():
            target = safe_snapshot_file(snapshot, f"api_snapshots/{name}/{filename}")
            sha_field = f"{key}_json_sha256"
            if sha256_file(target) != api.get(sha_field):
                fail(f"{name}/{filename}: SHA-256 mismatch against manifest")
            validate_trace(snapshot, name, key, target, api, paginated=True)
        # Metadata URL relationship and canonical repo identity are separately checked above.
    print("PASS: JSON Schema, exact repository set, schema binding, metadata correlation, API hashes, pagination chain, raw-page hashes and record counts")

def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--schema", required=True, type=Path)
    parser.add_argument("--manifest", required=True, type=Path)
    parser.add_argument("--snapshot-dir", required=True, type=Path)
    args = parser.parse_args()
    try:
        validate_manifest(args.schema.resolve(), args.manifest.resolve(), args.snapshot_dir.resolve())
        return 0
    except ValidationFailure as exc:
        print(f"FAIL: {exc}", file=sys.stderr)
        return 1
    except Exception as exc:
        print(f"FAIL: unexpected validator error: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 2
if __name__ == '__main__':
    raise SystemExit(main())
