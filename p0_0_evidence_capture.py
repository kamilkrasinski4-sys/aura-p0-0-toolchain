#!/usr/bin/env python3
"""AURA P0-0 capture engine. Fails closed; never overwrites an existing session."""
from __future__ import annotations
import argparse, hashlib, json, os, re, shutil, subprocess, sys, uuid
from datetime import datetime, timezone
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import parse_qs, urlencode, urljoin, urlparse
from urllib.request import Request, urlopen

HERE=Path(__file__).resolve().parent
EXPECTED_REPOSITORIES=["Aura-vNEXT","Aura-Guard","Crystal-panel-Aura-Protection","aura-guard-v1.3","aura-specification","Aura-Conformance-Kit","Authority","inclusion","acode-plugin-docs","acodex_server","termux-packages","Aura-Release-Management","aura-poc-a-core-v3.3"]
API_ENDPOINTS={
 "workflows":{"path":"actions/workflows","file":"workflows.json","array_key":"workflows"},
 "actions_runs":{"path":"actions/runs","file":"actions_runs.json","array_key":"workflow_runs"},
 "releases":{"path":"releases","file":"releases.json","array_key":None},
 "tags":{"path":"tags","file":"tags.json","array_key":None},
 "issues_prs":{"path":"issues","file":"issues_prs.json","array_key":None,"query":{"state":"all"}},
}

class CaptureError(Exception): pass

def log(message: str, *, out: Path | None=None):
    line=f"[{datetime.now(timezone.utc).isoformat(timespec='seconds')}] {message}"
    print(line, flush=True)
    if out is not None:
        log_path=out/"logs"/"capture.log"
        log_path.parent.mkdir(parents=True,exist_ok=True)
        with log_path.open("a",encoding="utf-8") as f: f.write(line+"\n")

def sha_bytes(data: bytes) -> str: return hashlib.sha256(data).hexdigest()
def sha_file(path: Path) -> str:
    h=hashlib.sha256()
    with path.open("rb") as f:
        for block in iter(lambda:f.read(1024*1024),b""): h.update(block)
    return h.hexdigest()
def json_write(path: Path, obj):
    path.parent.mkdir(parents=True,exist_ok=True)
    path.write_text(json.dumps(obj,sort_keys=True,indent=2)+"\n",encoding="utf-8")

def run(cmd: list[str], *, check=True, cwd: Path | None=None, out: Path | None=None):
    p=subprocess.run([str(x) for x in cmd],cwd=str(cwd) if cwd else None,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True)
    if out is not None:
        log(f"$ {' '.join(str(x) for x in cmd)}\n{p.stdout.rstrip()}",out=out)
    if check and p.returncode:
        raise CaptureError(f"command failed ({p.returncode}): {' '.join(str(x) for x in cmd)}\n{p.stdout[-2000:]}")
    return p

def command_version(command: list[str], fallback="not-installed") -> str:
    if not shutil.which(command[0]): return fallback
    p=subprocess.run(command,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True)
    return p.stdout.splitlines()[0].strip() if p.returncode==0 and p.stdout.strip() else fallback

def api_origin(api_base: str):
    p=urlparse(api_base)
    test_mode=os.environ.get("AURA_TEST_MODE")=="1"
    if p.scheme=="https" and p.hostname=="api.github.com" and p.path.rstrip("")=="": return (p.scheme,p.netloc)
    if test_mode and p.scheme=="http" and p.hostname in {"127.0.0.1","localhost","::1"} and p.port:
        return (p.scheme,p.netloc)
    raise CaptureError("API base must be https://api.github.com; loopback HTTP is allowed only when AURA_TEST_MODE=1")

def assert_trusted_url(url: str, base: str, expected_path_prefix: str):
    pu=urlparse(url); pb=urlparse(base)
    if pu.scheme!=pb.scheme or pu.netloc!=pb.netloc:
        raise CaptureError(f"pagination URL escaped trusted API origin: {url}")
    if not pu.path.startswith(expected_path_prefix):
        raise CaptureError(f"pagination URL escaped repository endpoint: {url}")

def parse_next_link(link: str | None):
    if not link: return None
    for part in link.split(","):
        match=re.search(r"<([^>]+)>\s*;\s*rel\s*=\s*\"?next\"?",part,re.I)
        if match: return match.group(1)
    return None

def http_get(url: str, *, token: str | None, out: Path, test_mode: bool=False):
    headers={"Accept":"application/vnd.github+json","X-GitHub-Api-Version":"2022-11-28","User-Agent":"AURA-P0-0-Evidence-Capture/3.0"}
    if token: headers["Authorization"]=f"Bearer {token}"
    req=Request(url,headers=headers,method="GET")
    try:
        with urlopen(req,timeout=45) as response:
            status=response.status; body=response.read(); hdrs=list(response.headers.items()); final_url=response.geturl(); reason=getattr(response,"reason","OK")
    except HTTPError as exc:
        body=exc.read()
        raise CaptureError(f"GitHub API returned HTTP {exc.code} for {url}: {body[:400].decode('utf-8','replace')}") from exc
    except URLError as exc:
        raise CaptureError(f"API request failed for {url}: {exc}") from exc
    if status!=200: raise CaptureError(f"API returned HTTP {status} for {url}")
    if final_url!=url:
        raise CaptureError(f"unexpected API redirect or URL normalization: requested={url}; effective={final_url}")
    raw_headers=f"HTTP/1.1 {status} {reason}\r\n"+"".join(f"{k}: {v}\r\n" for k,v in hdrs)+"\r\n"
    link_values=[v for k,v in hdrs if k.lower()=="link"]
    link_header=", ".join(link_values) if link_values else None
    try: payload=json.loads(body)
    except Exception as exc: raise CaptureError(f"API returned invalid JSON for {url}: {exc}") from exc
    return status,body,raw_headers,link_header,payload

def save_api_json(path: Path, body: bytes):
    path.parent.mkdir(parents=True,exist_ok=True)
    path.write_bytes(body)

def ref_text(repo: Path):
    p=run(["git","-C",repo,"for-each-ref","--format=%(refname) %(objectname)"])
    lines=sorted(p.stdout.splitlines(),key=lambda x:x.encode("utf-8"))
    return "".join(line+"\n" for line in lines)

def fsck(repo: Path, log_path: Path):
    p=run(["git","-C",repo,"fsck","--full","--no-reflogs","--unreachable"],check=False)
    log_path.parent.mkdir(parents=True,exist_ok=True); log_path.write_text(p.stdout,encoding="utf-8")
    unreachable=any(re.match(r"^(?:unreachable|dangling)\s+",line,re.I) for line in p.stdout.splitlines())
    if p.returncode: status="CORRUPTED"
    elif unreachable: status="HAS_UNREACHABLE_OBJECTS"
    elif re.search(r"(?:^|\n)(?:error|fatal|missing|broken)\b",p.stdout,re.I): status="ERROR"
    else: status="CLEAN"
    return status,p.returncode,unreachable,p.stdout

def api_capture(repo_name: str, out: Path, api_base: str, token: str | None, api_meta: dict, endpoint_key: str):
    spec=API_ENDPOINTS[endpoint_key]; path=f"/repos/vaidt/{repo_name}/{spec['path']}"
    base_origin=urlparse(api_base)
    query=dict(spec.get("query", {}))
    query["per_page"]="100"
    current=f"{api_base.rstrip('/')}{path}?{urlencode(query)}"
    assert_trusted_url(current,api_base,path)
    if endpoint_key == "issues_prs" and parse_qs(urlparse(current).query).get("state") != ["all"]:
        raise CaptureError(f"{repo_name}/issues_prs: initial request must explicitly include state=all")
    raw_root=out/"api_snapshots"/repo_name/"raw"/endpoint_key
    aggregate_path=out/"api_snapshots"/repo_name/spec["file"]
    pages=[]; all_records=[]; expected_total=None; page_no=1
    while current:
        assert_trusted_url(current,api_base,path)
        if endpoint_key == "issues_prs" and parse_qs(urlparse(current).query).get("state") != ["all"]:
            raise CaptureError(f"{repo_name}/issues_prs: every paginated request must preserve state=all: {current}")
        status,body,headers,link_header,payload=http_get(current,token=token,out=out)
        body_path=raw_root/f"page-{page_no:04d}.json"; headers_path=raw_root/f"page-{page_no:04d}.headers"
        save_api_json(body_path,body); headers_path.parent.mkdir(parents=True,exist_ok=True); headers_path.write_text(headers,encoding="utf-8")
        array_key=spec["array_key"]
        if array_key is None:
            if not isinstance(payload,list): raise CaptureError(f"{repo_name}/{endpoint_key}: expected root JSON array")
            records=payload; total=None
        else:
            if not isinstance(payload,dict) or not isinstance(payload.get(array_key),list): raise CaptureError(f"{repo_name}/{endpoint_key}: expected object with array {array_key}")
            total=payload.get("total_count")
            if isinstance(total,bool) or not isinstance(total,int) or total<0: raise CaptureError(f"{repo_name}/{endpoint_key}: invalid total_count")
            if expected_total is None: expected_total=total
            elif expected_total!=total: raise CaptureError(f"{repo_name}/{endpoint_key}: total_count changed across pages")
            records=payload[array_key]
        all_records.extend(records)
        next_rel=parse_next_link(link_header)
        next_url=urljoin(current,next_rel) if next_rel else None
        if next_url: assert_trusted_url(next_url,api_base,path)
        page={"request_url":current,"http_status":status,"body_file":body_path.relative_to(out).as_posix(),"body_sha256":sha_file(body_path),
              "headers_file":headers_path.relative_to(out).as_posix(),"headers_sha256":sha_file(headers_path),"link_header":link_header,
              "next_url":next_url,"record_count":len(records),"total_count":total}
        pages.append(page)
        if not next_url: break
        if any(existing["request_url"]==next_url for existing in pages): raise CaptureError(f"{repo_name}/{endpoint_key}: pagination cycle detected")
        current=next_url; page_no+=1
        if page_no>10000: raise CaptureError(f"{repo_name}/{endpoint_key}: excessive page count, aborting")
    if array_key is not None and len(all_records)!=expected_total:
        raise CaptureError(f"{repo_name}/{endpoint_key}: fetched {len(all_records)} records but total_count={expected_total}")
    aggregate={"total_count":expected_total,array_key:all_records} if array_key is not None else all_records
    json_write(aggregate_path,aggregate)
    trace={"endpoint_key":endpoint_key,"repository_name":repo_name,"aggregate_file":spec["file"],"page_count":len(pages),"record_count":len(all_records),"pages":pages}
    trace_path=out/"api_snapshots"/repo_name/"traces"/f"{endpoint_key}.json"; json_write(trace_path,trace)
    api_meta[f"{endpoint_key}_json_sha256"]=sha_file(aggregate_path)
    api_meta[f"{endpoint_key}_page_count"]=len(pages)
    api_meta[f"{endpoint_key}_record_count"]=len(all_records)
    api_meta[f"{endpoint_key}_pagination_complete"]=True
    api_meta[f"{endpoint_key}_pagination_trace_file"]=trace_path.relative_to(out).as_posix()
    api_meta[f"{endpoint_key}_pagination_trace_sha256"]=sha_file(trace_path)

def get_metadata(repo_name: str, out: Path, api_base: str, token: str | None):
    url=f"{api_base.rstrip('/')}/repos/vaidt/{repo_name}"
    assert_trusted_url(url,api_base,f"/repos/vaidt/{repo_name}")
    status,body,headers,link,payload=http_get(url,token=token,out=out)
    if not isinstance(payload,dict) or payload.get("full_name")!=f"vaidt/{repo_name}":
        raise CaptureError(f"metadata identity mismatch for vaidt/{repo_name}")
    api_dir=out/"api_snapshots"/repo_name; api_dir.mkdir(parents=True,exist_ok=True)
    # Store the raw JSON response body, without silently reserializing GitHub's payload.
    (api_dir/"metadata.json").write_bytes(body)
    (api_dir/"metadata.headers").write_text(headers,encoding="utf-8")
    return payload,sha_file(api_dir/"metadata.json")

def analyze_upstream(repo_name: str, meta: dict, source_repo: Path, out: Path, api_base: str, token: str | None, test_root: Path | None):
    if not meta.get("fork",False):
        return {"upstream_tracked":False,"upstream_repo":None,"upstream_default_branch":None,"upstream_metadata_json_sha256":None,"ahead_count":None,"behind_count":None,"delta_status":"NOT_A_FORK"}, False
    parent=meta.get("parent") or {}; full=parent.get("full_name")
    base={"upstream_tracked":True,"upstream_repo":full if isinstance(full,str) else None,"upstream_default_branch":None,
          "upstream_metadata_json_sha256":None,"ahead_count":None,"behind_count":None,"delta_status":"UPSTREAM_METADATA_MISSING"}
    if not isinstance(full,str) or not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+",full):
        log(f"{repo_name}: upstream metadata missing or malformed; retaining capture with exception status",out=out)
        return base, True
    up_url=f"{api_base.rstrip('/')}/repos/{full}"
    try:
        status,body,headers,link,up_meta=http_get(up_url,token=token,out=out)
    except CaptureError as exc:
        base["delta_status"]="UPSTREAM_METADATA_MISSING" if "HTTP 404" in str(exc) else "UNREACHABLE_UPSTREAM"
        log(f"{repo_name}: upstream metadata request failed; delta_status={base['delta_status']}: {exc}",out=out)
        return base, True
    if not isinstance(up_meta,dict) or up_meta.get("full_name")!=full or not up_meta.get("default_branch"):
        log(f"{repo_name}: upstream metadata is incomplete for {full}",out=out)
        return base, True
    up_api_path=out/"api_snapshots"/repo_name/"upstream_meta.json"
    up_api_path.write_bytes(body)
    base["upstream_default_branch"]=up_meta["default_branch"]
    base["upstream_metadata_json_sha256"]=sha_file(up_api_path)
    scratch=out/"upstream_scratchpads"/f"{repo_name}.git"
    upstream_remote=f"https://github.com/{full}.git"
    if test_root:
        local=test_root/(full+".git")
        if not local.is_dir():
            base["delta_status"]="UNREACHABLE_UPSTREAM"
            log(f"{repo_name}: mock upstream repository is unreachable: {local}",out=out)
            return base, True
        upstream_remote=str(local)
    try:
        run(["git","clone","--mirror",source_repo,scratch],out=out)
        run(["git","-C",scratch,"remote","add","upstream",upstream_remote],out=out)
        run(["git","-C",scratch,"fetch","upstream","+refs/heads/*:refs/remotes/upstream/*"],out=out)
    except CaptureError as exc:
        base["delta_status"]="UNREACHABLE_UPSTREAM"
        log(f"{repo_name}: upstream fetch failed; delta_status=UNREACHABLE_UPSTREAM: {exc}",out=out)
        return base, True
    upstream_ref=f"refs/remotes/upstream/{up_meta['default_branch']}"
    local_ref=f"refs/heads/{meta['default_branch']}"
    counts=run(["git","-C",scratch,"rev-list","--left-right","--count",f"{upstream_ref}...{local_ref}"],check=False,out=out)
    bits=counts.stdout.split()
    if counts.returncode or len(bits)!=2:
        base["delta_status"]="ANALYSIS_FAILED"
        log(f"{repo_name}: delta calculation failed; delta_status=ANALYSIS_FAILED: {counts.stdout[-500:]}",out=out)
        return base, True
    behind,ahead=map(int,bits)
    if ahead==0 and behind==0: delta="ZERO_DELTA"
    elif ahead>0 and behind==0: delta="FORK_AHEAD"
    elif ahead==0 and behind>0: delta="UPSTREAM_AHEAD"
    else: delta="DIVERGED"
    base.update({"ahead_count":ahead,"behind_count":behind,"delta_status":delta})
    return base, False

def capture_repo(repo_name: str, out: Path, api_base: str, token: str | None, test_root: Path | None):
    log(f"Repository capture: vaidt/{repo_name}",out=out)
    meta,meta_sha=get_metadata(repo_name,out,api_base,token)
    if meta.get("visibility")!="public": raise CaptureError(f"vaidt/{repo_name}: repository is not public")
    branch=meta.get("default_branch")
    if not isinstance(branch,str) or not branch: raise CaptureError(f"vaidt/{repo_name}: default_branch missing")
    source=out/"git_source_mirrors"/f"{repo_name}.git"; source.parent.mkdir(parents=True,exist_ok=True)
    source_url=f"https://github.com/vaidt/{repo_name}.git"
    clone_source=source_url
    if test_root:
        local=test_root/f"vaidt/{repo_name}.git"
        if not local.is_dir(): raise CaptureError(f"mock source repository missing: {local}")
        clone_source=str(local)
    run(["git","clone","--mirror",clone_source,source],out=out)
    default_ref=f"refs/heads/{branch}"
    headp=run(["git","-C",source,"rev-parse",default_ref],check=False,out=out)
    if headp.returncode: raise CaptureError(f"vaidt/{repo_name}: default branch ref {default_ref} missing")
    head=headp.stdout.strip()
    commits=int(run(["git","-C",source,"rev-list","--count",default_ref],out=out).stdout.strip())
    refs=ref_text(source)
    bundle_dir=out/"git_bundles"/repo_name; bundle_dir.mkdir(parents=True,exist_ok=True)
    refs_path=bundle_dir/"source_refs.txt"; refs_path.write_text(refs,encoding="utf-8")
    refs_sha=sha_file(refs_path)
    src_fsck_status,src_fsck_code,src_unreachable,src_fsck_output=fsck(source,out/"restoration_tests"/f"{repo_name}.source_fsck.log")
    if src_fsck_status!="CLEAN" or src_unreachable:
        raise CaptureError(f"vaidt/{repo_name}: source mirror fsck policy failed ({src_fsck_status}): {src_fsck_output[-1000:]}")
    bundle=bundle_dir/f"{repo_name}.bundle"
    run(["git","-C",source,"bundle","create",bundle,"--all"],out=out)
    bverify=run(["git","-C",source,"bundle","verify",bundle],check=False,out=out)
    if bverify.returncode: raise CaptureError(f"vaidt/{repo_name}: git bundle verify failed: {bverify.stdout}")
    restore=out/"restoration_tests"/f"{repo_name}.restored.git"
    run(["git","clone","--mirror",bundle,restore],out=out)
    restored_refs=ref_text(restore)
    ref_match="EXACT_MATCH" if restored_refs==refs else "MISMATCH"
    if ref_match!="EXACT_MATCH": raise CaptureError(f"vaidt/{repo_name}: restored refs differ from source refs")
    dst_fsck_status,dst_fsck_code,dst_unreachable,dst_fsck_output=fsck(restore,out/"restoration_tests"/f"{repo_name}.restored_fsck.log")
    if dst_fsck_status!="CLEAN" or dst_unreachable:
        raise CaptureError(f"vaidt/{repo_name}: restored fsck policy failed ({dst_fsck_status}): {dst_fsck_output[-1000:]}")

    api={"metadata_json_sha256":meta_sha}
    for key in API_ENDPOINTS:
        api_capture(repo_name,out,api_base,token,api,key)
    upstream,upstream_exception=analyze_upstream(repo_name,meta,source,out,api_base,token,test_root)
    entry={"repository_name":repo_name,"repository_full_name":f"vaidt/{repo_name}","source_git_url":source_url,
      "visibility":"public","is_fork":bool(meta.get("fork",False)),"default_branch":branch,"head_commit_sha":head,
      "total_commits_on_default_branch":commits,"git_refs_sha256":refs_sha,
      "git_bundle":{"file_name":bundle.name,"sha256":sha_file(bundle),"size_bytes":bundle.stat().st_size,"bundle_verify_status":"PASS"},
      "git_restoration_check":{"source_fsck_status":src_fsck_status,"source_fsck_exit_code":src_fsck_code,"source_unreachable_objects_detected":src_unreachable,
        "fsck_status":dst_fsck_status,"fsck_exit_code":dst_fsck_code,"reference_match_status":ref_match,"unreachable_objects_detected":dst_unreachable},
      "upstream_analysis":upstream,"github_api_artifacts":api}
    return entry, upstream_exception

def main():
    parser=argparse.ArgumentParser(description="Capture and preserve the 13-repository AURA P0-0 evidence snapshot")
    parser.add_argument("base_output_dir",type=Path)
    parser.add_argument("--force",action="store_true",help="allow an existing directory as a parent; never overwrite or delete prior sessions")
    parser.add_argument("--schema",type=Path,default=HERE/"p0_0_manifest_schema.json")
    args=parser.parse_args()
    base=args.base_output_dir.expanduser().resolve()
    if base.exists() and not args.force:
        print(f"FATAL: base output path already exists: {base}; no data was changed. Use a new path or explicit --force to create a new UUID child session.",file=sys.stderr); return 2
    if base.exists() and not base.is_dir():
        print(f"FATAL: base output path exists and is not a directory: {base}",file=sys.stderr); return 2
    schema=args.schema.resolve()
    if not schema.is_file(): print(f"FATAL: schema file missing: {schema}",file=sys.stderr); return 2
    auditor_identity=os.environ.get("AURA_AUDITOR_IDENTITY","").strip()
    if len(auditor_identity)<3:
        print("FATAL: set AURA_AUDITOR_IDENTITY to the exact intended OpenSSH signer principal before capture.",file=sys.stderr); return 2
    token=os.environ.get("GITHUB_TOKEN")
    test_mode=os.environ.get("AURA_TEST_MODE")=="1"
    api_base=os.environ.get("AURA_GH_API_BASE","https://api.github.com").rstrip("/")
    try: origin=api_origin(api_base)
    except CaptureError as exc: print(f"FATAL: {exc}",file=sys.stderr); return 2
    test_root=Path(os.environ["AURA_GIT_SOURCE_ROOT"]).resolve() if test_mode and os.environ.get("AURA_GIT_SOURCE_ROOT") else None
    session_id=str(uuid.uuid4())
    if not base.exists(): base.mkdir(parents=True,exist_ok=False)
    out=base/session_id
    try: out.mkdir(parents=False,exist_ok=False)
    except FileExistsError: print("FATAL: UUID output directory collision",file=sys.stderr); return 2
    for sub in ("git_source_mirrors","git_bundles","restoration_tests","upstream_scratchpads","api_snapshots","logs"):
        (out/sub).mkdir(parents=True,exist_ok=True)
    log(f"AURA P0-0 capture started; session={session_id}; api_base={api_base}; output={out}",out=out)
    try:
        entries=[]
        any_exceptions=False
        for name in EXPECTED_REPOSITORIES:
            entry,repo_exception=capture_repo(name,out,api_base,token,test_root)
            entries.append(entry)
            any_exceptions = any_exceptions or repo_exception
        env={"git_version":command_version(["git","--version"]),"curl_version":command_version(["curl","--version"]),
          "jq_version":command_version(["jq","--version"]),"python_version":sys.version.split()[0],"gh_cli_version":command_version(["gh","--version"]),
          "host_os":sys.platform,"host_arch":run(["uname","-m"]).stdout.strip() if shutil.which("uname") else "unknown"}
        manifest={"schema_version":"1.0.0","schema_artifact":{"file_name":schema.name,"sha256":sha_file(schema)},
          "capture_session_id":session_id,"capture_timestamp_utc":datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00","Z"),
          "auditor_identity":auditor_identity,
          "capture_status":"CAPTURE_COMPLETED_WITH_EXCEPTIONS" if any_exceptions else "CAPTURE_COMPLETED","environment_metadata":env,"repositories":entries}
        manifest_path=out/"evidence_manifest.json"; json_write(manifest_path,manifest)
        (out/"evidence_manifest.json.sha256").write_text(f"{sha_file(manifest_path)}  evidence_manifest.json\n",encoding="utf-8")
        # Immediately validate exact schema and captured API evidence. In test mode, local API origin is allowed only for this capture-validation path.
        p=run([sys.executable,HERE/"p0_0_manifest_validate.py","--schema",schema,"--manifest",manifest_path,"--snapshot-dir",out],check=False)
        if p.returncode:
            raise CaptureError(f"post-capture semantic validation failed: {p.stdout}")
        if any_exceptions:
            log("CAPTURE_COMPLETED_WITH_EXCEPTIONS; semantic validation PASS, but formal acceptance is forbidden.",out=out)
            print(f"SNAPSHOT_DIR={out}")
            return 2
        log("CAPTURE_COMPLETED; local semantic validation PASS. Signature is not created by the capture engine.",out=out)
        print(f"SNAPSHOT_DIR={out}")
        return 0
    except Exception as exc:
        error={"capture_session_id":session_id,"status":"CAPTURE_COMPLETED_WITH_EXCEPTIONS","error_type":type(exc).__name__,"error":str(exc),"timestamp_utc":datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00","Z")}
        json_write(out/"logs"/"capture_error.json",error)
        log(f"CAPTURE FAILED CLOSED: {type(exc).__name__}: {exc}",out=out)
        print(f"CAPTURE_FAILED; partial directory preserved for diagnostics: {out}",file=sys.stderr)
        return 2

if __name__=="__main__": raise SystemExit(main())
