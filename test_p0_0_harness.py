#!/usr/bin/env python3
"""Executable local test harness for P0-0 validator/verifier. No external network access."""
from __future__ import annotations
import copy, hashlib, json, os, shutil, subprocess, sys, tempfile, uuid, threading, urllib.parse, http.server, socketserver, re
from datetime import datetime, timezone
from pathlib import Path

HERE = Path(__file__).resolve().parent
SCHEMA = HERE / "p0_0_manifest_schema.json"
VALIDATOR = HERE / "p0_0_manifest_validate.py"
VERIFIER_SH = HERE / "verify_p0_0_snapshot.sh"
CAPTURE_SH = HERE / "p0_0_evidence_capture.sh"
REPOS = ["Aura-vNEXT","Aura-Guard","Crystal-panel-Aura-Protection","aura-guard-v1.3","aura-specification","Aura-Conformance-Kit","Authority","inclusion","acode-plugin-docs","acodex_server","termux-packages","Aura-Release-Management","aura-poc-a-core-v3.3"]
PRINCIPAL = "aura-p0-test"
NAMESPACE = "aura-governance"
API_MAP = {
    "workflows": ("workflows.json", "actions/workflows", "workflows"),
    "actions_runs": ("actions_runs.json", "actions/runs", "workflow_runs"),
    "releases": ("releases.json", "releases", None),
    "tags": ("tags.json", "tags", None),
    "issues_prs": ("issues_prs.json", "issues", None),
}

# Dynamic accounting: one counter increment per declared harness case.
POSITIVE_CASES = 0
NEGATIVE_CASES = 0

def record_case(kind: str) -> None:
    global POSITIVE_CASES, NEGATIVE_CASES
    if kind == "positive":
        POSITIVE_CASES += 1
    elif kind == "negative":
        NEGATIVE_CASES += 1
    else:
        raise ValueError(f"unknown case type: {kind!r}")

def run(cmd, cwd=None, input_data=None, check=True):
    p = subprocess.run([str(x) for x in cmd], cwd=str(cwd) if cwd else None, input=input_data, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=isinstance(input_data, str) or input_data is None, timeout=15)
    if check and p.returncode:
        raise RuntimeError(f"Command failed ({p.returncode}): {' '.join(map(str,cmd))}\n{p.stdout}")
    return p

def sha(path: Path):
    h=hashlib.sha256()
    with path.open('rb') as f:
        for block in iter(lambda:f.read(1024*1024),b''): h.update(block)
    return h.hexdigest()

def json_write(path: Path, obj):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, indent=2, sort_keys=True) + "\n", encoding="utf-8")

def refs_text(repo: Path):
    p=run(["git","-C",repo,"for-each-ref","--format=%(refname) %(objectname)"])
    return "".join(x+"\n" for x in sorted(p.stdout.splitlines(), key=lambda s:s.encode()))

def fsck_info(repo: Path):
    p=run(["git","-C",repo,"fsck","--full","--no-reflogs","--unreachable"],check=False)
    unreachable=any(line.startswith("unreachable ") or line.startswith("dangling ") for line in p.stdout.splitlines())
    if p.returncode: status="CORRUPTED"
    elif unreachable: status="HAS_UNREACHABLE_OBJECTS"
    else: status="CLEAN"
    return status,p.returncode,unreachable,p.stdout

def sign_snapshot(snapshot: Path, private_key: Path):
    manifest=snapshot/"evidence_manifest.json"
    sidecar=snapshot/"evidence_manifest.json.sha256"
    sidecar.write_text(f"{sha(manifest)}  evidence_manifest.json\n",encoding="utf-8")
    sig=Path(str(manifest)+".sig")
    sig.unlink(missing_ok=True)
    run(["ssh-keygen","-Y","sign","-f",private_key,"-n",NAMESPACE,manifest])

def make_page_payload(array_key, items, total):
    return items if array_key is None else {"total_count": total, array_key: items}

def write_endpoint(snapshot: Path, repo: str, key: str, page_count: int, manifest_api: dict):
    filename, endpoint_path, array_key = API_MAP[key]
    api_dir=snapshot/"api_snapshots"/repo
    aggregate_path=api_dir/filename
    if key == "workflows":
        all_records=[{"id":f"wf-{i+1}","name":f"workflow-{i+1}"} for i in range(page_count)]
        chunks=[[x] for x in all_records]
    elif key == "issues_prs" and repo == REPOS[0]:
        # Positive fixture: issues endpoint paginates and preserves state=all.
        all_records=[{"number":1,"title":"open fixture"},{"number":2,"title":"closed fixture"}]
        chunks=[[all_records[0]],[all_records[1]]]
    elif key == "actions_runs":
        chunks=[[]]; all_records=[]
    else:
        chunks=[[]]; all_records=[]
    actual_pages=len(chunks)
    page_records=[]
    for idx, items in enumerate(chunks, start=1):
        query_prefix="state=all&" if key == "issues_prs" else ""
        url=f"https://api.github.com/repos/vaidt/{repo}/{endpoint_path}?{query_prefix}per_page=100&page={idx}"
        next_url=f"https://api.github.com/repos/vaidt/{repo}/{endpoint_path}?{query_prefix}per_page=100&page={idx+1}" if idx < actual_pages else None
        link_header=f'<{next_url}>; rel="next"' if next_url else None
        payload=make_page_payload(array_key, items, len(all_records) if array_key is not None else None)
        body=json.dumps(payload, sort_keys=True, separators=(",", ":")) + "\n"
        raw_dir=api_dir/"raw"/key
        headers_dir=raw_dir
        body_path=raw_dir/f"page-{idx:04d}.json"
        headers_path=headers_dir/f"page-{idx:04d}.headers"
        body_path.parent.mkdir(parents=True,exist_ok=True)
        body_path.write_text(body,encoding="utf-8")
        headers="HTTP/2 200\r\ncontent-type: application/json\r\n"
        if link_header: headers += f"Link: {link_header}\r\n"
        headers += "\r\n"
        headers_path.write_text(headers,encoding="utf-8")
        page_records.append({
          "request_url":url,"http_status":200,"body_file":body_path.relative_to(snapshot).as_posix(),"body_sha256":sha(body_path),
          "headers_file":headers_path.relative_to(snapshot).as_posix(),"headers_sha256":sha(headers_path),
          "link_header":link_header,"next_url":next_url,"record_count":len(items),
          "total_count":len(all_records) if array_key is not None else None
        })
    aggregate=make_page_payload(array_key, all_records, len(all_records) if array_key is not None else None)
    json_write(aggregate_path, aggregate)
    trace={"endpoint_key":key,"repository_name":repo,"aggregate_file":filename,"page_count":actual_pages,"record_count":len(all_records),"pages":page_records}
    trace_path=api_dir/"traces"/f"{key}.json"
    json_write(trace_path,trace)
    manifest_api[f"{key}_json_sha256"]=sha(aggregate_path)
    manifest_api[f"{key}_page_count"]=actual_pages
    manifest_api[f"{key}_record_count"]=len(all_records)
    manifest_api[f"{key}_pagination_complete"]=True
    manifest_api[f"{key}_pagination_trace_file"]=trace_path.relative_to(snapshot).as_posix()
    manifest_api[f"{key}_pagination_trace_sha256"]=sha(trace_path)

def make_fixture(snapshot: Path, page_count: int, private_key: Path):
    snapshot.mkdir(parents=True,exist_ok=True)
    schema_obj=json.loads(SCHEMA.read_text(encoding="utf-8"))
    _=schema_obj
    entries=[]
    for repo_name in REPOS:
        source=snapshot/"git_source_mirrors"/f"{repo_name}.git"
        work=snapshot/"_work"/repo_name
        work.mkdir(parents=True,exist_ok=True)
        run(["git","init","-b","main",work])
        (work/"README.md").write_text(f"# {repo_name}\n",encoding="utf-8")
        run(["git","-C",work,"add","README.md"])
        env=os.environ.copy(); env.update({"GIT_AUTHOR_NAME":"AURA Test","GIT_AUTHOR_EMAIL":"aura-test@example.invalid","GIT_COMMITTER_NAME":"AURA Test","GIT_COMMITTER_EMAIL":"aura-test@example.invalid"})
        run(["git","-C",work,"-c","user.name=AURA Test","-c","user.email=aura-test@example.invalid","commit","-m","test baseline"],check=True)
        source.parent.mkdir(parents=True,exist_ok=True)
        run(["git","clone","--mirror",work,source])
        head=run(["git","-C",source,"rev-parse","refs/heads/main"]).stdout.strip()
        source_refs=refs_text(source)
        refs_path=snapshot/"git_bundles"/repo_name/"source_refs.txt"
        refs_path.parent.mkdir(parents=True,exist_ok=True); refs_path.write_text(source_refs,encoding="utf-8")
        refs_sha=sha(refs_path)
        bundle_path=refs_path.parent/f"{repo_name}.bundle"
        run(["git","-C",source,"bundle","create",bundle_path,"--all"])
        bverify=run(["git","-C",source,"bundle","verify",bundle_path],check=False)
        s_status,s_code,s_unreach,_=fsck_info(source)
        restore=snapshot/"_restore_build"/f"{repo_name}.git"
        run(["git","clone","--mirror",bundle_path,restore])
        restore_refs=refs_text(restore)
        r_status,r_code,r_unreach,_=fsck_info(restore)
        ref_match="EXACT_MATCH" if restore_refs==source_refs else "MISMATCH"
        api_dir=snapshot/"api_snapshots"/repo_name; api_dir.mkdir(parents=True,exist_ok=True)
        metadata={"full_name":f"vaidt/{repo_name}","visibility":"public","fork":False,"default_branch":"main","clone_url":f"https://github.com/vaidt/{repo_name}.git"}
        json_write(api_dir/"metadata.json",metadata)
        api={"metadata_json_sha256":sha(api_dir/"metadata.json")}
        for key in API_MAP:
            write_endpoint(snapshot,repo_name,key,(page_count if repo_name==REPOS[0] else 1) if key=="workflows" else 1,api)
        entries.append({
          "repository_name":repo_name,"repository_full_name":f"vaidt/{repo_name}","source_git_url":f"https://github.com/vaidt/{repo_name}.git",
          "visibility":"public","is_fork":False,"default_branch":"main","head_commit_sha":head,
          "total_commits_on_default_branch":int(run(["git","-C",restore,"rev-list","--count","refs/heads/main"]).stdout.strip()),
          "git_refs_sha256":refs_sha,
          "git_bundle":{"file_name":bundle_path.name,"sha256":sha(bundle_path),"size_bytes":bundle_path.stat().st_size,"bundle_verify_status":"PASS" if bverify.returncode==0 else "FAIL"},
          "git_restoration_check":{"source_fsck_status":s_status,"source_fsck_exit_code":s_code,"source_unreachable_objects_detected":s_unreach,
            "fsck_status":r_status,"fsck_exit_code":r_code,"reference_match_status":ref_match,"unreachable_objects_detected":r_unreach},
          "upstream_analysis":{"upstream_tracked":False,"upstream_repo":None,"upstream_default_branch":None,"upstream_metadata_json_sha256":None,"ahead_count":None,"behind_count":None,"delta_status":"NOT_A_FORK"},
          "github_api_artifacts":api
        })
    shutil.rmtree(snapshot/"_work",ignore_errors=True); shutil.rmtree(snapshot/"_restore_build",ignore_errors=True)
    manifest={"schema_version":"1.0.0","schema_artifact":{"file_name":SCHEMA.name,"sha256":sha(SCHEMA)},
       "capture_session_id":str(uuid.uuid4()),"capture_timestamp_utc":datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00","Z"),
       "auditor_identity":PRINCIPAL,"capture_status":"CAPTURE_COMPLETED",
       "environment_metadata":{"git_version":run(["git","--version"]).stdout.strip(),"curl_version":"test-harness","jq_version":"test-harness","python_version":sys.version.split()[0],"gh_cli_version":"test-harness","host_os":sys.platform,"host_arch":"test"},
       "repositories":entries}
    json_write(snapshot/"evidence_manifest.json",manifest)
    sign_snapshot(snapshot,private_key)

def rewrite_workflow_pages(snapshot: Path, page_count: int, private_key: Path):
    manifest=load_manifest(snapshot)
    repo=REPOS[0]
    r=next(item for item in manifest["repositories"] if item["repository_name"]==repo)
    raw=snapshot/"api_snapshots"/repo/"raw"/"workflows"
    shutil.rmtree(raw,ignore_errors=True)
    trace=snapshot/"api_snapshots"/repo/"traces"/"workflows.json"
    trace.unlink(missing_ok=True)
    write_endpoint(snapshot,repo,"workflows",page_count,r["github_api_artifacts"])
    save_manifest(snapshot,manifest,private_key)

def load_manifest(snapshot):
    return json.loads((snapshot/"evidence_manifest.json").read_text(encoding="utf-8"))
def save_manifest(snapshot, obj, key):
    json_write(snapshot/"evidence_manifest.json",obj)
    sign_snapshot(snapshot,key)
def call_verify(snapshot, allowed, principal=PRINCIPAL):
    return subprocess.run([str(VERIFIER_SH),str(snapshot),str(SCHEMA),"--profile","formal",str(allowed),principal,NAMESPACE],stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True,timeout=20)
def call_validate(snapshot):
    return subprocess.run([sys.executable,str(VALIDATOR),"--schema",str(SCHEMA),"--manifest",str(snapshot/"evidence_manifest.json"),"--snapshot-dir",str(snapshot)],stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True)

def expect_pass(label, snapshot, allowed):
    p=call_verify(snapshot,allowed)
    if p.returncode:
        raise AssertionError(f"{label}: expected PASS, got {p.returncode}\n{p.stdout}")
    print(f"PASS {label}", flush=True)
    record_case("positive")

def expect_validator_pass(label, snapshot):
    p=call_validate(snapshot)
    if p.returncode:
        raise AssertionError(f"{label}: expected validator PASS, got {p.returncode}\n{p.stdout}")
    print(f"PASS {label}", flush=True)
    record_case("positive")
def expect_fail(label, snapshot, allowed, principal=PRINCIPAL):
    p=call_verify(snapshot,allowed,principal)
    if p.returncode == 0:
        raise AssertionError(f"{label}: expected rejection but verifier returned PASS\n{p.stdout}")
    print(f"PASS {label} rejected (exit={p.returncode})", flush=True)
    record_case("negative")
def clone_snapshot(source: Path, target: Path, include_git=False):
    target.mkdir(parents=True,exist_ok=True)
    shutil.copytree(source/"api_snapshots",target/"api_snapshots")
    for fname in ("evidence_manifest.json","evidence_manifest.json.sha256","evidence_manifest.json.sig"):
        p=source/fname
        if p.is_file(): shutil.copy2(p,target/fname)
    if include_git:
        for dirname in ("git_source_mirrors","git_bundles"):
            shutil.copytree(source/dirname,target/dirname)
def resign_tamper_manifest(snapshot, key, mutate):
    manifest=load_manifest(snapshot); mutate(manifest); save_manifest(snapshot,manifest,key)

def test_capture_engine(tmp: Path):
    mock_root=tmp/"mock_git"
    (mock_root/"vaidt").mkdir(parents=True)
    for name in REPOS:
        work=tmp/"mock_work"/name; work.parent.mkdir(parents=True,exist_ok=True)
        if name == "inclusion":
            upstream_work=tmp/"mock_work"/"upstream"/name; upstream_work.parent.mkdir(parents=True,exist_ok=True)
            run(["git","init","-b","main",upstream_work])
            (upstream_work/"README.md").write_text(f"# Upstream {name}\n",encoding="utf-8")
            run(["git","-C",upstream_work,"add","README.md"])
            run(["git","-C",upstream_work,"-c","user.name=AURA Mock","-c","user.email=mock@example.invalid","commit","-m","upstream baseline"])
            run(["git","clone",upstream_work,work])
            with (work/"README.md").open("a",encoding="utf-8") as f: f.write("fork-only line\n")
            run(["git","-C",work,"add","README.md"])
            run(["git","-C",work,"-c","user.name=AURA Mock","-c","user.email=mock@example.invalid","commit","-m","fork-only commit"])
            (mock_root/"upstream").mkdir(parents=True,exist_ok=True)
            run(["git","clone","--mirror",upstream_work,mock_root/"upstream"/f"{name}.git"])
        else:
            work.mkdir(parents=True)
            run(["git","init","-b","main",work])
            (work/"README.md").write_text(f"# Mock {name}\n",encoding="utf-8")
            run(["git","-C",work,"add","README.md"])
            run(["git","-C",work,"-c","user.name=AURA Mock","-c","user.email=mock@example.invalid","commit","-m","mock baseline"])
        run(["git","clone","--mirror",work,mock_root/"vaidt"/f"{name}.git"])

    class Handler(http.server.BaseHTTPRequestHandler):
        protocol_version="HTTP/1.1"
        def log_message(self,*args): pass
        def do_GET(self):
            parts=urllib.parse.urlparse(self.path)
            path=parts.path
            q=urllib.parse.parse_qs(parts.query)
            status=200; headers={"Content-Type":"application/json"}; page_payload=None
            metadata_match=re.match(r"^/repos/([^/]+)/([^/]+)$",path)
            if metadata_match:
                owner,name=metadata_match.groups()
                if owner=="vaidt" and name in REPOS:
                    is_fork=(name=="inclusion")
                    page_payload={"full_name":f"vaidt/{name}","visibility":"public","fork":is_fork,"default_branch":"main","clone_url":f"https://github.com/vaidt/{name}.git"}
                    if is_fork: page_payload["parent"]={"full_name":"upstream/inclusion"}
                elif owner=="upstream" and name=="inclusion":
                    page_payload={"full_name":"upstream/inclusion","visibility":"public","fork":False,"default_branch":"main","clone_url":"https://github.com/upstream/inclusion.git"}
                else:
                    status=404; page_payload={"message":"not found"}
            else:
                m=re.match(r"^/repos/vaidt/([^/]+)/(actions/workflows|actions/runs|releases|tags|issues)$",path)
                if not m: status=404; page_payload={"message":"not found"}
                else:
                    name,ep=m.group(1),m.group(2); page=int(q.get("page",["1"])[0])
                    if name not in REPOS: status=404; page_payload={"message":"not found"}
                    elif ep=="issues" and q.get("state") != ["all"]:
                        status=400; page_payload={"message":"state=all is required by the evidence-preservation contract"}
                    elif ep=="actions/workflows":
                        if name==REPOS[0]:
                            if page==1:
                                page_payload={"total_count":2,"workflows":[{"id":1,"name":"mock-wf-1"}]}
                                headers["Link"]=f'<http://{self.headers.get("Host")}{path}?per_page=100&page=2>; rel="next"'
                            else: page_payload={"total_count":2,"workflows":[{"id":2,"name":"mock-wf-2"}]}
                        else: page_payload={"total_count":0,"workflows":[]}
                    elif ep=="actions/runs": page_payload={"total_count":0,"workflow_runs":[]}
                    elif ep=="issues":
                        if name==REPOS[0] and page==1:
                            page_payload=[{"number":1,"title":"open mock issue"}]
                            headers["Link"]=f'<http://{self.headers.get("Host")}{path}?state=all&per_page=100&page=2>; rel="next"'
                        elif name==REPOS[0] and page==2:
                            page_payload=[{"number":2,"title":"closed mock issue"}]
                        else:
                            page_payload=[]
                    else: page_payload=[]
            body=json.dumps(page_payload,separators=(",",":" )).encode()
            self.send_response(status)
            for k,v in headers.items(): self.send_header(k,v)
            self.send_header("Content-Length",str(len(body)))
            self.end_headers(); self.wfile.write(body)

    server=socketserver.ThreadingTCPServer(("127.0.0.1",0),Handler)
    server.daemon_threads=True
    port=server.server_address[1]
    thread=threading.Thread(target=server.serve_forever,daemon=True); thread.start()
    try:
        base=tmp/"capture_output"
        env=os.environ.copy(); env.update({"AURA_TEST_MODE":"1","AURA_GH_API_BASE":f"http://127.0.0.1:{port}","AURA_GIT_SOURCE_ROOT":str(mock_root),"AURA_AUDITOR_IDENTITY":PRINCIPAL})
        p=subprocess.run([str(CAPTURE_SH),str(base),"--schema",str(SCHEMA)],env=env,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True,timeout=90)
        if p.returncode:
            raise AssertionError(f"H-17 capture engine failed on local API/Git mocks (exit={p.returncode}):\n{p.stdout[-5000:]}")
        match=re.search(r"^SNAPSHOT_DIR=(.+)$",p.stdout,re.M)
        if not match: raise AssertionError("H-17 capture engine did not report SNAPSHOT_DIR")
        snapshot=Path(match.group(1).strip())
        check=subprocess.run([sys.executable,str(VALIDATOR),"--schema",str(SCHEMA),"--manifest",str(snapshot/"evidence_manifest.json"),"--snapshot-dir",str(snapshot)],env=env,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True,timeout=30)
        if check.returncode: raise AssertionError(f"H-17 captured manifest failed strict validation:\n{check.stdout}")
        captured_manifest=json.loads((snapshot/"evidence_manifest.json").read_text(encoding="utf-8"))
        inclusion=next(r for r in captured_manifest["repositories"] if r["repository_name"]=="inclusion")
        up=inclusion["upstream_analysis"]
        if up.get("delta_status")!="FORK_AHEAD" or up.get("ahead_count")!=1 or up.get("behind_count")!=0:
            raise AssertionError(f"H-17 upstream delta taxonomy mismatch: {up}")
        print("PASS H-17 capture -> raw-page archive -> manifest -> semantic validation + fork delta (local mocks)",flush=True)
        record_case("positive")
        return snapshot
    finally:
        server.shutdown(); server.server_close(); thread.join(timeout=2)

def main():
    if not shutil.which("git") or not shutil.which("ssh-keygen"):
        print("FATAL: harness requires git and real ssh-keygen in PATH. A test-only shim may be placed first in PATH for control-flow tests, but that does not validate OpenSSH SSHSIG interoperability.", file=sys.stderr)
        return 2
    with tempfile.TemporaryDirectory(prefix="aura-p0-harness-") as tmp_s:
        tmp=Path(tmp_s)
        key=tmp/"test_key"; run(["ssh-keygen","-q","-t","ed25519","-N","","-C",PRINCIPAL,"-f",key])
        pub=(Path(str(key)+".pub")).read_text().strip().split()
        allowed=tmp/"allowed_signers"; allowed.write_text(f'{PRINCIPAL} namespaces="{NAMESPACE}" {pub[0]} {pub[1]}\n',encoding="utf-8")
        wrong_key=tmp/"wrong_key"; run(["ssh-keygen","-q","-t","ed25519","-N","","-C","wrong","-f",wrong_key])
        wrong_pub=Path(str(wrong_key)+".pub").read_text().strip().split()
        wrong_allowed=tmp/"wrong_allowed_signers"; wrong_allowed.write_text(f'{PRINCIPAL} namespaces="{NAMESPACE}" {wrong_pub[0]} {wrong_pub[1]}\n',encoding="utf-8")
        base10=tmp/"positive_10_pages"; make_fixture(base10,10,key)
        base1=tmp/"positive_1_page"; clone_snapshot(base10,base1); rewrite_workflow_pages(base1,1,key); expect_validator_pass("H-01 single-page capture",base1)
        base2=tmp/"positive_2_pages"; clone_snapshot(base10,base2); rewrite_workflow_pages(base2,2,key); expect_validator_pass("H-02 two-page Link chain",base2)
        expect_pass("H-03 ten-page deterministic aggregation + formal verification",base10,allowed)

        # H-04: remove next URL in trace but update its declared hash and re-sign the manifest.
        h4=tmp/"h04"; clone_snapshot(base2,h4)
        def mutate_trace(trace): trace["pages"][0]["next_url"]=None; trace["pages"][0]["link_header"]=None
        m=load_manifest(h4); a=m["repositories"][0]["github_api_artifacts"]; tr=h4/a["workflows_pagination_trace_file"]
        td=json.loads(tr.read_text()); mutate_trace(td); json_write(tr,td); a["workflows_pagination_trace_sha256"]=sha(tr); save_manifest(h4,m,key)
        expect_fail("H-04 missing/broken pagination continuation",h4,allowed)

        # H-05: unsafe external next-page URL.
        h5=tmp/"h05"; clone_snapshot(base2,h5)
        m=load_manifest(h5); a=m["repositories"][0]["github_api_artifacts"]; tr=h5/a["workflows_pagination_trace_file"]
        td=json.loads(tr.read_text()); td["pages"][0]["request_url"]="https://evil.example/steal"; json_write(tr,td); a["workflows_pagination_trace_sha256"]=sha(tr); save_manifest(h5,m,key)
        expect_fail("H-05 API origin escape",h5,allowed)

        # H-06: page count in manifest disagrees with trace.
        h6=tmp/"h06"; clone_snapshot(base2,h6)
        resign_tamper_manifest(h6,key,lambda m:m["repositories"][0]["github_api_artifacts"].__setitem__("workflows_page_count",99))
        expect_fail("H-06 page count mismatch",h6,allowed)

        # H-07: record counter mismatch in manifest.
        h7=tmp/"h07"; clone_snapshot(base2,h7)
        resign_tamper_manifest(h7,key,lambda m:m["repositories"][0]["github_api_artifacts"].__setitem__("workflows_record_count",999))
        expect_fail("H-07 record count mismatch",h7,allowed)

        # H-08: duplicate repo name replaces a required repo.
        h8=tmp/"h08"; clone_snapshot(base1,h8)
        def duplicate_repo(m): m["repositories"][1]=copy.deepcopy(m["repositories"][0])
        resign_tamper_manifest(h8,key,duplicate_repo)
        expect_fail("H-08 duplicated/missing repository",h8,allowed)

        # H-09: change a stored aggregate without updating its declared hash.
        h9=tmp/"h09"; clone_snapshot(base1,h9)
        p=h9/"api_snapshots"/REPOS[0]/"workflows.json"; data=json.loads(p.read_text()); data["workflows"].append({"id":"tampered"}); json_write(p,data)
        expect_fail("H-09 API artifact tampering",h9,allowed)

        # H-10: remove signature.
        h10=tmp/"h10"; clone_snapshot(base1,h10); (h10/"evidence_manifest.json.sig").unlink()
        expect_fail("H-10 mandatory signature missing",h10,allowed)

        # H-11: signature is not accepted by the independent trusted signer list.
        expect_fail("H-11 untrusted signing key",base1,wrong_allowed)

        # H-12: inject a genuinely unreachable blob into the source mirror.
        print("START H-12: preparing unreachable-object fixture", flush=True)
        h12=tmp/"h12"; clone_snapshot(base10,h12)
        print("H-12: API fixture copied", flush=True)
        (h12/"git_source_mirrors").mkdir(parents=True,exist_ok=True)
        shutil.copytree(base10/"git_source_mirrors"/f"{REPOS[0]}.git",h12/"git_source_mirrors"/f"{REPOS[0]}.git")
        (h12/"git_bundles").mkdir(parents=True,exist_ok=True)
        shutil.copytree(base10/"git_bundles"/REPOS[0],h12/"git_bundles"/REPOS[0])
        source=h12/"git_source_mirrors"/f"{REPOS[0]}.git"
        print("H-12: source mirror copied; injecting object", flush=True)
        run(["git","-C",source,"hash-object","-w","--stdin"],input_data="unreachable-test-object",check=True)
        print("H-12: object injected; running verifier", flush=True)
        expect_fail("H-12 unreachable source Git object",h12,allowed)

        # Extra negative cases for R14/R15 and manifest status semantics.
        h13=tmp/"h13"; clone_snapshot(base1,h13)
        resign_tamper_manifest(h13,key,lambda m:m["schema_artifact"].__setitem__("sha256","0"*64))
        expect_fail("H-13 schema identity mismatch",h13,allowed)
        h14=tmp/"h14"; clone_snapshot(base1,h14)
        metadata=h14/"api_snapshots"/REPOS[0]/"metadata.json"; md=json.loads(metadata.read_text()); md["default_branch"]="wrong"; json_write(metadata,md)
        # This should fail API hash before the metadata semantic check; still proves tamper detection.
        expect_fail("H-14 metadata artifact tampering",h14,allowed)
        h15=tmp/"h15"; clone_snapshot(base1,h15)
        resign_tamper_manifest(h15,key,lambda m:m.__setitem__("capture_status","CAPTURE_COMPLETED_WITH_EXCEPTIONS"))
        expect_fail("H-15 exception status cannot be formally accepted",h15,allowed)
        h16=tmp/"h16"; clone_snapshot(base1,h16)
        resign_tamper_manifest(h16,key,lambda m:m.__setitem__("capture_timestamp_utc","yesterday-ish"))
        expect_fail("H-16 invalid timestamp format",h16,allowed)

        # H-19: issues/PR archive must explicitly preserve state=all on every page.
        h19=tmp/"h19"; clone_snapshot(base1,h19)
        m=load_manifest(h19)
        api=m["repositories"][0]["github_api_artifacts"]
        tr=h19/api["issues_prs_pagination_trace_file"]
        td=json.loads(tr.read_text(encoding="utf-8"))
        td["pages"][0]["request_url"] = td["pages"][0]["request_url"].replace("state=all&", "")
        json_write(tr,td)
        api["issues_prs_pagination_trace_sha256"] = sha(tr)
        save_manifest(h19,m,key)
        expect_fail("H-19 issues_prs must declare state=all",h19,allowed)

        # H-20: prove the date-time format checker rejects ONLY the invalid timestamp.
        # Start from a complete validator-accepted fixture, then change a single field.
        h20=tmp/"h20"; clone_snapshot(base1,h20)
        baseline=call_validate(h20)
        if baseline.returncode != 0:
            raise AssertionError(f"H-20 precondition failed: baseline fixture must validate before mutation\n{baseline.stdout}")
        h20_manifest=load_manifest(h20)
        h20_manifest["capture_timestamp_utc"]="2026-10-15T21:03:21"  # intentionally missing UTC offset/Z
        json_write(h20/"evidence_manifest.json",h20_manifest)
        h20_result=call_validate(h20)
        if h20_result.returncode == 0:
            raise AssertionError("H-20: validator accepted invalid date-time after changing only capture_timestamp_utc")
        out = f"{h20_result.stdout}\n{h20_result.stderr}"
        normalized = out.casefold()

        field_ok = "capture_timestamp_utc" in normalized
        expected_reasons = (
            "date-time",
            "must be expressed in utc",
            "rfc 3339",
            "rfc3339",
            "z suffix",
        )
        reason_ok = any(reason in normalized for reason in expected_reasons)

        if not field_ok or not reason_ok:
            raise AssertionError(
                "H-20: validator rejected for the wrong reason; "
                "expected capture_timestamp_utc/date-time or "
                f"equivalent UTC/RFC3339 message\n{out}"
            )
        print("PASS H-20 invalid date-time rejected specifically at capture_timestamp_utc",flush=True)
        record_case("negative")

        captured_snapshot=test_capture_engine(tmp)
        formal_test_env=os.environ.copy(); formal_test_env["AURA_TEST_MODE"]="1"
        p=subprocess.run([str(VERIFIER_SH),str(captured_snapshot),str(SCHEMA),"--profile","formal",str(allowed),PRINCIPAL,NAMESPACE],env=formal_test_env,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True,timeout=10)
        if p.returncode==0 or "refuses AURA_TEST_MODE=1" not in p.stdout:
            raise AssertionError("H-18: formal verifier did not explicitly reject test mode")
        print("PASS H-18 formal verifier rejects AURA_TEST_MODE=1",flush=True)
        record_case("negative")
        total_cases = POSITIVE_CASES + NEGATIVE_CASES
        if POSITIVE_CASES != 4 or NEGATIVE_CASES != 16 or total_cases != 20:
            raise AssertionError(f"Harness accounting mismatch: {POSITIVE_CASES} positive + {NEGATIVE_CASES} negative = {total_cases}; expected 4 + 16 = 20")
        print(f"\nHARNESS RESULT: {total_cases}/{total_cases} test cases passed ({POSITIVE_CASES} positive + {NEGATIVE_CASES} negative), verified with real OpenSSH ssh-keygen.", flush=True)
    return 0
if __name__=='__main__':
    try: raise SystemExit(main())
    except Exception as exc:
        print(f"HARNESS FAIL: {type(exc).__name__}: {exc}",file=sys.stderr); raise
