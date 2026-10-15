# AURA P0-0 Evidence Preservation Kit v1.0.2 — Candidate

## Status

- P0-0 gate: `OPEN / REMEDIATION REQUIRED`
- Stage 1: `PENDING — LOCK GENERATION AND LIVE CI REQUIRED`
- Stage 2: `NOT AUTHORIZED`
- Mutational lock for the `vaidt` repositories: `ACTIVE`

This version updates the dependency-lock workflow, H-19/H-20 accounting, network namespace assertions, and execution log retention. It is a candidate tool pack, not a fully approved Stage 1 run. The complete `requirements-stage1.lock` is intentionally absent because it could not be generated and validated in the current environment without CPython 3.12, the approved `pip-tools==7.4.1` builder, and access to PyPI. No manually written lock or guessed hashes are included.

## Repository-root layout

Unpack the candidate's contents directly into the root of the dedicated AURA tooling repository/branch, preserving `.github/workflows/` and `scripts/`.

## 1. Generate and verify the lock

Run in an approved builder with CPython 3.12, Ubuntu 24.04-compatible resolver context, pip-tools 7.4.1 pre-provisioned from a separately approved/hash-locked toolchain, and controlled PyPI access:

```bash
PYTHON_BIN=python3.12 ./scripts/regenerate_stage1_lock.sh
./scripts/verify_stage1_lock.sh
```

The generator reads `requirements-stage1.in`, compiles the complete dependency graph using `pip-compile --generate-hashes`, installs the temporary lock in a clean venv using `--require-hashes --no-deps`, runs `pip check`, verifies all required distributions including `rpds-py` and the `format-nongpl` dependencies, and proves that `FormatChecker` accepts a correct RFC 3339 `date-time` and rejects one without a timezone. It atomically writes the lock only if every check passes.

Review and commit the generated `requirements-stage1.lock`. Do not hand-edit hashes. A missing lock causes the Stage 1 workflow to fail before test execution.

## 2. Execute Stage 1

After the generated lock is in the tooling branch, manually launch `.github/workflows/stage1-native-harness.yml` from GitHub Actions.

The workflow:

- uses `ubuntu-24.04`, read-only repository permissions, and action SHAs pinned in the YAML;
- installs only the committed hash-locked Python environment and runs `pip check`;
- performs a real OpenSSH `ssh-keygen -Y sign` / `-Y verify` preflight using a temporary test key;
- starts the harness in a `unshare -Urmn` network namespace and asserts the namespace has exactly `lo` and no IPv4 or IPv6 routes immediately before the harness runs;
- checks the harness's dynamic final report `20/20 test cases passed (4 positive + 16 negative)` and preserves the actual exit status through `tee`;
- retains environment, dependency-install, SSHSIG, network-isolation, and harness logs as one Actions artifact for 90 days.

The workflow must remain fail-closed if the runner blocks user/network namespaces or any dependency, signature, or test assertion fails.

## 3. Test case numbering

- H-19: `issues_prs` query must use `state=all` on every page.
- H-20: baseline fixture must pass, then changing only `capture_timestamp_utc` to a timezone-less value must yield a specific `date-time` validation failure.

The harness counts cases dynamically and stops before reporting success unless it has recorded exactly four positive and sixteen negative cases.

## 4. Local evidence from this authoring environment

See `TEST_RESULTS_v1.0.2.md` and `test-evidence/local-run-2026-10-15/`. Local static checks, schema meta-validation, the synthetic capture/semantic validator path, H-20, and a network namespace preflight passed. Lock generation was blocked because `python3.12` and `pip-compile` are unavailable. The full native harness exited `2` because the real system `ssh-keygen` is unavailable. No live GitHub API call or operation on real repositories was performed.

Do not interpret these partial local results as a passed GitHub Actions run or as evidence of a real captured/signature-verified snapshot.
