# AURA P0-0 — Remediation Report v1.0.2

**Gate:** `AURA-P0-0-PRESERVATION-AUDIT`  
**Gate status:** `OPEN / REMEDIATION REQUIRED`  
**Tooling status:** `CANDIDATE TOOLING PACK — LOCAL CHECKS PARTIAL`  
**Assessment:** Static review plus local synthetic checks; no GitHub Actions execution and no live GitHub capture.

## 1. Work performed

| Finding | Implemented change | Current evidence/status |
|---|---|---|
| CI-01 — generated dependency hashes | Added `requirements-stage1.in` and `scripts/regenerate_stage1_lock.sh`; it compiles with `pip-compile --generate-hashes` and verifies generated hashes through isolated install | **BLOCKED:** this host lacks CPython 3.12 and pip-tools; no lock was generated or represented as verified |
| CI-02 — full dependency graph | Lock generation requires the entire graph from `jsonschema[format-nongpl]==4.23.0`; checks explicitly include `rpds-py`, `arrow`, `python-dateutil`, `six`, `tzdata`, plus the format validators; `pip check` validates transitive completeness | **PENDING lock generation** |
| CI-03 — FormatChecker | Added H-20 while preserving H-19. H-20 validates the unmodified fixture, then changes only `capture_timestamp_utc` and requires the error to name the field and `date-time` | **PASS on current local synthetic fixture; locked Python 3.12 environment not yet tested** |
| CI-04 — network isolation | Workflow asserts exactly one interface (`lo`) and no IPv4/IPv6 routes in the same `unshare -Urmn` process that runs the harness | **PASS locally in current container; GitHub runner not tested** |
| CI-05 — error propagation and fingerprints | Explicit Bash `set -euo pipefail`, pipeline status checks, and SHA-256 fingerprints for the schema, validator, capture/verifier/harness code, input and generated lock | **Static checks PASS** |
| CI-06 — execution logs | Workflow stores environment, dependency, SSHSIG, network namespace, and full harness logs; artifact retention is 90 days | **Workflow syntax parsed; no artifact from a GitHub Actions run exists** |
| CI-07 — native SSHSIG | Added preflight to generate an Ed25519 test key, sign a payload, and verify it with the native `ssh-keygen` | **BLOCKED locally: `ssh-keygen` unavailable** |
| CI-08 — H-01..H-20 | Harness dynamically counts cases and requires exactly 20 (4 positive + 16 negative) before emitting the final success line | **Not run end-to-end because system `ssh-keygen` is unavailable** |

## 2. Test H-20 accounting

H-19 remains reserved for rejection of an `issues_prs` pagination trace that omits `state=all`.

H-20 is the date-time regression test. Its precondition requires the full fixture to pass first; the only mutation is:

```json
"capture_timestamp_utc": "2026-10-15T21:03:21"
```

The validator must reject this value specifically as a `date-time` error. The local recorded result is:

```text
BASELINE_VALIDATION_EXIT=0
INVALID_DATE_VALIDATION_EXIT=1
FAIL: JSON Schema validation failed at ['capture_timestamp_utc']: '2026-10-15T21:03:21' is not a 'date-time'
PASS H-20: validator rejected only the malformed date-time path as expected
```

The complete harness requires 20 distinct cases: H-01 through H-20 with H-19 and H-20 preserving separate meanings; 4 positive and 16 negative cases are checked by dynamic counters.

## 3. Dependency-lock disposition

The repository/package deliberately does not contain a hand-edited `requirements-stage1.lock`. The current environment identified CPython 3.13.5, no `python3.12`, no `pip-compile`, and no external PyPI resolution. The generation attempt exited nonzero before changing any lock output.

The lock-generation script is fail-closed and must be run on an approved CPython 3.12 / Ubuntu 24.04-compatible builder where `pip-tools==7.4.1` is already provisioned through a separately approved toolchain. It will only replace `requirements-stage1.lock` after a fresh hashed compilation, isolated `pip install --require-hashes --no-deps`, `pip check`, explicit required-distribution checks, and the positive/negative format test all succeed.

The Stage 1 workflow checks that the lock is present, nonempty, pip-compile-generated, pins `jsonschema==4.23.0`, and explicitly contains `rpds-py`; it fails closed before the harness when that condition is not met. Thus this pack is not yet ready for a successful GitHub Actions run until the generated lock is provided.

## 4. Evidence artifacts

Local logs are included under `test-evidence/local-run-2026-10-15/`:

- `environment.log`
- `static-checks.log`
- `static-checks-final.log` (final syntax, schema/YAML, H-01..H-20 inventory, bytecode-hygiene and fail-closed lock-state checks)
- `lock-generation-attempt.log`
- `pip-tools-bootstrap-attempt.log`
- `lock-verification-attempt.log`
- `native-harness-attempt.log`
- `network-isolation-preflight.log`
- `h20-format-check.log`

## 5. Explicitly not performed

- No request was sent to `api.github.com`.
- No real `vaidt` repository was cloned, altered, archived, or deleted.
- No live repository capture was performed.
- No production manifest was generated or signed.
- The full H-01..H-20 harness was not executed with native OpenSSH.
- The complete hashed dependency lock was not generated or installed in this environment.
- No GitHub Actions workflow was triggered, and no GitHub Actions artifact exists yet.

## 6. Formal decision

`AURA-P0-0-PRESERVATION-AUDIT = OPEN / REMEDIATION REQUIRED`.

The static/test-fixture changes for H-20, network assertions, dynamic test accounting, and log preservation are implemented. CI-01/CI-02 are not closed until the actual lock is generated and verified in the approved target builder. CI-07/CI-08 remain pending until a GitHub Actions run successfully uses native OpenSSH and emits the complete `20/20 test cases passed (4 positive + 16 negative)` result.

Stage 2 remains `NOT AUTHORIZED`; the mutational lock remains `ACTIVE`.
