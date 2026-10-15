# Local test results — AURA P0-0 Remediation Pack v1.0.2

**Execution mode:** local, static/synthetic only. **No GitHub Actions run.**

## Results

| Check | Result | Evidence |
|---|---|---|
| `bash -n` for capture/verifier/harness and lock scripts | PASS | `test-evidence/local-run-2026-10-15/static-checks-final.log` |
| In-memory Python compilation | PASS | Same log; no bytecode files written |
| JSON Schema Draft 2020-12 meta-validation | PASS | Same log |
| Workflow YAML syntax parse and `bash -n` for each workflow `run:` block | PASS | `test-evidence/local-run-2026-10-15/static-checks-final.log`; workflow has expected jobs/permissions and each extracted shell block parses |
| Local capture/semantic validation over 13 synthetic repos and loopback mock API | PASS | `h20-format-check.log` includes successful H-17 capture fixture |
| H-20 baseline valid, then only date-time value changed | PASS | `h20-format-check.log`; validator reports `['capture_timestamp_utc'] ... is not a 'date-time'` |
| Network namespace check: only `lo`, no IPv4/IPv6 routes | PASS | `network-isolation-preflight.log`; exit `0` |
| Generate `requirements-stage1.lock` | BLOCKED | `lock-generation-attempt.log`; target CPython 3.12 is unavailable, `pip-compile` is absent, and external PyPI resolution is unavailable |
| Full native SSHSIG harness | BLOCKED | `native-harness-attempt.log`; harness exits `2` because system `ssh-keygen` is absent |

## Interpretation

The H-20 check was exercised directly against the local semantic validator using a synthetically captured snapshot. It demonstrates rejection for the specific malformed `date-time` value in the current interpreter environment, but it is **not** a verification against the not-yet-generated `requirements-stage1.lock` or specifically against `jsonschema==4.23.0` in CPython 3.12.

The network isolation assertion was executed locally in a new `unshare -Urmn` namespace and passed. This does not substitute for the same check on the actual `ubuntu-24.04` GitHub Actions runner.

No result is claimed for the complete H-01..H-20 native harness. No production API access, live repository clone, signing operation on a real capture manifest, or repository mutation was performed.

## Gate decision

`OPEN / REMEDIATION REQUIRED` remains mandatory. First generate and verify the lock in the approved target builder, then run the workflow on GitHub Actions and review the complete artifact bundle before authorizing any later live capture.
