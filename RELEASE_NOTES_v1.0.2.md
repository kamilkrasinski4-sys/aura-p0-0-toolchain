# AURA P0-0 Remediation Pack v1.0.2 — release notes

## Implemented in this candidate

- Added `requirements-stage1.in` as the single source dependency declaration: `jsonschema[format-nongpl]==4.23.0`.
- Added a target-specific pip-tools lock generation/verification script. It requires a pre-provisioned `pip-tools==7.4.1` environment on CPython 3.12, compiles with hashes, verifies an isolated hash-enforced installation and `pip check`, tests active `date-time` validation, then atomically publishes the lock.
- The lock itself is **not included** because this execution environment lacks CPython 3.12 and pip-tools, and cannot resolve PyPI from the container. See `LOCK_GENERATION_STATUS.md`. No manually entered hash list is claimed as a generated lock.
- Added H-20: a negative `FormatChecker` test which first proves the full baseline fixture validates, changes only `capture_timestamp_utc`, and requires an error naming both `capture_timestamp_utc` and `date-time`.
- Preserved H-19 for `issues_prs state=all`; dynamic test accounting now requires exactly 20 cases (4 positive + 16 negative).
- Added `.github/workflows/stage1-native-harness.yml`, with a fail-closed lock precondition, hash-enforced dependency installation, native OpenSSH SSHSIG preflight, network assertions in the same network namespace as the harness, and retention of five execution logs for 90 days.
- Added `scripts/verify_stage1_lock.sh` to re-check an already generated lock on the target platform.

## Explicit limitations

- The full 20-case harness was not executed: system `ssh-keygen` is unavailable in this environment.
- The complete pip-tools lock could not be generated or installed here.
- The network namespace assertion itself passed locally in the available container, but no GitHub Actions run has occurred.
- No request was made to `api.github.com`; no real `vaidt` repository was cloned or modified.

## Gate

`AURA-P0-0-PRESERVATION-AUDIT` remains `OPEN / REMEDIATION REQUIRED`.
The bundle is an updated candidate, not a CI-approved release and not evidence of live capture or SSHSIG interoperability.
