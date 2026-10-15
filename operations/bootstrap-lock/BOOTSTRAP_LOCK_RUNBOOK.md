# AURA P0-0 — Bootstrap Lock Overlay v1.0.2

**Status:** local deployment overlay; not yet installed in GitHub and not CI evidence.

## Purpose

This overlay adds `.github/workflows/bootstrap-lock.yml` to the dedicated AURA P0-0 tooling repository. It runs only on manual `workflow_dispatch`, uses `ubuntu-24.04` and CPython 3.12 x64, installs the pinned bootstrap resolver `pip-tools==7.4.1`, invokes the existing lock-generation and lock-verification scripts, and uploads the lock plus execution/fingerprint logs as a 90-day artifact.

The workflow is read-only with respect to repository contents (`permissions: contents: read`) and does **not** commit or push the generated lock. This prevents the bootstrap run from changing repository state automatically.

## Required order

1. Install this file at `.github/workflows/bootstrap-lock.yml` in the designated AURA P0-0 tooling repository. Do not install it in any frozen `vaidt/*` target repository.
2. Confirm the checked-out commit contains `requirements-stage1.in`, `scripts/regenerate_stage1_lock.sh`, `scripts/verify_stage1_lock.sh`, and `.github/workflows/stage1-native-harness.yml` from candidate v1.0.2.
3. In **Actions → AURA P0-0 Bootstrap Dependencies Lock → Run workflow**, select the reviewed tooling branch and run manually.
4. Require the workflow to finish successfully and the artifact `aura-p0-0-lock-bootstrap-evidence` to contain `requirements-stage1.lock`, `bootstrap_lock.sha256`, and `bootstrap_lock_generation.log` with `BOOTSTRAP_LOCK_RESULT: PASS`.
5. Download the artifact. Locally run `sha256sum -c bootstrap_lock.sha256` from the directory containing `requirements-stage1.lock`; preserve the unmodified artifact and the verified output as evidence.
6. Only after that check, review and commit `requirements-stage1.lock` to the **tooling repository**. Record the commit SHA and preserve the bootstrap workflow run URL / run ID. Do not alter or unfreeze any `vaidt/*` target repository.
7. Then manually run `AURA P0-0 Stage 1 Native Harness` against the commit containing the lock. Preserve its environment, dependency, SSHSIG, network isolation, and harness logs. Stage 1 is not accepted unless the authentic runner log reports exactly `HARNESS RESULT: 20/20 test cases passed (4 positive + 16 negative)` and the network isolation evidence is present in the artifact.

## Evidence interpretation

- A generated artifact is evidence of a workflow execution, not proof of authority or production readiness by itself.
- `bootstrap_lock.sha256` binds the downloaded lock bytes to the recorded digest; it does not authenticate the workflow run. Preserve the GitHub run identity and artifact together.
- A local/static check, a successful lock-generation workflow, and a successful native harness are distinct evidence states. Do not collapse them.
- A failed or incomplete workflow leaves P0-0 `OPEN / REMEDIATION REQUIRED`.

## Current execution state

No GitHub repository was mutated by preparing this overlay. The destination tooling repository has not been unambiguously identified in the instruction context. A GitHub Actions `workflow_dispatch` capability is available through the connected GitHub integration, but dispatching cannot safely proceed before the target repository and branch are known; the existing `vaidt/*` repositories are explicitly frozen. Consequently, no GitHub Actions run ID, artifact, generated lock, or native 20/20 result is claimed by this package.
