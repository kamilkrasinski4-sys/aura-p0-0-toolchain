# AURA P0-0 Toolchain Seed v1.0.2 — Deployment Runbook

**State:** prepared local seed only; not committed to GitHub; no CI run is claimed.

## Intended control plane

Repository name: `aura-p0-0-toolchain`
Visibility: **private** (recommended default)
Default branch: `main`
Account: a separately authenticated audit/control-plane profile, explicitly not `vaidt`.

## Contents

The root contains the candidate AURA P0-0 Evidence Preservation Kit v1.0.2. It also contains `.github/workflows/bootstrap-lock.yml` from the Bootstrap Lock Overlay. The original source checksum files are retained under `provenance/`; the root `SHA256SUMS.txt` is a newly generated integrity list for the merged seed tree.

## Controlled execution sequence

1. Create the private repository `aura-p0-0-toolchain` in the separate authorized audit profile. Do not use the currently connected `vaidt` account and do not mutate any `vaidt/*` target repository.
2. Commit the seed contents to `main` after reviewing the diff and checksum provenance.
3. Run **AURA P0-0 Bootstrap Dependencies Lock** using `workflow_dispatch`. Accept only a successful run with artifact `aura-p0-0-lock-bootstrap-evidence` containing `requirements-stage1.lock`, `bootstrap_lock.sha256`, and `bootstrap_lock_generation.log` with `BOOTSTRAP_LOCK_RESULT: PASS`.
4. Download the artifact and verify the lock bytes using `sha256sum -c bootstrap_lock.sha256` from its containing directory. Preserve the unmodified artifact, run URL/ID and the verification output.
5. Commit the generated, verified `requirements-stage1.lock` to the tooling repository `main`. Do not hand-edit or synthesize hashes.
6. Dispatch **AURA P0-0 Stage 1 Native Harness** on that commit. Preserve the complete run logs and artifact `aura-p0-0-stage1-native-evidence`.
7. Stage 1 evidence is accepted only if the authentic runner log includes exactly `HARNESS RESULT: 20/20 test cases passed (4 positive + 16 negative)`, the Native OpenSSH SSHSIG preflight succeeds, hash-locked dependency installation and `pip check` succeed, and the network isolation log proves the harness ran with only loopback and no IPv4/IPv6 routes.

## State rules

A local seed, a GitHub commit, a Bootstrap run, a verified lockfile, and a passing Stage 1 harness are separate evidence states. Do not infer a later state from an earlier one. Until genuine Stage 1 runner logs and artifacts are preserved, P0-0 remains `OPEN / REMEDIATION REQUIRED`; the mutation block on all target `vaidt/*` repositories remains `ACTIVE`.
