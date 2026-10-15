# Release Notes — AURA P0-0 Remediation Pack v1.0.1

**Classification:** Candidate tooling pack; not a canonical AURA standard.
**Gate:** `OPEN / REMEDIATION REQUIRED`.

## Fixed

- F-02: removed compiled Python artifacts and added `.gitignore` rules for `__pycache__/`, `*.py[cod]`, `*.swp`, and `.DS_Store`.
- F-03: aligned the capture runbook with the implemented CLI: positional `base_output_dir`, plus `--schema <path>` and optional `--force`. The harness now invokes the schema flag explicitly.
- F-04: defined the `issues_prs` endpoint contract as `state=all`; the capture engine emits that query parameter, requires it on every pagination URL, and the semantic validator rejects pages without it.
- Harness: added H-19, a negative fixture that removes `state=all` from the issue trace and must be rejected.
- SHA256SUMS: regenerated for this clean v1.0.1 release.

## Verification status

Static checks and CLI help checks may be performed in this environment. Full harness execution requiring native OpenSSH `ssh-keygen` is pending because that executable is unavailable here. No live GitHub requests were made and no live `vaidt` repositories were cloned. Therefore `CANDIDATE TOOLING PACK — VERIFIED ON TEST FIXTURES` describes the intended release classification only after its fixture suite is executed successfully on a host with native OpenSSH; this archive itself has not obtained a new 19/19 native-OpenSSH test result.
