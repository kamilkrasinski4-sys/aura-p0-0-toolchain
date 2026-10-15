# Stage 1 dependency lock — generation status

**Status: `BLOCKED — NO VERIFIED requirements-stage1.lock GENERATED`**

This package intentionally does not ship a hand-authored or guessed `requirements-stage1.lock`.
The current execution environment has CPython 3.13.5, does not provide `python3.12` or `pip-compile`, and cannot resolve external PyPI hosts from the container. Therefore the required target-platform compilation and hash-checked installation could not be performed here.

## Approved generation procedure

Run from an approved builder that provides CPython 3.12, `pip-tools==7.4.1` installed from a separately approved/hash-locked toolchain, and controlled connectivity to PyPI:

```bash
PYTHON_BIN=python3.12 ./scripts/regenerate_stage1_lock.sh
./scripts/verify_stage1_lock.sh
```

The generator compiles `requirements-stage1.in` with `pip-compile --upgrade --generate-hashes --resolver=backtracking`, writes to a temporary file, then performs a hash-enforced installation with `--no-deps`, `pip check`, required distribution inventory, and positive/negative `FormatChecker` assertions. It replaces `requirements-stage1.lock` only after all those checks succeed.

The generated lock must be reviewed, committed to the dedicated tooling branch, and its SHA-256 included in the review record before Stage 1 CI can proceed. The Stage 1 workflow deliberately fails at `Require Generated Dependency Lock` while the lock is absent, empty, not pip-compile-generated, missing `jsonschema==4.23.0`, or missing `rpds-py`.

**No hashes were manually substituted, and no unverified lock is represented as generated or validated.**
