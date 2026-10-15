#!/usr/bin/env bash
# Verify a committed pip-compile lock on CPython 3.12 / Ubuntu 24.04.
set -euo pipefail
IFS=$'\n\t'
ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
LOCK="${ROOT}/requirements-stage1.lock"
PYTHON_BIN="${PYTHON_BIN:-python3.12}"

[[ -s "${LOCK}" ]] || { echo "FAIL: requirements-stage1.lock missing/empty" >&2; exit 1; }
[[ -f "${ROOT}/requirements-stage1.in" ]] || { echo "FAIL: requirements-stage1.in missing" >&2; exit 1; }
"${PYTHON_BIN}" --version
TMP_ENV="$(mktemp -d)"
trap 'rm -rf -- "${TMP_ENV}"' EXIT
"${PYTHON_BIN}" -m venv "${TMP_ENV}/venv"
"${TMP_ENV}/venv/bin/python" -m pip install --require-hashes --no-deps -r "${LOCK}"
"${TMP_ENV}/venv/bin/python" -m pip check
"${TMP_ENV}/venv/bin/python" - <<'PY'
import importlib.metadata
from jsonschema import FormatChecker
from jsonschema.exceptions import FormatError

installed = {d.metadata["Name"].lower().replace("_", "-") for d in importlib.metadata.distributions() if d.metadata.get("Name")}
required = {"jsonschema", "attrs", "jsonschema-specifications", "referencing", "rpds-py", "fqdn", "idna", "isoduration", "arrow", "python-dateutil", "six", "tzdata", "jsonpointer", "rfc3339-validator", "rfc3986-validator", "uri-template", "webcolors"}
missing = sorted(required - installed)
if missing:
    raise SystemExit(f"Missing required distributions: {missing}")
fc = FormatChecker()
fc.check("2026-10-15T21:03:21Z", "date-time")
try:
    fc.check("2026-10-15T21:03:21", "date-time")
except FormatError:
    print("PASS: FormatChecker rejects timezone-less date-time")
else:
    raise SystemExit("FAIL: date-time check unexpectedly accepted invalid timestamp")
print("PASS: lock hashes accepted, dependency graph present, pip check clean")
PY
