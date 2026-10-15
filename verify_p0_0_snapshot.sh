#!/usr/bin/env bash
# Formal-only wrapper. No diagnostic/skip profile is accepted.
set -euo pipefail
IFS=$'\n\t'
if (( $# < 6 || $# > 7 )); then
  echo >&2 "Usage: $0 <snapshot_dir> <schema_file> --profile formal <allowed_signers> <principal> [namespace]"
  exit 2
fi
SNAPSHOT_DIR="$1"
SCHEMA_FILE="$2"
if [[ "$3" != "--profile" || "$4" != "formal" ]]; then
  echo >&2 "FAIL R10: this verifier only accepts --profile formal"
  exit 1
fi
ALLOWED_SIGNERS="$5"
PRINCIPAL="$6"
NAMESPACE="${7:-aura-governance}"
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
[[ -d "$SNAPSHOT_DIR" ]] || { echo >&2 "FAIL: snapshot directory missing"; exit 1; }
[[ -f "$SCHEMA_FILE" ]] || { echo >&2 "FAIL: schema file missing"; exit 1; }
[[ -f "$ALLOWED_SIGNERS" ]] || { echo >&2 "FAIL R10: allowed_signers file missing"; exit 1; }
[[ -n "$PRINCIPAL" && -n "$NAMESPACE" ]] || { echo >&2 "FAIL R10: principal/namespace required"; exit 1; }
exec python3 "${SCRIPT_DIR}/p0_0_snapshot_verify.py" \
  --snapshot-dir "$SNAPSHOT_DIR" \
  --schema "$SCHEMA_FILE" \
  --allowed-signers "$ALLOWED_SIGNERS" \
  --principal "$PRINCIPAL" \
  --namespace "$NAMESPACE"
