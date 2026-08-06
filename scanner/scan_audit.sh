#!/usr/bin/env bash
# scan_pci_audit.sh — Re-emit a prior PCI report from the iac-reports archive.
#
# Workflow:
#   1. Identify the run directory (--run-id) OR query the iac-reports
#      container for the most recent run.
#   2. Download the four aggregate files (coverage_matrix.csv,
#      combined.sarif, junit.xml, report.html) from
#      iacsa/iac-reports/<run_id>/.
#   3. Place them under .checkov/<run_id>/aggregate/ locally.
#   4. If --out is given, copy report.html there.
#
# This is a READ-ONLY operation. No terraform, no Azure mutations.
#
# Usage:
#   scan_pci_audit.sh --run-id <run_id> [--out <path>]
#   scan_pci_audit.sh --latest
#
# Args:
#   --run-id   The run ID to fetch (e.g. 20260804T153407Z-2455).
#   --latest   Fetch the most recent run_id from the iac-reports listing.
#   --out      Optional destination for report.html. Default: stdout path.
#   --dry-run  Print actions without downloading.

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib/common.sh
source "${SCRIPT_DIR}/lib/common.sh"

RUN_ID=""
LATEST=0
OUT_PATH=""
DRY_RUN=0
# Storage account + container for the iac-reports archive. Override
# with PCI_STATE_STORAGE_ACCOUNT and PCI_REPORTS_CONTAINER env vars.
STORAGE_ACCOUNT="${PCI_STATE_STORAGE_ACCOUNT:-iacsa}"
CONTAINER_NAME="${PCI_REPORTS_CONTAINER:-iac-reports}"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --run-id)  RUN_ID="$2"; shift 2 ;;
    --latest)  LATEST=1; shift ;;
    --out)     OUT_PATH="$2"; shift 2 ;;
    --dry-run) DRY_RUN=1; shift ;;
    --help|-h) cat <<EOF
Usage: $0 [--run-id <id> | --latest] [--out <path>] [--dry-run]

Re-emits a prior PCI report from the iac-reports archive. No re-scan.
EOF
      exit 0 ;;
    *) pci_log ERROR "unknown argument: $1"; exit 64 ;;
  esac
done

if [[ -z "$RUN_ID" && $LATEST -eq 0 ]]; then
  LATEST=1
fi

# Discover the run id.
if [[ $LATEST -eq 1 ]]; then
  pci_log INFO "fetching latest run_id from $CONTAINER_NAME"
  if [[ $DRY_RUN -eq 1 ]]; then
    RUN_ID="DRYRUN-LATEST"
  else
    # List blobs and pick the first folder-like prefix
    # Prefix ends with /; we want the parent dir name.
    RUN_ID="$(az storage blob list \
      --account-name "$STORAGE_ACCOUNT" \
      --container-name "$CONTAINER_NAME" \
      --auth-mode login \
      --query "[?contains(name, '/')].[name]" \
      -o tsv 2>/dev/null | awk -F'/' '{print $1}' | sort -u | tail -1)"
    if [[ -z "$RUN_ID" ]]; then
      pci_log ERROR "no runs found in $STORAGE_ACCOUNT/$CONTAINER_NAME"
      exit 2
    fi
  fi
fi

pci_log INFO "run_id: $RUN_ID"

# Local destination
dest_dir="${PCI_REPO_ROOT}/.checkov/${RUN_ID}/aggregate"
mkdir -p "$dest_dir"

# Files to fetch
files=(coverage_matrix.csv combined.sarif junit.xml report.html)
for f in "${files[@]}"; do
  if [[ $DRY_RUN -eq 1 ]]; then
    echo "[dry-run] az storage blob download --container-name $CONTAINER_NAME --name $RUN_ID/$f --file $dest_dir/$f"
  else
    pci_log INFO "downloading $f"
    if ! az storage blob download \
        --account-name "$STORAGE_ACCOUNT" \
        --container-name "$CONTAINER_NAME" \
        --name "$RUN_ID/$f" \
        --file "$dest_dir/$f" \
        --auth-mode login \
        --output none 2>&1; then
      pci_log WARN "failed to download $f"
    fi
  fi
done

pci_log INFO "audit complete: $dest_dir"
if [[ -n "$OUT_PATH" && -f "$dest_dir/report.html" ]]; then
  cp "$dest_dir/report.html" "$OUT_PATH"
  pci_log INFO "report.html copied to: $OUT_PATH"
fi
ls -la "$dest_dir"
