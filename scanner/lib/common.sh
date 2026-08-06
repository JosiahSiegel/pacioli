# lib/common.sh — Shared helpers for scan.sh.
#
# Sourced by scan.sh and anythin in scanner/.
# Provides:
#   - run_id generation (scope-derived, UTC-date-suffixed, sortable)
#   - output_dir management (under .checkov/<run_id>/)
#   - trap-and-cleanup for storage firewall IP whitelist
#   - logging control (verbose + redact SAS)
#   - safety guard (sourced from safety.sh)
#
# This file does NOT call any Azure-mutating commands except those in
# cleanup_ip_whitelist (which is the paired partner of tf_init.sh's add).

# Source guard.
[[ -n "${__COMMON_SH_LOADED:-}" ]] && return 0
__COMMON_SH_LOADED=1

# Pull in safety guards first.
# shellcheck source=lib/safety.sh
source "$(dirname "${BASH_SOURCE[0]}")/safety.sh"

# ---------------------------------------------------------------------------
# Force UTF-8 for all Python subprocesses (checkov, aggregate.py, etc.).
#
# Why: Windows Python defaults to cp1252 for file I/O. Some .tf modules embed
# JSON-encoded strings with emoji glyphs (KQL workbook titles, ADF dashboard
# panels) — e.g. ⏳ (E2 8F B3) and ⚠ (E2 9A A0). Checkov's context parser calls
# file.readlines() with no encoding override and crashes on the byte 0x8F
# (the second byte of those emoji multi-byte sequences). Setting PYTHONIOENCODING
# + PYTHONUTF8 makes Python use UTF-8 everywhere — file reads, stdout, stderr,
# and the default encoding for open().
# Exported here so every script that sources this lib inherits it.
# ---------------------------------------------------------------------------
export PYTHONIOENCODING=utf-8
export PYTHONUTF8=1
export LC_ALL="${LC_ALL:-C.UTF-8}"
export LANG="${LANG:-C.UTF-8}"

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------
# Pacioli does NOT live inside the Terraform repo. The consumer points at
# the Terraform repo via PACIOLI_TARGET_REPO (default: the current working
# directory). Mapping files live INSIDE the pacioli install (under
# mappings/) and can be overridden via PACIOLI_MAPPING.
#
# Example:
#   export PACIOLI_TARGET_REPO=/path/to/terraform-repo
#   export PACIOLI_MAPPING=/path/to/soc2_mapping.yaml
#
# Backward compat: if PCI_REPO_ROOT is set in the environment, use it.
# ---------------------------------------------------------------------------
PACIOLI_TARGET_REPO="${PACIOLI_TARGET_REPO:-${PCI_REPO_ROOT:-$(pwd)}}"
# Resolve to absolute path. MSYS Git Bash on Windows mangles S:/ paths into
# /s/ via pwd, so we canonicalize via cd in a subshell. We do NOT use
# realpath because it does not resolve S:/ paths correctly on Windows.
if [[ -d "$PACIOLI_TARGET_REPO" ]]; then
  PACIOLI_TARGET_REPO="$(cd "$PACIOLI_TARGET_REPO" && pwd)"
fi
if [[ ! -d "$PACIOLI_TARGET_REPO" ]]; then
  echo "FATAL: PACIOLI_TARGET_REPO does not exist: $PACIOLI_TARGET_REPO" >&2
  exit 2
fi

# Mapping file location. Default: <pacioli install>/mappings/pci_dss_4.0.1.yaml.
# Allow override via --mapping or PACIOLI_MAPPING.
# The mapping pack lives at <repo>/mappings/, NOT <repo>/scanner/mappings/.
# We compute PACIOLI_INSTALL_DIR from the location of common.sh (lib/common.sh),
# so the install root is ../../ not ../.
# Do not use realpath; see PACIOLI_TARGET_REPO above.
PACIOLI_INSTALL_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
PACIOLI_DEFAULT_MAPPING="${PACIOLI_INSTALL_DIR}/mappings/pci_dss_4.0.1.yaml"
PACIOLI_MAPPING="${PACIOLI_MAPPING:-${PACIOLI_DEFAULT_MAPPING}}"

# Backward-compat aliases for legacy callers that read PCI_* names.
PCI_REPO_ROOT="$PACIOLI_TARGET_REPO"
PCI_SCOPE_FILE="${PACIOLI_TARGET_REPO}/pci_scope.yaml"
PCI_MAPPING_FILE="$PACIOLI_MAPPING"
PCI_BASELINE_FILE="${PACIOLI_TARGET_REPO}/pci_baseline.yaml"

# Local cache root for scan artifacts (never in git; see .gitignore).
# Default: under the consumer's Terraform repo as .checkov/ (same drive as
# the .tf code, so checkov doesn't choke on cross-drive paths).
PCI_CACHE_ROOT="${PCI_CACHE_ROOT:-${PACIOLI_TARGET_REPO}/.checkov}"

# ---------------------------------------------------------------------------
# Azure storage account for state-file archive + IP whitelist
# ---------------------------------------------------------------------------
# Override these for any Azure tenant. The defaults are placeholder values
# (originally seeded from the project's first deployment). For any other
# tenant, set:
#   export PCI_STATE_STORAGE_ACCOUNT=mystorage
#   export PCI_REPORTS_CONTAINER=iac-reports
# before invoking the scanner.
# ---------------------------------------------------------------------------
PCI_STATE_STORAGE_ACCOUNT="${PCI_STATE_STORAGE_ACCOUNT:-iacsa}"
PCI_REPORTS_CONTAINER="${PCI_REPORTS_CONTAINER:-iac-reports}"

# ---------------------------------------------------------------------------
# Run ID
# ---------------------------------------------------------------------------
# Two generation paths:
#   init_run_dir              Legacy UTC-timestamp-PID (kept for selftest and
#                             backward compatibility). Example output:
#                             .checkov/20260804T143000Z-8347
#   init_pretty_run_dir <pairs_tsv>  [envir-args…]
#                             Derive a memorable, scope-aware id from the
#                             content of a (project TAB env) pairs file. The
#                             id is suffixed with the UTC calendar date so
#                             it's both findable AND sortable. If the dir
#                             already exists (re-run same scope same day), an
#                             "-HHMM" suffix and a numeric counter are
#                             appended.
#   init_run_dir_labeled <label>  [envir-args…]
#                             Use a caller-provided label verbatim (sanitized
#                             to [A-Za-z0-9_-]). Suffixed with the UTC date
#                             for ordering.

# Sanitize a candidate label/name component to [A-Za-z0-9_.-]. Anything
# else becomes a single dash, with leading/trailing dashes and dots
# stripped. Empty (after stripping) returns 'x' (placeholder).
# Note: the dash MUST go at the END of the char class ([A-Za-z0-9_.-]),
# otherwise bash treats it as a range delimiter and gets confused by the
# reversed _..- range (0x5F > 0x2D).
sanitize_name() {
  local s="$1"
  s="${s//[^A-Za-z0-9_.-]/-}"
  # strip leading/trailing dashes and dots
  while [[ "$s" == -* ]]; do s="${s#-}"; done
  while [[ "$s" == *- ]]; do s="${s%-}"; done
  [[ -z "$s" ]] && s="x"
  echo "$s"
}

# Compute the next non-colliding dir under PCI_CACHE_ROOT by appending
# -HHMM, then -2, -3, etc.
# Args: <base_name_without_path>  <full_target_path>
resolve_collision_free_dir() {
  local base="$1"; local full="$2"
  if [[ ! -d "$full" ]]; then
    echo "$full"; return 0
  fi
  local hhmm
  hhmm="$(date -u +%H%M)"
  local attempt="${full}-${hhmm}"
  if [[ ! -d "$attempt" ]]; then
    echo "$attempt"; return 0
  fi
  local n=2
  while [[ -d "${full}-${hhmm}-${n}" ]]; do
    n=$((n + 1))
  done
  echo "${full}-${hhmm}-${n}"
}

# Legacy: UTC basic ISO-8601 + PID. Kept for selftest and any script that
# still calls it explicitly.
init_run_dir() {
  local ts; ts="$(date -u +%Y%m%dT%H%M%SZ)"
  local rid="${ts}-$$"
  RUN_DIR="${PCI_CACHE_ROOT}/${rid}"
  mkdir -p "${RUN_DIR}"
  echo "${RUN_DIR}"
}

# Derive a scope-aware run id from a tab-separated (project TAB env) pairs
# file. The id is "<slug>-<UTC-date>" where:
#   <slug> = "all"                              when scope includes every
#                                              in-scope project across all
#                                              envs (i.e. no filters)
#          = "all-<env>"                        when scope is every project
#                                              but only one env (e.g.
#                                              --env prod)
#          = "<proj>"                           when scope is one project
#                                              across multiple envs
#          = "<proj>-<env>"                     when scope is exactly one
#                                              (project, env) pair
# Args:
#   $1                       Tab-separated (project TAB env) pairs file
# Env (optional override):
#   PCI_RUN_NAME             Operator-supplied slug to use instead of the
#                            derived one. Useful for catching cross-team
#                            reference IDs like "q4-review" or "audit-nov".
init_pretty_run_dir() {
  local pairs_file="$1"
  [[ -f "$pairs_file" ]] || {
    echo "init_pretty_run_dir: pairs file not found: $pairs_file" >&2
    return 1
  }
  local today; today="$(date -u +%Y-%m-%d)"

  # Count unique projects and envs. Filter out blank lines and lines
  # without a tab; the script that wrote this file is responsible for
  # emitting only valid (project TAB env) pairs, but we defend against
  # stray CRLF / partial writes here.
  local pairs
  pairs="$(awk -F'\t' 'NF>=2 && $1 != "" && $2 != "" {print $1 "\t" $2}' "$pairs_file")"
  if [[ -z "$pairs" ]]; then
    # Empty scope: fall back to a date+slug form. Echo the
    # PROJECT_FILTER / ENV_FILTER so the operator can see what they
    # asked for (helpful when --project X matched zero in-scope envs).
    local tag=""
    if [[ -n "${PROJECT_FILTER:-}" && -n "${ENV_FILTER:-}" ]]; then
      tag="$(sanitize_name "$PROJECT_FILTER")-$(sanitize_name "$ENV_FILTER")"
    elif [[ -n "${PROJECT_FILTER:-}" ]]; then
      tag="$(sanitize_name "$PROJECT_FILTER")"
    elif [[ -n "${ENV_FILTER:-}" ]]; then
      tag="all-$(sanitize_name "$ENV_FILTER")"
    else
      tag="empty"
    fi
    local rid="${tag}-${today}"
    RUN_DIR="${PCI_CACHE_ROOT}/${rid}"
    RUN_DIR="$(resolve_collision_free_dir "${rid}" "${RUN_DIR}")"
    mkdir -p "${RUN_DIR}"
    echo "${RUN_DIR}"
    return 0
  fi

  # Read unique projects + envs. Sort, join with "-". Project names that
  # contain dashes are preserved verbatim (sanitize collapses illegal
  # chars only).
  local projs envs
  projs="$(echo "$pairs" | awk -F'\t' '{print $1}' | sort -u)"
  envs="$(echo "$pairs" | awk -F'\t' '{print $2}' | sort -u)"
  local n_projs n_envs
  n_projs="$(echo "$projs" | wc -l | tr -d ' ')"
  n_envs="$(echo "$envs" | wc -l | tr -d ' ')"

  local slug
  if [[ -n "${PCI_RUN_NAME:-}" ]]; then
    slug="$(sanitize_name "$PCI_RUN_NAME")"
  elif [[ $n_projs -eq 1 && $n_envs -eq 1 ]]; then
    slug="$(sanitize_name "$(echo "$projs" | head -n1)")-$(sanitize_name "$(echo "$envs" | head -n1)")"
  elif [[ $n_projs -eq 1 ]]; then
    slug="$(sanitize_name "$(echo "$projs" | head -n1)")"
  elif [[ $n_envs -eq 1 ]]; then
    slug="all-$(sanitize_name "$(echo "$envs" | head -n1)")"
  else
    slug="all"
  fi
  local rid="${slug}-${today}"
  RUN_DIR="${PCI_CACHE_ROOT}/${rid}"
  RUN_DIR="$(resolve_collision_free_dir "${rid}" "${RUN_DIR}")"
  mkdir -p "${RUN_DIR}"
  echo "${RUN_DIR}"
}

# Caller-supplied label, sanitized to [A-Za-z0-9_-], suffixed with date.
# Args: <label>
init_run_dir_labeled() {
  local label="$1"
  [[ -z "$label" ]] && {
    echo "init_run_dir_labeled: empty label" >&2
    return 1
  }
  local today; today="$(date -u +%Y-%m-%d)"
  local slug; slug="$(sanitize_name "$label")"
  local rid="${slug}-${today}"
  RUN_DIR="${PCI_CACHE_ROOT}/${rid}"
  RUN_DIR="$(resolve_collision_free_dir "${rid}" "${RUN_DIR}")"
  mkdir -p "${RUN_DIR}"
  echo "${RUN_DIR}"
}

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
# Verbosity: export PCI_VERBOSE=1 for info-level; default is warn+ only.
pci_log() {
  local level="$1"; shift
  local ts
  ts="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  case "$level" in
    ERROR) echo "${ts} ERROR $*" >&2 ;;
    WARN)  [[ -n "${PCI_VERBOSE:-}" ]] && echo "${ts} WARN  $*" >&2 ;;
    INFO)  [[ -n "${PCI_VERBOSE:-}" ]] && echo "${ts} INFO  $*" >&2 ;;
    DEBUG) [[ -n "${PCI_DEBUG:-}" ]] && echo "${ts} DEBUG $*" ;;
  esac
  # Always return 0 so silent log calls don't fail the script under
  # `set -o pipefail`. (`case` adopts the exit status of the last command
  # executed in the matched branch, which is 1 when the `[[ ... ]]` test in a
  # silent WARN/INFO/DEBUG branch fails.)
  return 0
}

# ---------------------------------------------------------------------------
# redaction
# ---------------------------------------------------------------------------
# Wraps a command in `{ set +x; ... ; } 2>/dev/null` blocks to prevent
# accidental SAS / secret echo by `set -x` or `bash -x`.
# Usage: redact_cmd "your command here"
# Returns: the wrapped command as a string for eval (rarely used directly).
#
# Most callers should use safe_run_exec instead.
redact_cmd() {
  local cmd="$1"
  printf '{ set +x; } 2>/dev/null; %s; { set -x; } 2>/dev/null' "$cmd"
}

# safe_run_exec <cmd> [args...]
# Validates against refuse_if_mutating then executes with redaction.
# This is the ONLY way to run external commands in scan.sh.
#
# IMPORTANT: this function does NOT touch xtrace state. Callers may
# enable/disable -x as needed via the redact_cmd helper.
safe_run_exec() {
  local cmd_display="$*"
  pci_log DEBUG "exec: $cmd_display"
  refuse_if_mutating "$cmd_display"
  "$@"
  return $?
}

# ---------------------------------------------------------------------------
# Storage firewall IP whitelist cleanup
# ---------------------------------------------------------------------------
# Pairs with whitelist_my_ip (the add). Idempotent: re-verifies the IP is
# still in the firewall rules before removing it (handles the case where
# the rule was already removed by another process).
#
# Removes the IP that was added by THIS run. The IP is expected to be
# stored in ${RUN_DIR}/.whitelist_ip after whitelist_my_ip runs.
cleanup_ip_whitelist() {
  local ip_file="${RUN_DIR:-}/.whitelist_ip"
  if [[ ! -f "$ip_file" ]]; then
    pci_log INFO "no .whitelist_ip file at $ip_file; nothing to clean up"
    return 0
  fi
  local ip
  ip="$(cat "$ip_file" 2>/dev/null || true)"
  if [[ -z "$ip" ]]; then
    pci_log INFO ".whitelist_ip is empty; nothing to clean up"
    return 0
  fi

  # REFUSE_IF_MUTATING will allow az storage account network-rule remove
  # because it's in ALLOWED_EXCEPTIONS.
  pci_log INFO "removing storage firewall IP: $ip"
  if ! command -v az >/dev/null 2>&1; then
    pci_log WARN "az CLI not found; cannot remove IP $ip automatically. Manual cleanup required."
    return 1
  fi

  # Confirm IP is still present before removing (idempotency).
  local present
  present="$(az storage account network-rule list \
    --account-name "$PCI_STATE_STORAGE_ACCOUNT" \
    --query "ipRules[?ipAddressOrRange=='$ip'].ipAddressOrRange" \
    -o tsv 2>/dev/null || echo "")"
  if [[ -z "$present" ]]; then
    pci_log INFO "IP $ip already removed; skipping"
    return 0
  fi

  az storage account network-rule remove \
    --account-name "$PCI_STATE_STORAGE_ACCOUNT" \
    --ip-address "$ip" \
    --output none 2>/dev/null || pci_log WARN "failed to remove IP $ip; manual cleanup required"
}

# ---------------------------------------------------------------------------
# Storage firewall IP whitelist add (lightweight; no full tf_init.sh)
# ---------------------------------------------------------------------------
# Adds the current public IP to the $PCI_STATE_STORAGE_ACCOUNT storage firewall so
# terraform plan can read remote state. Idempotent: returns 0 if the IP
# is already present. Writes the IP to ${RUN_DIR}/.whitelist_ip so
# cleanup_ip_whitelist can remove it later.
#
# This is the ONLY Azure mutation the scan performs. It is paired with
# cleanup_ip_whitelist via the trap.
#
# Requires: az CLI logged in, RUN_DIR set.
whitelist_my_ip() {
  if [[ -z "${RUN_DIR:-}" ]]; then
    pci_log ERROR "RUN_DIR not set; cannot whitelist IP"
    return 1
  fi
  if ! command -v az >/dev/null 2>&1; then
    pci_log ERROR "az CLI not found; cannot whitelist IP"
    return 1
  fi

  local current_ip
  current_ip="$(curl --ssl-no-revoke --silent --show-error https://api.ipify.org || true)"
  if [[ -z "$current_ip" ]]; then
    pci_log ERROR "failed to detect current public IP"
    return 1
  fi
  pci_log INFO "current public IP: $current_ip"

  # Check if already whitelisted.
  local existing
  existing="$(az storage account network-rule list \
    --account-name "$PCI_STATE_STORAGE_ACCOUNT" \
    --query "ipRules[?ipAddressOrRange=='$current_ip'].ipAddressOrRange" \
    -o tsv 2>/dev/null || echo "")"
  if [[ -n "$existing" ]]; then
    pci_log INFO "IP $current_ip already whitelisted; skipping add"
    echo "$current_ip" > "${RUN_DIR}/.whitelist_ip"
    return 0
  fi

  pci_log INFO "whitelisting IP $current_ip on $PCI_STATE_STORAGE_ACCOUNT"
  # ALLOWED_EXCEPTIONS: this is the only allowed mutation.
  az storage account network-rule add \
    --account-name "$PCI_STATE_STORAGE_ACCOUNT" \
    --ip-address "$current_ip" \
    --output none 2>/dev/null || {
      pci_log ERROR "failed to add IP $current_ip to firewall"
      return 1
    }

  # Verify with retry (Azure propagation delay).
  local i
  for i in 1 2 3 4 5; do
    sleep 10
    existing="$(az storage account network-rule list \
      --account-name "$PCI_STATE_STORAGE_ACCOUNT" \
      --query "ipRules[?ipAddressOrRange=='$current_ip'].ipAddressOrRange" \
      -o tsv 2>/dev/null || echo "")"
    if [[ -n "$existing" ]]; then
      pci_log INFO "IP $current_ip confirmed whitelisted"
      echo "$current_ip" > "${RUN_DIR}/.whitelist_ip"
      return 0
    fi
    if [[ $i -eq 5 ]]; then
      pci_log ERROR "failed to verify IP $current_ip added after 5 retries"
      return 1
    fi
  done
  echo "$current_ip" > "${RUN_DIR}/.whitelist_ip"
}

# ---------------------------------------------------------------------------
# Plan artifact cleanup
# ---------------------------------------------------------------------------
# Per PCI 10.7 hygiene: tfplan.binary and plan.json contain resolved
# Azure topology and may contain sensitive attribute values. Shred them
# on exit so they don't linger on disk.
shred_plan_artifacts() {
  local plan_bin="${RUN_DIR:-}/tfplan.binary"
  local plan_json="${RUN_DIR:-}/plan.json"
  if [[ -f "$plan_bin" ]]; then
    if command -v shred >/dev/null 2>&1; then
      shred -u "$plan_bin" 2>/dev/null || rm -f "$plan_bin"
    else
      rm -f "$plan_bin"
    fi
  fi
  if [[ -f "$plan_json" ]]; then
    if command -v shred >/dev/null 2>&1; then
      shred -u "$plan_json" 2>/dev/null || rm -f "$plan_json"
    else
      rm -f "$plan_json"
    fi
  fi
}

# ---------------------------------------------------------------------------
# Aggregator: refuses to do anything else; expect callers to validate.
# ---------------------------------------------------------------------------
require_file() {
  local f="$1"
  if [[ ! -f "$f" ]]; then
    pci_log ERROR "required file not found: $f"
    exit 2
  fi
}

# Parse python YAML once with a single Python invocation. Avoids spawning
# Python per key. Outputs JSON to stdout.
# Usage: yaml_to_json <yaml_file>
yaml_to_json() {
  python -c "import yaml, json, sys; print(json.dumps(yaml.safe_load(open(sys.argv[1]))))" "$1"
}

# Extract project entries from pci_scope.yaml as a single JSON array.
# Only 'in_scope' projects are scanned. 'pending' = attestation outstanding
# (skip — see pci_scope.yaml comments). 'excluded' = not in PCI scope at all
# (skip — e.g. sandbox).
# Usage: jq -c '.[] | select(.status == "in_scope")' <<<"$(load_pci_scope)"
load_pci_scope() {
  yaml_to_json "$PCI_SCOPE_FILE" | python -c "
import json, sys
data = json.load(sys.stdin)
projects = data.get('projects', [])
active = [p for p in projects if p.get('status') == 'in_scope']
print(json.dumps(active))
"
}

# Validate that an env dir exists and looks like a real Terraform env.
#
# An env is "real" if it has at least one of:
#   - terraform.aztfexport.tf  (aztfexport-generated backend config — present in ALL
#                               in-scope envs, generated on every aztfexport run)
#   - main.tf                  (hand-written entry point)
#   - main.aztfexport.tf       (aztfexport-merged entry point for small envs)
#   - provider.aztfexport.tf   (aztfexport-generated provider block)
#   - provider.tf              (hand-written provider block — e.g. when no
#                               provider.aztfexport.tf was generated)
# The previous implementation only accepted main.tf or provider.aztfexport.tf,
# which incorrectly rejected valid envs that use main.aztfexport.tf +
# provider.tf (the aztfexport-generated provider block).
require_env_dir() {
  local d="$1"
  if [[ ! -d "$d" ]]; then
    pci_log ERROR "env dir does not exist: $d"
    return 1
  fi
  # Exclude tilde-prefixed stub .tf files (e.g. ~locals.tf) from count.
  # They are placeholders; an env that only has tilde stubs is empty.
  local tf_count
  tf_count="$(find "$d" -maxdepth 1 -type f -name '*.tf' ! -name '~*' | wc -l)"
  if [[ "$tf_count" -eq 0 ]]; then
    pci_log ERROR "env dir has no .tf files (excluding ~stubs): $d"
    return 1
  fi
}

# Find the aztfexport files in an env dir; emit as space-separated list.
# These are the files we MUST skip during scan (and MUST NOT mutate).
# Note: provider.tf is intentionally NOT in this list — it's a real
# Terraform provider declaration, not an aztfexport artifact.
find_aztfexport_files() {
  local env_dir="$1"
  find "$env_dir" -maxdepth 1 -type f \( \
    -name "terraform.aztfexport.tf" -o \
    -name "provider.aztfexport.tf" -o \
    -name "main.aztfexport.tf" -o \
    -name "aztfexportResourceMapping.json" -o \
    -name "aztfexportSkippedResources.txt" \
    \) 2>/dev/null
}

# ---------------------------------------------------------------------------
# Self-test
# ---------------------------------------------------------------------------
common_selftest() {
  local failed=0
  if ! safety_selftest; then
    echo "FAIL: safety selftest" >&2
    failed=1
  fi

  # Test that init_run_dir produces a valid path
  local rid
  rid="$(init_run_dir)" || { echo "FAIL: init_run_dir" >&2; failed=1; }
  if [[ ! -d "$rid" ]]; then
    echo "FAIL: init_run_dir did not create dir: $rid" >&2
    failed=1
  fi

  # Test sanitize_name: illegal chars become -, dashes collapsed, empty
  # returns the placeholder.
  local sn
  sn="$(sanitize_name 'Foo_Bar/Prod v2.0')" || sn=""
  [[ "$sn" == "Foo_Bar-Prod-v2.0" ]] || {
    echo "FAIL: sanitize_name: '$sn'" >&2; failed=1; }
  sn="$(sanitize_name '/leading-and/trailing/')" || sn=""
  [[ "$sn" == "leading-and-trailing" ]] || {
    echo "FAIL: sanitize_name (leading/trailing): '$sn'" >&2; failed=1; }
  sn="$(sanitize_name '')" || sn=""
  [[ "$sn" == "x" ]] || {
    echo "FAIL: sanitize_name (empty): '$sn'" >&2; failed=1; }

  # Test init_pretty_run_dir: produces a dir, applies collision logic.
  local tmp_pairs; tmp_pairs="$(mktemp)"
  printf 'PROJECT_A\tprod\nPROJECT_B\tprod\n' > "$tmp_pairs"
  local pretty1 pretty2
  pretty1="$(init_pretty_run_dir "$tmp_pairs")" || pretty1=""
  if [[ ! -d "$pretty1" ]]; then
    echo "FAIL: init_pretty_run_dir did not create dir: $pretty1" >&2
    failed=1
  fi
  # The second call resolves the collision (-HHMM or counter).
  pretty2="$(init_pretty_run_dir "$tmp_pairs")" || pretty2=""
  if [[ ! -d "$pretty2" ]]; then
    echo "FAIL: init_pretty_run_dir (collision) did not create dir: $pretty2" >&2
    failed=1
  fi
  if [[ "$pretty1" == "$pretty2" ]]; then
    echo "FAIL: init_pretty_run_dir collision handler returned same path: $pretty1 vs $pretty2" >&2
    failed=1
  fi
  rm -rf "$pretty1" "$pretty2" "$tmp_pairs"

  # Test init_run_dir_labeled: honors a user-supplied slug.
  local labeled
  unset PCI_RUN_NAME
  labeled="$(init_run_dir_labeled 'q4-review')" || labeled=""
  if [[ ! -d "$labeled" ]]; then
    echo "FAIL: init_run_dir_labeled did not create dir: $labeled" >&2
    failed=1
  fi
  rm -rf "$labeled"

  # Test yaml_to_json on a real file
  if ! yaml_to_json "$PCI_SCOPE_FILE" >/dev/null 2>&1; then
    echo "FAIL: yaml_to_json on pci_scope.yaml" >&2
    failed=1
  fi

  # Test load_pci_scope
  local scope
  scope="$(load_pci_scope)" || { echo "FAIL: load_pci_scope" >&2; failed=1; }
  if [[ -z "$scope" ]]; then
    echo "FAIL: load_pci_scope returned empty" >&2
    failed=1
  fi

  # Confirm exclusions
  if [[ "$scope" == *rg-example* ]]; then
    echo "FAIL: load_pci_scope included rg-example" >&2
    failed=1
  fi

  rm -rf "$rid"
  return $failed
}
