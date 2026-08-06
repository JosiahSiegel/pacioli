#!/usr/bin/env bash
# scan_pci.sh — Read-only PCI scan orchestrator.
#
# Runs the Plan B pipeline: terraform plan -json per in-scope env, then
# checkov on the plan JSON + secrets framework on the .tf source. NEVER
# mutates Azure. The only mutation is the storage firewall IP whitelist
# (added by tf_init.sh, removed by lib/common.sh::cleanup_ip_whitelist).
#
# Usage:
#   scan_pci.sh [--mode gate|report|audit] [--project P] [--env E]
#               [--scan-plan|--scan-state] [--dry-run] [--verbose]
#               [--no-aggregate] [--label TEXT] 
#
# Modes:
#   gate    — CI gate. --hard-fail-on HIGH,CRITICAL. Exits non-zero on findings.
#             Does NOT auto-aggregate (CI ingests SARIF artifacts directly).
#   report  — Manual scan. --soft-fail. Never blocks. (default for human runs)
#             Auto-runs aggregate_pci.py at the end and prints the report
#             path. Use --no-aggregate to skip.
#   audit   — Re-emit a prior report from archive. No re-scan, no aggregation
#             here (audit mode emits from archive).
#
# Steps per env:
#   1. terraform init -backend=false (provider cache only, no API calls)
#   2. terraform plan -out=tfplan.binary (acquires state lock, reads state)
#   3. terraform show -json tfplan.binary > plan.json
#   4. checkov -f plan.json --framework terraform_plan --output sarif
#   5. checkov -d <env_dir> --framework secrets --output sarif
#   6. shred tfplan.binary and plan.json (PCI 10.7 hygiene)
#
# Traps:
#   EXIT INT TERM — cleanup_ip_whitelist + shred_plan_artifacts

set -uo pipefail

# Source common helpers (which sources safety.sh). common.sh exports UTF-8 env
# vars needed by child Python processes (checkov, aggregate_pci.py) — see the
# comment in lib/common.sh for why.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib/common.sh
source "${SCRIPT_DIR}/lib/common.sh"

# ---------------------------------------------------------------------------
# Defaults
# ---------------------------------------------------------------------------
MODE="report"
PROJECT_FILTER=""
ENV_FILTER=""
DRY_RUN=0
SCAN_PLAN=0    # If 1, run the terraform_plan framework layer (needs init+plan).
SCAN_STATE=0   # If 1, also download state blob and scan; emit drift diff.
               # Implicitly enables SCAN_PLAN.
NO_AGGREGATE=0 # If 1, --mode report skips the end-of-run aggregate_pci.py
               # call. Gate and audit modes never aggregate (gate is exit-
               # only; audit re-emits from archive).
RUN_LABEL=""   # If non-empty, used as the run-dir slug instead of the
               # derived one. Suffixed with the UTC date for ordering
               # (sanitized to [A-Za-z0-9_-]).

# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------
usage() {
  cat <<EOF
Usage: $0 [--mode gate|report|audit] [--project P] [--env E]
           [--scan-plan] [--scan-state]
           [--dry-run] [--verbose]
           [--no-aggregate]
           [--label TEXT] 

Run mode:
  gate    CI gate (default if CI env detected).  --hard-fail-on HIGH,CRITICAL.
          Does NOT auto-aggregate (CI ingests raw SARIF artifacts).
  report  Manual scan.  --soft-fail.  Never blocks.  (default for humans)
          Auto-runs aggregate_pci.py at the end and prints the report
          HTML path.  Use --no-aggregate to skip.
  audit   Re-emit prior report from archive (no re-scan).

Scan depth (three tiers, default = source only):
  (no flag)      Source-only scan. Runs checkov --framework terraform on the
                 .tf source + custom PCI checks + secrets framework. NO
                 terraform init, NO terraform plan, NO storage read. Fast
                 (seconds), fully offline once checkov is installed. The
                 right default for day-to-day CI / pre-commit hooks.
  --scan-plan    Add the terraform_plan layer. Runs \`terraform init\` +
                 \`terraform plan -json\` so Checkov can see resolved values
                 (catches things like CMK on encryption-bearing resources
                 where the boolean is buried in a module output). Requires
                 the storage firewall to whitelist your IP (auto-handled
                 via whitelist_my_ip()).
  --scan-state   Add the state-as-plan layer. Implies --scan-plan. Downloads
                 the .tfstate blob from Azure Storage, converts to
                 plan-shape JSON, and runs Checkov against it. Emits a
                 drift_report.{json,md} comparing source plan and state
                 plan (catches ignore_changes drift). Requires storage
                 firewall whitelist + state-blob read access.

Filters:
  --project P      Restrict to one project (e.g. CR_Formstax_SQL).
  --env E          Restrict to one env (e.g. prod).

Modifiers:
  --dry-run        Print commands without executing.
  --verbose        Enable INFO logging (DEBUG with PCI_DEBUG=1).
  --no-aggregate   Skip the auto-aggregation step (only meaningful for
                   --mode report; gate and audit modes never aggregate).
                   When omitted, --mode report invokes aggregate_pci.py
                   at the end of the scan and prints the report.html path.
  --label TEXT     Custom slug for the run-dir name (sanitized to
                   [A-Za-z0-9_-]). Suffixes the UTC date for ordering.
                   Overrides the scope-derived default. Useful for tagging
                   a run as e.g. "audit-q4" or "pre-deploy".
  --help           Show this help.

Environment:
  PCI_VERBOSE=1   Same as --verbose.
  PCI_DEBUG=1     Even more verbose.
  CI=1            Auto-detect gate mode.

Safety:
  This script is READ-ONLY against Azure. It will REFUSE to run:
  - terraform apply / destroy / state rm / state mv / state import / taint
  - terraform plan/apply/destroy -lock=false
  - az <resource> delete / update / create
  - checkov --fix
  Allowed (when their flag is set): terraform init/plan/show,
           az storage blob download (state read-back only, --scan-state),
           az storage account network-rule {add,remove,list} (cleanup).
  See .scripts/checkov/lib/safety.sh for the full list.
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --mode)      MODE="$2"; shift 2 ;;
    --project)   PROJECT_FILTER="$2"; export PROJECT_FILTER; shift 2 ;;
    --env)       ENV_FILTER="$2"; export ENV_FILTER; shift 2 ;;
    --scan-plan) SCAN_PLAN=1; shift ;;
    --scan-state) SCAN_PLAN=1; SCAN_STATE=1; shift ;;
    --dry-run)     DRY_RUN=1; shift ;;
    --verbose)     export PCI_VERBOSE=1; shift ;;
    --no-aggregate) NO_AGGREGATE=1; shift ;;
    --label)       RUN_LABEL="$2"; shift 2 ;;
    --help|-h)     usage; exit 0 ;;
    *)             pci_log ERROR "unknown argument: $1"; usage; exit 64 ;;
  esac
done

# Auto-detect CI mode.
if [[ "${MODE}" == "report" && -n "${CI:-}" ]]; then
  MODE="gate"
  pci_log INFO "CI environment detected; mode=gate"
fi

# Mode validation.
case "$MODE" in
  gate|report|audit) ;;
  *) pci_log ERROR "invalid mode: $MODE (must be gate|report|audit)"; exit 64 ;;
esac

# ---------------------------------------------------------------------------
# Trap: cleanup IPs + shred plan artifacts on any exit.
# ---------------------------------------------------------------------------
trap_on_exit() {
  local rc=$?
  pci_log INFO "exit (rc=$rc); running cleanup"
  cleanup_ip_whitelist || true
  shred_plan_artifacts || true
  # Stage dir is set during scope-pairs build and either moved into
  # $RUN_DIR (so empty by this point) or never created at all.
  [[ -n "${STAGE_DIR:-}" ]] && rm -rf "$STAGE_DIR" 2>/dev/null || true
  return $rc
}
trap trap_on_exit EXIT INT TERM

# ---------------------------------------------------------------------------
# Dry-run helper
# ---------------------------------------------------------------------------
run_cmd() {
  if [[ $DRY_RUN -eq 1 ]]; then
    echo "[dry-run] $*"
  else
    safe_run_exec "$@"
  fi
}

# run_checkov <args...>
# Run checkov with the URL-rewrite filter on its stdout/stderr.
# Equivalent to `run_cmd checkov <args>` but pipes through
# checkov_stderr_filter so the operator's terminal shows canonical
# GitHub URLs instead of broken prismacloud.io links.
#
# The unsafe-pattern check runs against the reconstructed command line
# (the same check run_cmd applies via safe_run_exec). Refuses on
# match with exit 99.
run_checkov() {
  # Reject any mutating flags before running. Mirrors safe_run_exec.
  refuse_if_mutating "checkov $*"
  if [[ $DRY_RUN -eq 1 ]]; then
    echo "[dry-run] checkov $*"
  else
    checkov "$@" 2>&1 | checkov_stderr_filter
  fi
}

# ---------------------------------------------------------------------------
# Rewrite broken helpUri inside a Checkov SARIF file.
# ---------------------------------------------------------------------------
# Checkov OSS populates rule.helpUri with docs.prismacloud.io URLs.
# That domain was acquired by Palo Alto in 2026 and the per-rule
# deep-links now redirect to a generic landing page (no per-rule context).
# We rewrite the URLs to the canonical GitHub source files so any
# downstream tooling that ingests the SARIF (CI scanners, the
# aggregate_pci.py HTML report, the iac-reports archive) sees URLs
# that actually resolve to the rule definition.
#
# Usage:
#   rewrite_sarif_help_url <sarif_path>
#
# No-op if the SARIF is missing or has no helpUri strings to rewrite.
# No-op in --dry-run mode.
rewrite_sarif_help_url() {
  local sarif_path="$1"
  if [[ $DRY_RUN -eq 1 ]]; then
    echo "[dry-run] rewrite_sarif_help_url $sarif_path"
    return 0
  fi
  if [[ ! -f "$sarif_path" ]]; then
    return 0
  fi
  if ! command -v python >/dev/null 2>&1; then
    pci_log WARN "python not found; skipping helpUri rewrite for $sarif_path"
    return 0
  fi
  python "${PCI_REPO_ROOT}/.scripts/checkov/rewrite_sarif_help.py" "$sarif_path" >/dev/null \
    || pci_log WARN "rewrite_sarif_help.py failed for $sarif_path (rc=$?)"
}

# ---------------------------------------------------------------------------
# Rewrite broken helpUri in Checkov's CLI stdout.
# ---------------------------------------------------------------------------
# Checkov's console output includes lines like:
#
#   Guide: https://docs.prismacloud.io/en/enterprise-edition/policy-reference/...
#
# Those URLs are broken (see comment on rewrite_sarif_help_url). We pipe
# the output through sed so the operator sees the rewrite happen in their
# terminal as well. The per-rule deep-link is replaced with the static
# Checkov GitHub repo root (always 200) so the operator can drill down
# to the rule file manually.
checkov_stderr_filter() {
  # Replace any docs.prismacloud.io URL with the GitHub repo root.
  # The escaping is for both bash and sed; the trailing 'g' is global.
  sed -E 's|https://docs\.prismacloud\.io[^[:space:]]*|https://github.com/bridgecrewio/checkov|g'
}

# ---------------------------------------------------------------------------
# Audit mode: re-emit from archive (no re-scan).
# ---------------------------------------------------------------------------
if [[ "$MODE" == "audit" ]]; then
  pci_log ERROR "audit mode not implemented yet (Phase 8)"
  exit 1
fi

# ---------------------------------------------------------------------------
# Validate required files
# ---------------------------------------------------------------------------
require_file "$PCI_SCOPE_FILE"
require_file "$PCI_MAPPING_FILE"
require_file "$PCI_BASELINE_FILE"

pci_log INFO "mode: $MODE"

# ---------------------------------------------------------------------------
# Build scope pairs (project TAB env) into a temp file BEFORE creating
# the run dir. The dir name is derived from what's actually being
# scanned (one project+env pair, all envs in a project, all projects in
# one env, or all projects). Suffixing with the UTC calendar date keeps
# runs sorted chronologically and easy to find later.
# ---------------------------------------------------------------------------
SCOPE_JSON="$(load_pci_scope)"
pci_log INFO "loaded scope: $(echo "$SCOPE_JSON" | python -c 'import json,sys; print(len(json.load(sys.stdin)))') projects"

# Staging dir for the pairs file. Lives until the actual run dir is
# created below, then the pairs file is moved in. Removed by trap_on_exit.
STAGE_DIR="$(mktemp -d)"
# Build a list of (project, env) pairs to scan. Write to a staging TSV so
# the while-read loop doesn't run in a subshell (which would lose
# variable state and silently eat output).
SCOPE_PAIRS_STAGING="${STAGE_DIR}/pairs.tsv"
echo "$SCOPE_JSON" | python -c "
import json, sys, os
projects = json.load(sys.stdin)
for p in projects:
    proj = p['project']
    if os.environ.get('PROJECT_FILTER') and proj != os.environ['PROJECT_FILTER']:
        continue
    for env in p.get('envs', []):
        if os.environ.get('ENV_FILTER') and env != os.environ['ENV_FILTER']:
            continue
        print(f'{proj}\t{env}', flush=True)
" > "$SCOPE_PAIRS_STAGING"

pci_log INFO "scope pairs to scan: $(wc -l < "$SCOPE_PAIRS_STAGING")"

# ---------------------------------------------------------------------------
# Derive the run-dir name from the scope (see init_pretty_run_dir in
# lib/common.sh). If --label was supplied, it wins over the scope-derived
# slug. Either way the UTC date is suffixed for ordering, and a -HHMM or
# numeric counter is appended if the same name is reused same day.
# ---------------------------------------------------------------------------
if [[ -n "$RUN_LABEL" ]]; then
  RUN_DIR="$(init_run_dir_labeled "$RUN_LABEL")" || {
    pci_log ERROR "failed to derive labeled run dir from: $RUN_LABEL"
    exit 1
  }
else
  RUN_DIR="$(init_pretty_run_dir "$SCOPE_PAIRS_STAGING")" || {
    pci_log ERROR "failed to derive run dir from scope pairs"
    exit 1
  }
fi

# Move the pairs file into the run dir under its canonical name.
SCOPE_PAIRS_FILE="${RUN_DIR}/.scope_pairs.tsv"
mv "$SCOPE_PAIRS_STAGING" "$SCOPE_PAIRS_FILE"
rmdir "$STAGE_DIR" 2>/dev/null || true
STAGE_DIR=""

pci_log INFO "run dir: $RUN_DIR"

while IFS=$'\t' read -r proj env; do
  # Strip CR (Windows line endings) and any trailing whitespace.
  proj="${proj%$'\r'}"; env="${env%$'\r'}"
  [[ -z "$proj" || -z "$env" ]] && continue
  env_dir="${PCI_REPO_ROOT}/env/${proj}/${env}"
  if ! require_env_dir "$env_dir"; then
    pci_log WARN "skipping ${proj}/${env}: env dir invalid"
    continue
  fi

  pci_log INFO "scanning ${proj}/${env}"

  # Per-env output dir
  env_run_dir="${RUN_DIR}/${proj}/${env}"
  mkdir -p "$env_run_dir"

  # ----------------------------------------------------------------------
  # Tier 1/2/3 gate: decide what to do based on --scan-plan / --scan-state.
  # Source-only (no flag) skips terraform entirely (no init, no plan, no
  # storage read). --scan-plan adds init + plan. --scan-state adds state
  # blob download + drift diff (and implies --scan-plan).
  # ----------------------------------------------------------------------

  plan_bin=""
  plan_json=""

  if [[ $SCAN_PLAN -eq 1 ]]; then
    # Step 0a: whitelist current IP on $PCI_STATE_STORAGE_ACCOUNT (only allowed
    # mutation). Pairs with cleanup_ip_whitelist via the EXIT trap.
    pci_log INFO "  whitelist current IP on $PCI_STATE_STORAGE_ACCOUNT storage firewall"
    if [[ $DRY_RUN -eq 1 ]]; then
      echo "[dry-run] whitelist_my_ip"
    else
      whitelist_my_ip || {
        pci_log ERROR "failed to whitelist IP; cannot read remote state; skipping ${proj}/${env}"
        continue
      }
    fi

    # Step 0b: terraform init -input=false (no interactive prompts). Init
    # configures the backend so that `terraform plan` can read remote
    # state for the refresh step. Providers are downloaded from the public
    # Terraform registry or filesystem_mirror (whichever is configured);
    # no Azure-resource mutations occur.
    pci_log INFO "  terraform init"
    if ! run_cmd terraform -chdir="$env_dir" init -input=false -no-color; then
      pci_log ERROR "terraform init failed for ${proj}/${env}; skipping plan layer"
      continue
    fi

    # Step 0c: terraform plan -out=tfplan.binary. Acquires state lock;
    # reads state from remote backend. NO mutation.
    plan_bin="${env_run_dir}/tfplan.binary"
    pci_log INFO "  terraform plan -out=$(basename "$plan_bin")"
    if ! run_cmd terraform -chdir="$env_dir" plan -no-color -out="$plan_bin" -lock=true; then
      pci_log ERROR "terraform plan failed for ${proj}/${env}; skipping plan layer"
      continue
    fi

    # Step 0d: terraform show -json -> plan.json
    plan_json="${env_run_dir}/plan.json"
    pci_log INFO "  terraform show -json"
    run_cmd terraform -chdir="$env_dir" show -json "$plan_bin" > "$plan_json"
  fi

  # Compute skip paths for the aztfexport files (do not mutate them).
  # Find them dynamically and pass --skip-path to checkov.
  skip_paths=()
  while IFS= read -r f; do
    [[ -n "$f" ]] && skip_paths+=("--skip-path" "$f")
  done < <(find_aztfexport_files "$env_dir")

  # Custom PCI checks (policy-as-code). Loaded via --external-checks-dir.
  # Auto-load all .py files under .scripts/checkov/pci_checks/.
  PCI_CHECKS_DIR="${PCI_REPO_ROOT}/.scripts/checkov/pci_checks"
  external_check_args=()
  if [[ -d "$PCI_CHECKS_DIR" ]]; then
    external_check_args+=("--external-checks-dir" "$PCI_CHECKS_DIR")
  fi

  # Step 1: custom-policy-as-code pass against the .tf source (no plan,
  # no state). Always runs — these checks are static and catch patterns
  # like lifecycle ignore_changes, inline default_action, CMK absence
  # on encryption-bearing resources.
  if [[ -d "$PCI_CHECKS_DIR" ]]; then
    pci_log INFO "  checkov --framework terraform (custom PCI checks on .tf)"
    paac_dir="${env_run_dir}/checkov_paac"
    mkdir -p "$paac_dir"
    paac_args=(
      -d "$env_dir"
      --framework terraform
      --output sarif
      --output-file-path "$paac_dir"
      --external-checks-dir "$PCI_CHECKS_DIR"
    )
    if [[ "$MODE" == "gate" ]]; then
      paac_args+=(--hard-fail-on HIGH,CRITICAL)
    else
      paac_args+=(--soft-fail)
    fi
    [[ ${#skip_paths[@]} -gt 0 ]] && paac_args+=("${skip_paths[@]}")
    # Pipe checkov's output through the URL rewriter so the operator
    # sees canonical GitHub URLs instead of broken prismacloud.io links.
    # Under set -o pipefail, the pipeline carries checkov's exit code.
    checkov "${paac_args[@]}" 2>&1 | checkov_stderr_filter
    paac_rc=${PIPESTATUS[0]}
    if [[ $paac_rc -ne 0 ]]; then
      # Mirror run_cmd's refuse_if_mutating safety check before logging.
      pci_log WARN "checkov paac returned rc=$paac_rc for ${proj}/${env}"
    fi
    if [[ -f "${paac_dir}/results_sarif.sarif" ]]; then
      mv "${paac_dir}/results_sarif.sarif" "${env_run_dir}/results_paac.sarif"
      rmdir "$paac_dir" 2>/dev/null || true
      rewrite_sarif_help_url "${env_run_dir}/results_paac.sarif"
    fi
  fi

  # Step 2: built-in terraform framework against the .tf source (always
  # runs). This is the deepest source-only layer — catches hundreds of
  # common Azure misconfigurations statically.
  if [[ $SCAN_PLAN -eq 0 ]]; then
    pci_log INFO "  checkov --framework terraform (built-in source scan)"
    terraform_src_dir="${env_run_dir}/checkov_terraform_source"
    mkdir -p "$terraform_src_dir"
    tf_src_args=(
      -d "$env_dir"
      --framework terraform
      --output sarif
      --output-file-path "$terraform_src_dir"
    )
    if [[ "$MODE" == "gate" ]]; then
      tf_src_args+=(--hard-fail-on HIGH,CRITICAL)
    else
      tf_src_args+=(--soft-fail)
    fi
    [[ ${#skip_paths[@]} -gt 0 ]] && tf_src_args+=("${skip_paths[@]}")
    run_checkov "${tf_src_args[@]}"
    if [[ -f "${terraform_src_dir}/results_sarif.sarif" ]]; then
      mv "${terraform_src_dir}/results_sarif.sarif" "${env_run_dir}/results_terraform_source.sarif"
      rmdir "$terraform_src_dir" 2>/dev/null || true
      rewrite_sarif_help_url "${env_run_dir}/results_terraform_source.sarif"
    fi
  fi

  # Step 3: checkov terraform_plan framework on the plan JSON. Only runs
  # when --scan-plan (or --scan-state) is set.
  if [[ $SCAN_PLAN -eq 1 && -f "$plan_json" ]]; then
    terraform_plan_dir="${env_run_dir}/checkov_terraform_plan"
    mkdir -p "$terraform_plan_dir"
    pci_log INFO "  checkov --framework terraform_plan (source plan)"
    checkov_args=(
      -d "$env_dir"
      -f "$plan_json"
      --framework terraform_plan
      --output sarif
      --output-file-path "$terraform_plan_dir"
    )
    if [[ "$MODE" == "gate" ]]; then
      checkov_args+=(--hard-fail-on HIGH,CRITICAL)
    else
      checkov_args+=(--soft-fail)
    fi
    [[ ${#skip_paths[@]} -gt 0 ]] && checkov_args+=("${skip_paths[@]}")
    [[ ${#external_check_args[@]} -gt 0 ]] && checkov_args+=("${external_check_args[@]}")
    run_checkov "${checkov_args[@]}"
    if [[ -f "${terraform_plan_dir}/results_sarif.sarif" ]]; then
      mv "${terraform_plan_dir}/results_sarif.sarif" "${env_run_dir}/results_terraform_plan.sarif"
      rmdir "$terraform_plan_dir" 2>/dev/null || true
      rewrite_sarif_help_url "${env_run_dir}/results_terraform_plan.sarif"
    fi
  fi

  # Step 4: checkov secrets framework on .tf source. Always runs — it's
  # static and safe to scan.
  pci_log INFO "  checkov --framework secrets"
  secrets_dir="${env_run_dir}/checkov_secrets"
  mkdir -p "$secrets_dir"
  secrets_args=(
    -d "$env_dir"
    --framework secrets
    --output sarif
    --output-file-path "$secrets_dir"
  )
  if [[ "$MODE" == "gate" ]]; then
    secrets_args+=(--hard-fail-on HIGH,CRITICAL)
  else
    secrets_args+=(--soft-fail)
  fi
    [[ ${#skip_paths[@]} -gt 0 ]] && secrets_args+=("${skip_paths[@]}")
    [[ ${#external_check_args[@]} -gt 0 ]] && secrets_args+=("${external_check_args[@]}")
    run_checkov "${secrets_args[@]}"
    if [[ -f "${secrets_dir}/results_sarif.sarif" ]]; then
      mv "${secrets_dir}/results_sarif.sarif" "${env_run_dir}/results_secrets.sarif"
      rmdir "$secrets_dir" 2>/dev/null || true
      rewrite_sarif_help_url "${env_run_dir}/results_secrets.sarif"
    fi

  # Step 5b (optional): state-as-plan scan + drift diff.
  # This catches "ignore_changes" drift: when .tf declares a config but
  # the actual Azure resource has been modified out-of-band (manually,
  # via the Portal, or by another automation) and Terraform will rewrite
  # it on next apply because ignore_changes is missing. Source-scan will
  # not see this; state-scan will.
  if [[ $SCAN_STATE -eq 1 ]]; then
    pci_log INFO "  state-scan: download state blob from Azure"
    # The remote backend key is read from terraform.aztfexport.tf to
    # handle naming variations (e.g., "Fromstax" vs "Formstax").
    backend_key=""
    if [[ -f "$env_dir/terraform.aztfexport.tf" ]]; then
      backend_key="$(grep -E '^\s*key\s*=' "$env_dir/terraform.aztfexport.tf" \
        | head -1 | sed -E 's/.*"([^"]+)".*/\1/')"
    fi
    if [[ -z "$backend_key" ]]; then
      # Fallback: synthesize from project + env
      backend_key="CR_$(echo "${env}" | awk '{print toupper(substr($0,1,1)) substr($0,2)}')_${proj}.tfstate"
      pci_log WARN "no backend key in terraform.aztfexport.tf; falling back to synthesized: $backend_key"
    fi
    state_local="${env_run_dir}/state.tfstate"
    state_plan_json="${env_run_dir}/state_as_plan.json"
    drift_report="${env_run_dir}/drift_report.json"

    if [[ $DRY_RUN -eq 1 ]]; then
      echo "[dry-run] az storage blob download --container-name iac --name ${backend_key} --file ${state_local}"
      echo "[dry-run] python .scripts/checkov/tfstate_to_plan.py ${state_local} ${state_plan_json}"
    else
      run_cmd az storage blob download \
        --account-name "$PCI_STATE_STORAGE_ACCOUNT" \
        --container-name iac \
        --name "$backend_key" \
        --file "$state_local" \
        --auth-mode login \
        --output none 2>&1 | head -5
      if [[ -f "$state_local" && -s "$state_local" ]]; then
        pci_log INFO "  state blob downloaded: $(stat -c %s "$state_local" 2>/dev/null || wc -c < "$state_local") bytes"
        # Shred the encrypted state blob ASAP (PCI 10.7 hygiene)
        run_cmd python .scripts/checkov/tfstate_to_plan.py "$state_local" "$state_plan_json"
        if [[ -f "$state_local" ]]; then
          shred -u "$state_local" 2>/dev/null || rm -f "$state_local"
        fi

        # Scan state-as-plan with checkov
        state_dir="${env_run_dir}/checkov_state"
        mkdir -p "$state_dir"
        state_args=(
          -d "$env_dir"
          -f "$state_plan_json"
          --framework terraform_plan
          --output sarif
          --output-file-path "$state_dir"
        )
        if [[ "$MODE" == "gate" ]]; then
          state_args+=(--hard-fail-on HIGH,CRITICAL)
        else
          state_args+=(--soft-fail)
        fi
        [[ ${#skip_paths[@]} -gt 0 ]] && state_args+=("${skip_paths[@]}")
        run_checkov "${state_args[@]}"
        if [[ -f "${state_dir}/results_sarif.sarif" ]]; then
          mv "${state_dir}/results_sarif.sarif" "${env_run_dir}/results_state.sarif"
          rmdir "$state_dir" 2>/dev/null || true
          rewrite_sarif_help_url "${env_run_dir}/results_state.sarif"
        fi

        # Generate drift diff between source plan and state plan.
        # Drift = attributes that exist in state but not in plan, OR
        # attributes that differ between the two views. This is the
        # signal that ignore_changes is masking real Azure drift.
        if [[ -f "$plan_json" && -f "$state_plan_json" ]]; then
          run_cmd python .scripts/checkov/drift_report.py \
            "$plan_json" "$state_plan_json" "$drift_report"
        fi

        # Shred state plan after drift extraction
        shred -u "$state_plan_json" 2>/dev/null || rm -f "$state_plan_json"
      fi
    fi
  fi

  # Step 6: shred plan artifacts (PCI 10.7 hygiene). Skipped when source-only
  # mode never produced these files.
  if [[ -n "$plan_bin" || -n "$plan_json" ]]; then
    pci_log INFO "  shred plan artifacts"
    if [[ $DRY_RUN -eq 0 ]]; then
      [[ -n "$plan_bin" ]] && shred -u "$plan_bin" 2>/dev/null || rm -f "$plan_bin"
      [[ -n "$plan_json" ]] && shred -u "$plan_json" 2>/dev/null || rm -f "$plan_json"
    fi
  fi

  pci_log INFO "  done ${proj}/${env}"
done < "$SCOPE_PAIRS_FILE"

# ---------------------------------------------------------------------------
# Final aggregation (report mode only, unless --no-aggregate)
# ---------------------------------------------------------------------------
# Gate mode: skip. CI ingests raw SARIF / junit artifacts directly via
#   Pipeline.PublishBuildArtifact and does NOT need to spend cycles re-
#   walking every per-env SARIF on each test run.
# Audit mode: skip. scan_pci_audit.sh handles aggregation against the
#   iac-reports archive; this script's --mode audit branch is the wrong
#   place for that work.
# Report mode: aggregate_pci.py walks every <env>/results_*.sarif and
#   emits combined.sarif, coverage_matrix.csv, junit.xml, report.html.
#   Without this step, operators would have to run a second command.

SCAN_RC=0
if [[ "$MODE" == "report" && $NO_AGGREGATE -eq 0 ]]; then
  if [[ $DRY_RUN -eq 1 ]]; then
    pci_log INFO "aggregation (dry-run): python "${SCRIPT_DIR}/aggregate.py" --run-dir $RUN_DIR"
  else
    pci_log INFO "aggregating $RUN_DIR (coverage matrix + HTML report)"
    if python "${SCRIPT_DIR}/aggregate.py" --run-dir "$RUN_DIR"; then
      AGG_RC=0
    else
      AGG_RC=$?
      pci_log ERROR "aggregate_pci.py failed (rc=$AGG_RC); raw SARIFs are still in $RUN_DIR"
    fi

    # aggregate_pci.py default --out is <run-dir>/aggregate (it preserves
    # that subdir for backwards compatibility with the original manual
    # flow). Probe both possible locations so the operator gets a useful
    # path even if the script's default ever changes.
    REPORT_HTML=""
    for candidate in "${RUN_DIR}/aggregate/report.html" "${RUN_DIR}/report.html"; do
      if [[ -f "$candidate" ]]; then
        REPORT_HTML="$candidate"
        break
      fi
    done
    if [[ -n "$REPORT_HTML" ]]; then
      pci_log INFO "report: $REPORT_HTML"
    fi
    # Don't mask the scan RC if it was already non-zero.
    # NOTE: aggregator's rc=7 means "HIGH/CRITICAL findings present" (gate
    # semantics). In report mode that's the WHOLE POINT of the report; the
    # report.html carries the findings. Suppress rc=7 here so the manual
    # scan target can be "never blocks" as documented in the Makefile and
    # CLAUDE.md. The block-level gate target is `make scan-pci` (no -report).
    if [[ $AGG_RC -ne 0 && $AGG_RC -ne 7 ]]; then
      SCAN_RC=$AGG_RC
    fi
  fi
fi

pci_log INFO "scan complete: $RUN_DIR"
if [[ $SCAN_PLAN -eq 0 ]]; then
  pci_log INFO "tier: source-only (built-in terraform framework + custom PCI checks + secrets)"
elif [[ $SCAN_STATE -eq 1 ]]; then
  pci_log INFO "tier: source + plan + state-drift"
else
  pci_log INFO "tier: source + plan"
fi
exit $SCAN_RC
