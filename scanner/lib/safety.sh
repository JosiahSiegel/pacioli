# lib/safety.sh — Hard refusals for any operation that mutates Azure.
#
# This file is sourced by scan_pci.sh and aggregate_pci.py. It enforces the
# Phase 2 safety invariants: the scanner is READ-ONLY against Azure. The ONLY
# Azure mutations permitted are the storage firewall IP whitelist additions
# done by tf_init.sh, and they MUST be paired with cleanup in a trap.
#
# To extend: add a new forbidden pattern to REFUSE_PATTERN (regex) and a
# human-readable reason to REFUSE_REASON (associative array entry).
#
# IMPORTANT: this is defense-in-depth. Even if someone bypasses these checks
# by reading source code, the audit trail (git log of this file) and the
# PR review process are the primary safeguards. This file makes the
# accidental-invocation case loud and immediate.

# Source guard.
[[ -n "${__SAFETY_SH_LOADED:-}" ]] && return 0
__SAFETY_SH_LOADED=1

# Patterns (extended regex) that MUST NEVER appear on a command line.
# Add new entries here when adding new mutating commands.
declare -a REFUSE_PATTERN=(
  # Terraform: state mutations
  'terraform[[:space:]]+apply\b'
  'terraform[[:space:]]+destroy\b'
  'terraform[[:space:]]+state[[:space:]]+(rm|mv|import|replace-provider|list)\b'
  'terraform[[:space:]]+taint\b'
  'terraform[[:space:]]+untaint\b'
  'terraform[[:space:]]+import\b'
  # Terraform: locking bypass
  'terraform[[:space:]]+plan.*-lock=false'
  'terraform[[:space:]]+apply.*-lock=false'
  'terraform[[:space:]]+destroy.*-lock=false'
  # Terraform: auto-approve bypass
  '-auto-approve'
  # Azure CLI: stateful / destructive operations
  'az[[:space:]]+storage[[:space:]]+account[[:space:]]+delete\b'
  'az[[:space:]]+resource[[:space:]]+(delete|update|create)\b'
  'az[[:space:]]+group[[:space:]]+delete\b'
  'az[[:space:]]+keyvault[[:space:]]+delete\b'
  'az[[:space:]]+sql[[:space:]]+(server|db)[[:space:]]+delete\b'
  'az[[:space:]]+appservice[[:space:]]+(plan|webapp)[[:space:]]+delete\b'
  'az[[:space:]]+role[[:space:]]+assignment[[:space:]]+delete\b'
  # Checkov: never auto-apply fixes
  'checkov.*--fix'
)

declare -A REFUSE_REASON=(
  ['terraform[[:space:]]+apply\b']='Terraform apply mutates Azure. Forbidden in scan_pci.sh. Use scan_pci.sh for read-only scans only.'
  ['terraform[[:space:]]+destroy\b']='Terraform destroy deletes Azure resources. Forbidden in scan_pci.sh.'
  ['terraform[[:space:]]+state[[:space:]]+(rm|mv|import|replace-provider|list)\b']='Terraform state mutations are forbidden. PCI scan is read-only.'
  ['terraform[[:space:]]+taint\b']='Taint triggers destroy on next apply. Forbidden.'
  ['terraform[[:space:]]+untaint\b']='Untaint clears taint marker. Forbidden.'
  ['terraform[[:space:]]+import\b']='Import mutates state. Use aztfexport for legitimate imports.'
  ['terraform[[:space:]]+plan.*-lock=false']='Lock bypass defeats drift detection. Forbidden.'
  ['terraform[[:space:]]+apply.*-lock=false']='Lock bypass on apply. Forbidden.'
  ['terraform[[:space:]]+destroy.*-lock=false']='Lock bypass on destroy. Forbidden.'
  ['-auto-approve']='Auto-approve bypasses confirmation. Forbidden.'
  ['az[[:space:]]+storage[[:space:]]+account[[:space:]]+delete\b']='Storage account deletion. Forbidden.'
  ['az[[:space:]]+resource[[:space:]]+(delete|update|create)\b']='Azure resource mutation. Forbidden.'
  ['az[[:space:]]+group[[:space:]]+delete\b']='Resource group deletion. Forbidden.'
  ['az[[:space:]]+keyvault[[:space:]]+delete\b']='Key Vault deletion. Forbidden.'
  ['az[[:space:]]+sql[[:space:]]+(server|db)[[:space:]]+delete\b']='SQL deletion. Forbidden.'
  ['az[[:space:]]+appservice[[:space:]]+(plan|webapp)[[:space:]]+delete\b']='App Service deletion. Forbidden.'
  ['az[[:space:]]+role[[:space:]]+assignment[[:space:]]+delete\b']='RBAC mutation. Forbidden.'
  ['checkov.*--fix']='Checkov auto-fix is forbidden. Triage findings manually.'
)

# ALLOWED EXCEPTIONS — commands that look mutating but are scoped to the
# storage firewall IP whitelist ONLY. These are checked first; if the command
# matches one of these patterns, the broader refusal is skipped.
# Pattern: regex that, if matched, exempts the command from the wider refusal.
declare -a ALLOWED_EXCEPTIONS=(
  # The storage account network-rule add/remove is the only allowed mutation,
  # and only inside tf_init.sh and the trap-and-cleanup helper.
  'az[[:space:]]+storage[[:space:]]+account[[:space:]]+network-rule[[:space:]]+(add|remove|list)\b'
  # Read-only state blob download for --scan-state (no --overwrite, no
  # delete, no copy, no upload). Strict regex restricts to download.
  'az[[:space:]]+storage[[:space:]]+blob[[:space:]]+download\b'
)

# refuse_if_mutating(cmd_string)
# Refuses if cmd_string matches any REFUSE_PATTERN (and is not an ALLOWED_EXCEPTION).
# Exits with code 99 on refusal.
refuse_if_mutating() {
  local cmd="$1"
  local pattern reason

  # Check allowed exceptions first
  for pattern in "${ALLOWED_EXCEPTIONS[@]}"; do
    if [[ "$cmd" =~ $pattern ]]; then
      return 0
    fi
  done

  # Check refusals
  for pattern in "${REFUSE_PATTERN[@]}"; do
    if [[ "$cmd" =~ $pattern ]]; then
      reason="${REFUSE_REASON[$pattern]:-Unknown refusal pattern: $pattern}"
      echo "REFUSED: $reason" >&2
      echo "         Command: $cmd" >&2
      exit 99
    fi
  done
  return 0
}

# safe_run(cmd_string)
# Validates the command against refuse_if_mutating, then executes it.
safe_run() {
  local cmd="$*"
  refuse_if_mutating "$cmd"
  "$@"
}

# Verify the safety library is in effect by running a self-test.
# Returns 0 if pass, 1 if fail.
safety_selftest() {
  local failed=0
  local -a should_refuse=(
    "terraform apply -auto-approve"
    "terraform destroy"
    "terraform state rm foo"
    "terraform plan -lock=false"
    "az group delete -n foo"
    "az storage account delete -n foo"
    "checkov -d . --fix"
  )
  local -a should_allow=(
    "terraform plan -out=tfplan.binary"
    "terraform show -json tfplan.binary"
    "terraform init -backend=false"
    "az storage account network-rule add --account-name $PCI_STATE_STORAGE_ACCOUNT --ip-address 1.2.3.4"
    "az storage account network-rule remove --account-name $PCI_STATE_STORAGE_ACCOUNT --ip-address 1.2.3.4"
    "az storage account network-rule list --account-name $PCI_STATE_STORAGE_ACCOUNT"
  )

  for cmd in "${should_refuse[@]}"; do
    if (refuse_if_mutating "$cmd") 2>/dev/null; then
      echo "FAIL: should have refused: $cmd" >&2
      failed=1
    fi
  done

  for cmd in "${should_allow[@]}"; do
    if ! (refuse_if_mutating "$cmd") 2>/dev/null; then
      echo "FAIL: should have allowed: $cmd" >&2
      failed=1
    fi
  done

  return $failed
}
