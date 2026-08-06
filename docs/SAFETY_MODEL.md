# Pacioli — Safety Model

> **The scanner is read-only against Azure.** This document is the
> authoritative description of that invariant: which commands are
> refused, which are allowed, how the guard is implemented, and how
> to add a new pattern.

The safety guarantee is enforced at the *process spawn* level — every
external command the scanner runs is matched against a list of refused
patterns before execution. A match causes the script to exit with
code 99 *before* the command runs. The guard is implemented in
`scanner/lib/safety.sh` and is the first thing every driver script
sources.

## What is refused (as of this writing)

The `REFUSE_PATTERN` array in `scanner/lib/safety.sh` lists every
command shape that the scanner will not execute:

### Terraform state mutations

```
terraform apply <anything>
terraform destroy <anything>
terraform state rm <name>
terraform state mv <name>
terraform state import <name>
terraform state replace-provider <name>
terraform state list <name>            # ambiguous with read; refuse out of caution
terraform taint <name>
terraform untaint <name>
terraform import <name>
```

### Terraform locking bypass

```
terraform plan ... -lock=false
terraform apply ... -lock=false
terraform destroy ... -lock=false
```

### Terraform auto-approve bypass

```
<anything> -auto-approve
```

### Azure CLI mutations

```
az storage account delete
az resource delete | update | create
az group delete
az keyvault delete
az sql (server|db) delete
az appservice (plan|webapp) delete
az role assignment delete
```

### Checkov auto-fix

```
checkov ... --fix
```

## What is allowed

Two patterns are explicitly *exempted* from the broader refusals,
because the scan flow requires them:

### Storage firewall IP whitelist (tier 2/3 only)

```
az storage account network-rule (add|remove|list)
```

The `add` is performed by `whitelist_my_ip` in `lib/common.sh`,
paired with `cleanup_ip_whitelist` via the EXIT trap. The `remove`
is the trap's paired partner. The `list` is used for verification
("is the IP actually present?") and idempotency.

The IP is stored at `${RUN_DIR}/.whitelist_ip` after a successful
add so the trap can find it on cleanup.

### State blob download (tier 3 only)

```
az storage blob download ...
```

The state blob is downloaded to `${RUN_DIR}/<project>/<env>/state.tfstate`,
converted to plan-JSON shape via `tfstate_to_plan.py`, then
**shredded** (`shred -u`) before the script exits (PCI 10.7
hygiene — see `shred_plan_artifacts` in `lib/common.sh`).

## How the guard is implemented

`scanner/lib/safety.sh` defines:

```bash
declare -a REFUSE_PATTERN=( ... )     # Extended regex patterns
declare -A REFUSE_REASON=( ... )      # Human-readable reason per pattern
declare -a ALLOWED_EXCEPTIONS=( ... ) # Patterns exempted from refusal

refuse_if_mutating <cmd_string> {
    # Returns 0 if allowed
    # Exits 99 if refused
}
```

Every driver uses the guard via one of two paths:

1. **`safe_run_exec <cmd> [args...]`** in `lib/common.sh` —
   the canonical way. Calls `refuse_if_mutating` against the
   reconstructed command line, then executes.

2. **`run_cmd <cmd> [args...]`** in `scan.sh` — same guard,
   plus `--dry-run` support (prints the command instead of
   executing it when `$DRY_RUN=1`).

3. **`refuse_if_mutating <cmd_string>` directly** — for cases
   where the caller wants to gate but not execute (e.g. the
   `run_checkov` helper in `scan.sh`, which calls
   `refuse_if_mutating "checkov $*"` before piping Checkov's
   output through the URL filter).

The guard is NOT optional. Every external command in `scan.sh`
goes through `run_cmd`, `run_checkov`, or `safe_run_exec`. There
are no bare `terraform` / `az` / `checkov` invocations.

## The EXIT trap

`scan.sh` registers a single trap:

```bash
trap trap_on_exit EXIT INT TERM
trap_on_exit() {
    local rc=$?
    pci_log INFO "exit (rc=$rc); running cleanup"
    cleanup_ip_whitelist || true
    shred_plan_artifacts || true
    [[ -n "${STAGE_DIR:-}" ]] && rm -rf "$STAGE_DIR" 2>/dev/null || true
    return $rc
}
```

The trap fires on:

- Normal exit (any `exit N`).
- `Ctrl-C` (SIGINT).
- `kill <pid>` without `-9` (SIGTERM).
- The `set -uo pipefail` triggered abort.

The trap does NOT fire on `SIGKILL` (kernel OOM, `kill -9`). For
that case, the storage firewall IP may be left behind. See
[Operator Guide → Cleaning up stale storage-firewall IPs](OPERATOR_GUIDE.md#cleaning-up-stale-storage-firewall-ips).

## The self-test

`lib/safety.sh` defines `safety_selftest()`. It runs when the file
is *invoked directly* (not sourced). The selftest:

1. Asserts that every command in the `should_refuse` list is
   refused.
2. Asserts that every command in the `should_allow` list is
   accepted (passes the guard).

The `should_refuse` list:

```bash
"terraform apply -auto-approve"
"terraform destroy"
"terraform state rm foo"
"terraform plan -lock=false"
"az group delete -n foo"
"az storage account delete -n foo"
"checkov -d . --fix"
```

The `should_allow` list:

```bash
"terraform plan -out=tfplan.binary"
"terraform show -json tfplan.binary"
"terraform init -backend=false"
"az storage account network-rule add --account-name $PCI_STATE_STORAGE_ACCOUNT --ip-address 1.2.3.4"
"az storage account network-rule remove --account-name $PCI_STATE_STORAGE_ACCOUNT --ip-address 1.2.3.4"
"az storage account network-rule list --account-name $PCI_STATE_STORAGE_ACCOUNT"
```

When you add a new refused pattern, add at least one test case to
`should_refuse`. When you add a new allowed exception, add a test
case to `should_allow`. The `make selftest` target must pass
before you can merge.

Run it:

```bash
make selftest
# safety_selftest: PASS
```

## Defense in depth

The guard is one layer. The full safety story is:

1. **`refuse_if_mutating`** in `lib/safety.sh` — pattern match
   against the command line. Catches accidental invocation.
2. **EXIT trap** in `scan.sh` — cleanup is *guaranteed* on
   normal exit, SIGINT, SIGTERM. Only SIGKILL bypasses it.
3. **Code review** — every PR is reviewed by a maintainer who is
   expected to read the diff against this document.
4. **Git history** — `git log --all -p -- scanner/lib/safety.sh`
   is the audit trail. Any change to the refused patterns is
   recorded in commit history with a justification.
5. **The selftest** — `make selftest` is a CI gate. A PR that
   weakens the safety guard without a corresponding selftest
   change will fail CI.

## Extending the guard

When you need to add a new refused pattern:

1. Open `scanner/lib/safety.sh`.
2. Add a new entry to the `REFUSE_PATTERN` array.
3. Add the matching `REFUSE_REASON` entry (the key must be the
   exact pattern, including all escaping).
4. Add a test case to `should_refuse` in `safety_selftest()`.
5. Run `make selftest` and confirm `safety_selftest: PASS`.
6. Add a `safety:` commit with a one-line rationale.

When you need to allow a new mutation (rare — this should be
discussed in an issue first):

1. Confirm the mutation is *required* for the scan to function.
2. Confirm it can be paired with a cleanup step.
3. Add the pattern to `ALLOWED_EXCEPTIONS`.
4. Add a test case to `should_allow`.
5. Document the rationale in a comment in `lib/safety.sh`.
6. Run `make selftest` and confirm `safety_selftest: PASS`.
7. Add a `safety:` commit with a detailed rationale.

## Why bash, not Python?

The driver is bash for one reason: the EXIT trap is the simplest,
most reliable way to guarantee cleanup of a paired mutation. The
Python equivalent (`try/finally` + `atexit.register` + signal
handlers) is correct but verbose, and signal-handler coverage in
particular is easy to get wrong. The bash trap is 8 lines and
impossible to misread.

## See also

- [Operator Guide → Safety invariants](OPERATOR_GUIDE.md#safety-invariants)
- [Architecture](ARCHITECTURE.md) — how the guard fits in
- [Developer Guide](DEVELOPER_GUIDE.md) — extending the scanner
- [Troubleshooting](TROUBLESHOOTING.md) — common failures
