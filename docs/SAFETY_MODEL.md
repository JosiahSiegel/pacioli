# Pacioli — Safety Model

> **The scanner is read-only against Azure.** This document is the
> authoritative description of that invariant: which commands are
> refused, which are allowed, how the guard is implemented, and how
> to add a new pattern.

The safety guarantee is enforced at the *process spawn* level — every
external command the scanner runs is matched against a list of refused
patterns before execution. A match raises
`scanner.safety.MutatingOperationRefused` (and the scanner exits with
code 99) *before* the command runs. The guard is implemented in
`scanner/safety.py` (`SafetyGuard.refuse_if_mutating`) and is imported
by `scanner/orchestrator.py` at module load.

## What is refused (as of this writing)

The `REFUSE_PATTERN` tuple in `scanner/safety.py` lists every
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

The `add` is performed by the storage firewall whitelist logic in
`scanner/orchestrator.py`, paired with the cleanup hook in
`scanner/trap.py`. The `remove` is the hook's paired partner. The
`list` is used for verification ("is the IP actually present?")
and idempotency.

The IP is stored at `<env_run_dir>/.whitelist_ip` after a successful
add so the cleanup hook can find it on teardown.

### State blob download (tier 3 only)

```
az storage blob download ...
```

The state blob is downloaded to `<env_run_dir>/<project>/<env>/state.tfstate`,
converted to plan-JSON shape via `scanner/tfstate_to_plan.py`, then
**shredded** (`shred -u`) before the scanner exits (PCI 10.7
hygiene — see the plan-artifact shredding in
`scanner/orchestrator.py`).

## How the guard is implemented

`scanner/safety.py` defines:

```text
REFUSE_PATTERN: tuple[str, ...]           # Regex patterns
REFUSE_REASON: dict[str, str]             # Human-readable reason per pattern
ALLOWED_EXCEPTIONS: tuple[str, ...]      # Patterns exempted from refusal

class SafetyGuard:
    def refuse_if_mutating(self, cmd: str) -> None:
        # Returns None if allowed
        # Raises MutatingOperationRefused if refused
```

The orchestrator uses the guard via one of three paths:

1. **`scanner/orchestrator.py`'s process-spawn helper** — the
   canonical way. Calls `SafetyGuard.refuse_if_mutating` against
   the reconstructed command line, then executes via
   `subprocess.run`.

2. **`scanner/orchestrator.py`'s guarded-runner helper** — same
   guard, plus `--dry-run` support (prints the command instead of
   executing it when `DRY_RUN=1`).

3. **`SafetyGuard.refuse_if_mutating(cmd_string)` directly** —
   for cases where the caller wants to gate but not execute
   (e.g. the `run_checkov` helper in `scanner/orchestrator.py`,
   which calls `refuse_if_mutating("checkov $*")` before piping
   Checkov's output through the URL filter).

The guard is NOT optional. Every external command in
`scanner/orchestrator.py` goes through one of these guarded paths.
There are no bare `terraform` / `az` / `checkov` invocations.

## The cleanup trap

`scanner/trap.py` registers a cleanup chain via `atexit.register`
plus `signal.signal(SIGINT/SIGTERM, …)` handlers. The chain runs:

- Removes the storage firewall IP the orchestrator added (paired
  with the whitelist logic in `scanner/orchestrator.py`).
- Plan-artifact shredding (destroys `tfplan.binary` + `plan.json`).
- Removal of the staging dir for the pairs file.

The cleanup fires on:

- Normal exit (any return from the orchestrator).
- `Ctrl-C` (SIGINT).
- `kill <pid>` without `-9` (SIGTERM).

The cleanup does NOT fire on `SIGKILL` (kernel OOM, `kill -9`).
For that case, the storage firewall IP may be left behind. See
[Operator Guide → Cleaning up stale storage-firewall IPs](OPERATOR_GUIDE.md#cleaning-up-stale-storage-firewall-ips).

## The self-test

`scanner/safety.py` defines `safety_selftest()`. It runs when the
module is *invoked directly* via `python -m scanner.safety`. The
selftest:

1. Asserts that every command in the `should_refuse` list is
   refused.
2. Asserts that every command in the `should_allow` list is
   accepted (passes the guard).

The `should_refuse` list:

```python
[
    "terraform apply -auto-approve",
    "terraform destroy",
    "terraform state rm foo",
    "terraform plan -lock=false",
    "az group delete -n foo",
    "az storage account delete -n foo",
    "checkov -d . --fix",
]
```

The `should_allow` list:

```python
[
    "terraform plan -out=tfplan.binary",
    "terraform show -json tfplan.binary",
    "terraform init -backend=false",
    "az storage account network-rule add --account-name $PACIOLI_STATE_STORAGE_ACCOUNT --ip-address 1.2.3.4",
    "az storage account network-rule remove --account-name $PACIOLI_STATE_STORAGE_ACCOUNT --ip-address 1.2.3.4",
    "az storage account network-rule list --account-name $PACIOLI_STATE_STORAGE_ACCOUNT",
]
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

1. **`SafetyGuard.refuse_if_mutating`** in `scanner/safety.py` —
   pattern match against the command line. Catches accidental
   invocation.
2. **`scanner/trap.py` cleanup chain** — cleanup is *guaranteed*
   on normal exit, SIGINT, SIGTERM. Only SIGKILL bypasses it.
3. **Code review** — every PR is reviewed by a maintainer who is
   expected to read the diff against this document.
4. **Git history** — `git log --all -p -- scanner/safety.py` is
   the audit trail. Any change to the refused patterns is
   recorded in commit history with a justification.
5. **The selftest** — `make selftest` is a CI gate. A PR that
   weakens the safety guard without a corresponding selftest
   change will fail CI.

## Extending the guard

When you need to add a new refused pattern:

1. Open `scanner/safety.py`.
2. Add a new entry to the `REFUSE_PATTERN` tuple (regex, `\s`
   instead of bash `[[:space:]]`).
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
5. Document the rationale in a comment in `scanner/safety.py`.
6. Run `make selftest` and confirm `safety_selftest: PASS`.
7. Add a `safety:` commit with a detailed rationale.

## Why Python, not bash?

The driver is Python for one reason: `atexit.register` + signal
handlers give a clean, *guaranteed* cleanup story for the storage
firewall IP whitelist without the maintenance burden of a separate
shell layer. The earlier bash driver used `trap EXIT INT TERM`;
the Python equivalent (`scanner/trap.py`) handles SIGINT, SIGTERM,
and normal exit, with `atexit` as a backstop. Same guarantee, no
shell, fewer moving parts.

## See also

- [Operator Guide → Safety invariants](OPERATOR_GUIDE.md#safety-invariants)
- [Architecture](ARCHITECTURE.md) — how the guard fits in
- [Developer Guide](DEVELOPER_GUIDE.md) — extending the scanner
- [Troubleshooting](TROUBLESHOOTING.md) — common failures
