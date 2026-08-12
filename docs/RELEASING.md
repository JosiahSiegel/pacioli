# Releasing Pacioli

> How the release pipeline actually works in this repo, what triggers a
> release, what doesn't, and how to force one when needed. This is the
> ground-truth document — the `.github/release-please-config.json`,
> `.github/workflows/release-please.yml`, and `CONTRIBUTING.md` are
> referenced from here.

This repo uses [release-please](https://github.com/googleapis/release-please)
(Google's GitHub Action) on the `main` branch to automate versioning,
CHANGELOG generation, GitHub Releases, and PyPI publishing. Everything
runs from `.github/workflows/release-please.yml` and the config in
`.github/release-please-config.json`. There is no separate `make release`
or manual tag step.

---

## TL;DR

| You merged… | Result |
|---|---|
| Any `feat:` commit | release-please opens a release PR (minor bump) |
| Any `fix:` or `perf:` commit | release-please opens a release PR (patch bump) |
| A `BREAKING CHANGE:` footer | release-please opens a release PR (major bump) |
| Only `chore:`, `ci:`, `docs:`, `test:`, `build:`, `refactor:`, `revert:` commits since the last release | **No release PR.** CI runs but logs `No user facing commits found since <sha> - skipping` |
| You need to force a release anyway | Push an empty commit with `Release-As: x.y.z` in the body |

---

## What actually triggers a release PR

release-please scans commits since the last release SHA and looks for
"releasable units". The trigger comes from two places, both in
`.github/release-please-config.json`:

### 1. The version bump rule

Driven by `determineReleaseType()` in
[release-please's default strategy](https://github.com/googleapis/release-please/blob/main/src/versioning-strategies/default.ts).
For every commit since the last release tag:

| Commit trait | Bump |
|---|---|
| `BREAKING CHANGE:` footer (or `!` after type) | **major** (or minor if `bump-minor-pre-major: true` and pre-1.0) |
| `feat:` / `feature:` | **minor** |
| anything else | **patch** (default fallback) |

This is why a `chore(ci):` commit *would* technically bump the version
to `0.2.1` if release-please opened a PR — but it doesn't, because of
the second rule.

### 2. The skip rule

After computing the bump type, release-please checks whether any
commit type is **not hidden** in `changelog-sections`. From the
[default sections](https://github.com/googleapis/release-please/blob/main/src/util/filter-commits.ts):

```typescript
const DEFAULT_CHANGELOG_SECTIONS = [
  {type: 'feat',     section: 'Features',                  hidden: false},
  {type: 'fix',      section: 'Bug Fixes',                 hidden: false},
  {type: 'perf',     section: 'Performance Improvements',  hidden: false},
  {type: 'revert',   section: 'Reverts',                   hidden: false},
  {type: 'chore',    section: 'Miscellaneous Chores',      hidden: true},
  {type: 'docs',     section: 'Documentation',             hidden: true},
  {type: 'style',    section: 'Styles',                    hidden: true},
  {type: 'refactor', section: 'Code Refactoring',          hidden: true},
  {type: 'test',     section: 'Tests',                     hidden: true},
  {type: 'build',    section: 'Build System',              hidden: true},
  {type: 'ci',       section: 'Continuous Integration',    hidden: true},
];
```

Pacioli's config overrides `refactor` to be **visible** (in the
"Changed" section), so refactors *do* trigger a release PR. Everything
else hidden-vs-visible matches the defaults.

If **every** commit since the last release has a hidden type, the
workflow logs:

```
✔ No user facing commits found since <sha> - skipping
```

…and does **not** open a release PR. No tag, no GitHub Release, no
PyPI publish. This is the correct behavior, not a bug — release-please
is telling you "nothing here is worth shipping to users".

---

## The release flow end-to-end

1. You merge a PR with a `feat:` / `fix:` / `perf:` commit (or
   `BREAKING CHANGE:`) into `main`.
2. `.github/workflows/ci.yml` runs first (tests + lint + safety).
3. `.github/workflows/release-please.yml` runs after CI. It sees the
   releasable commits, opens (or updates an existing) release PR.
4. The release PR's title is
   `chore(main): release <major>.<minor>.<patch>` (configurable via
   `pull-request-title-pattern` if needed). Its body previews the
   CHANGELOG diff, and it bumps `pyproject.toml` (and `CITATION.cff`
   per `extra-files`).
5. You review and merge the release PR.
6. On the merge push, release-please creates the GitHub Release, the
   `vX.Y.Z` tag, and runs `.github/workflows/release.yml` which builds
   the wheel + sdist and publishes to PyPI (see `release.yml` for the
   current PyPI config).

---

## When you want to force a release

If you need a release on top of a merge that release-please skipped
(e.g., shipping the hygiene improvements from
`.omo/evidence/...` cleanup that were all `chore:`), use the canonical
mechanism from the [release-please README](https://github.com/googleapis/release-please#how-do-i-change-the-version-number-of-a-release):

```bash
git commit --allow-empty -m "chore: force release v0.2.1

Release-As: 0.2.1"
git push origin main
```

The `Release-As: x.y.z` line in the commit body forces the next release
to use exactly that version, regardless of conventional-commit types.

### Why `chore(main): release 0.2.1` does NOT work

If you push a regular commit titled `chore(main): release 0.2.1` and
bump `pyproject.toml` to `0.2.1` by hand, release-please will **still
skip** the next run. Here's why:

- The commit type is `chore`, which is **hidden** in
  `changelog-sections`.
- release-please decides whether to open a release PR based on commit
  types, **not** by reading `pyproject.toml`.
- It computes the bump type from `determineReleaseType()`, sees only
  hidden commits, and logs `No user facing commits found since ... -
  skipping`.
- The manually-edited `pyproject.toml` is ignored — release-please will
  overwrite it with the computed next version on the next real release.

So manually bumping `pyproject.toml` and pushing it as a normal commit
is a no-op for the release pipeline. It just sits there until the next
legitimate `feat:` / `fix:` lands, at which point release-please opens
its own PR with its own version calculation (which may or may not
match your manual edit).

The **only** ways to force a specific version are:

1. **The `Release-As:` footer** (recommended; documented; one-line
   empty commit).
2. **`release-as` in `release-please-config.json`** (config-level;
   affects every release until you remove it).
3. **A `BREAKING CHANGE:` footer on a `feat:` commit** (forces major
   bump, but also opens a release PR).

---

## Diagnosing "no release happened"

If you expected a release and didn't get one, walk this list:

1. **Check the `release-please` workflow run on the push.**
   `gh run list --workflow=release-please.yml --limit 5`. The log will
   say either:
   - `✔ Building pull requests` → a release PR was opened or updated
   - `✔ No user facing commits found since <sha> - skipping` → no
     releasable commits since the last release tag
   - An error → see the stack trace

2. **Check the last release SHA.** release-please uses the GitHub API
   to find the latest release for `package-name: "pacioli"`. If the
   latest GitHub Release isn't tagged at the commit you think it is,
   the "since" baseline will be wrong.

   ```bash
   gh release list --limit 5
   ```

3. **Check the PR title pattern.** release-please also accepts PR
   titles as the "primary commit message" for squash-merged PRs. A
   squash-merged PR with title `docs: typo` produces a hidden `docs:`
   commit on main even if the PR contained code changes. If you want
   squash-merged feat PRs to count, use a `feat:` PR title.

4. **Check `changelog-sections` in
   `.github/release-please-config.json`.** If a commit type you expect
   to trigger a release is missing from that list, it's treated as
   hidden by default.

5. **Force a release.** If everything above looks right and you still
   need a release, use the `Release-As:` empty-commit mechanism.

---

## Configuration files (read-only reference)

| File | What it controls |
|---|---|
| `.github/workflows/release-please.yml` | Triggers on push to `main`, calls `googleapis/release-please-action@v4` with `release-type: python` and `publish-target: github`. |
| `.github/release-please-config.json` | `package-name`, `changelog-path`, `changelog-sections` (which types are visible), `version-file: pyproject.toml`, `extra-files: [CITATION.cff]`. |
| `.github/workflows/release.yml` | Triggered by a successful release-please run. Builds the wheel + sdist and publishes to PyPI. |
| `pyproject.toml` | The version field release-please updates on each release PR. |
| `CITATION.cff` | Listed in `extra-files`; release-please updates the `version:` and `date-released:` fields here too. |
| `CHANGELOG.md` | Listed in `changelog-path`; release-please appends the new section here on each release PR. |

---

## What this doc does NOT cover

- **Pre-1.0 versioning semantics.** Pacioli is at 0.x.y. Release-please
  treats this normally (0.2.0 → 0.2.1 → 0.3.0); there's no
  `bump-minor-pre-major` config set. If we want to change that, edit
  `.github/release-please-config.json`.
- **Manual PyPI uploads.** Everything goes through
  `.github/workflows/release.yml`. If you need to upload a one-off
  build manually, that's a separate workflow not documented here.
- **The release-please release PR's review process.** We currently
  auto-merge release PRs by convention; if we change that, update this
  doc.

---

## Pointers

- release-please README:
  <https://github.com/googleapis/release-please#readme>
- release-please design doc:
  <https://github.com/googleapis/release-please/blob/main/docs/design.md>
- Default versioning strategy (the source of the bump rules):
  <https://github.com/googleapis/release-please/blob/main/src/versioning-strategies/default.ts>
- Default `changelog-sections` (the source of the skip rule):
  <https://github.com/googleapis/release-please/blob/main/src/util/filter-commits.ts>
- Conventional Commits spec (the commit grammar release-please parses):
  <https://www.conventionalcommits.org/en/v1.0.0/#specification>