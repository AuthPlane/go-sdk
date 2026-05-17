# Release Guide

How to ship a new version of the Go SDK (`core`, `http`, `mcp`). All three modules release together at the same version. See [`RELEASE_POLICY.md`](RELEASE_POLICY.md) for the policy this guide implements.

## Prerequisites

- You are a maintainer on `AuthPlane/go-sdk`.
- **`RELEASE_BOT_APP_ID`** and **`RELEASE_BOT_PRIVATE_KEY`** are set as organization secrets scoped to this repo. The Release Bot GitHub App mints a short-lived token used to push the four annotated tags and check out the conformance catalog. (`ci.yml` does not need these — the conformance repo is public.) `release.yml` fails fast with a clear error if either secret is missing — the workflow will not silently proceed.
- `CHANGELOG.md` on `main` has a populated `## [Unreleased]` section.

There is no registry to configure. `proxy.golang.org` polls public tags and begins serving the new module versions within seconds of the atomic push — **the tag push is the publish**.

## Happy path: current-line release

For a normal forward-progress release off `main`.

### 1. Cut the release branch

Dispatch **Actions → Cut release branch** from `main`. Inputs:

- `releaseVersion`: target version, e.g. `1.3.0` (no `v` prefix, no suffix).
- Leave `hotfixBase` empty.

The workflow:

- Verifies `CHANGELOG.md` has `## [Unreleased]` on `main`.
- Branches off `main` as `release/v<X.Y.Z>` (no file edits — the branch is a byte-identical copy of `main` at that point).
- Pushes the branch.

Unlike npm/PyPI SDKs there is no next-dev bump PR — Go module versions are tags, not files.

### 2. Stabilize the release branch

On `release/v<X.Y.Z>`:

- Rename `## [Unreleased]` in `CHANGELOG.md` to `## [<X.Y.Z>]`.
- On `main`, add a fresh `## [Unreleased]` header so the next release can be cut.
- Land any last-minute fixes (lint, doc updates, etc.).

The `require core` bump in `mcp/go.mod` and `http/go.mod` is handled automatically by `release.yml` — do not edit it by hand.

### 3. (Optional) Dry-run the release workflow

Dispatch **Actions → Release** with `release/v<X.Y.Z>` selected and `dryRun: true`. Runs vet, lint, require-bump, `go mod tidy`, and tests — but does **not** push the tags, create the GitHub Release, or delete the branch.

### 4. Dispatch the release workflow

Dispatch **Actions → Release** with `release/v<X.Y.Z>` selected and `dryRun: false`. The workflow:

- Runs `go vet` and `golangci-lint` across all three modules.
- Bumps `require github.com/authplane/go-sdk/core@vX.Y.Z` in `mcp/go.mod` and `http/go.mod`, then runs `go mod tidy`.
- Runs all tests (including conformance) in all three modules.
- Commits the require-bumps as `release: vX.Y.Z` on the release branch.
- Creates four annotated tags locally: `core/vX.Y.Z`, `mcp/vX.Y.Z`, `http/vX.Y.Z`, `vX.Y.Z`.
- **Atomic-pushes** the branch tip and all four tags. Either everything lands or nothing does.
- Creates the GitHub Release anchored at `vX.Y.Z` with notes from `CHANGELOG.md`.
- Deletes `release/vX.Y.Z` on the remote.

The release commit (with the require-bumps) lives only on the now-deleted release branch, but remains reachable from the four tags — `proxy.golang.org` resolves it correctly.

### 5. Confirm

- `GOPROXY=proxy.golang.org go list -m github.com/authplane/go-sdk/core@vX.Y.Z` resolves.
- `https://proxy.golang.org/github.com/authplane/go-sdk/core/@v/vX.Y.Z.info` returns JSON (same check for `mcp` and `http`).
- `https://pkg.go.dev/github.com/authplane/go-sdk/core@vX.Y.Z` populates within ~10 minutes. Trigger indexing manually if needed:
  ```bash
  GOPROXY=proxy.golang.org go get github.com/authplane/go-sdk/core@vX.Y.Z
  ```
- The GitHub Release page renders with `_Released commit: <sha>_` plus the CHANGELOG notes.

## Happy path: older-line hotfix

For patches to an older minor line — e.g. shipping `0.5.2` after `1.0.0` is already out.

### 1. Cut the hotfix branch

Dispatch **Actions → Cut release branch** from `main`. Inputs:

- `releaseVersion`: target patch, e.g. `0.5.2`.
- `hotfixBase`: the existing tag to branch from, e.g. `v0.5.1`. Must be on the same minor line as `releaseVersion` and strictly older than `main`'s latest tag.

The workflow branches off the tag as `hotfix/v<X.Y.Z>` with no file edits.

### 2. Stabilize the hotfix branch

- Add a `## [<X.Y.Z>]` section to `CHANGELOG.md` on the hotfix branch.
- Land the fix (cherry-pick from `main` or commit directly).

### 3. Dispatch the release workflow

Same as steps 3–5 of the current-line flow, but with `hotfix/v<X.Y.Z>` selected.

### 4. Backport if needed

After publish, if any commits on the hotfix branch should also reach `main`, dispatch **Actions → Backport fixes** with `fromBranch=vX.Y.Z` — the tag, because the hotfix branch is deleted by `release.yml` on success.

---

## Troubleshooting

### Atomic push fails

`release.yml` pushes the branch tip and all four tags atomically. If the push fails (e.g. a ruleset misconfiguration or a concurrent conflicting push), no remote state is mutated. Fix the cause and re-run the workflow on the same release branch — the tag-exists pre-flight will not block a retry unless a tag was somehow partially pushed.

### GitHub Release missing

If the atomic push succeeded but GitHub Release creation failed, the modules are already live. Create the release manually:

```bash
gh release create vX.Y.Z --title vX.Y.Z --notes-file <path-to-notes>
```

No `--target` — the tag already points at the correct commit.

### Source branch delete failed

`release.yml` logs a warning but does not fail the workflow if branch deletion is blocked. Delete manually:

```bash
git push origin --delete release/vX.Y.Z
```

### Tag push blocked by ruleset

If a ruleset prevents the Release Bot from pushing `v*` tags, fall back to a manual release from a maintainer machine:

```bash
v=X.Y.Z   # substitute the actual version, e.g. v=1.3.0

git clone git@github.com:AuthPlane/go-sdk.git /tmp/go-sdk-release-v"$v"
cd /tmp/go-sdk-release-v"$v"
git checkout release/v"$v"

git config user.name "<your-github-username>"
git config user.email "<your-authplane-email>"

for mod in mcp http; do
  (cd "$mod" && go mod edit -require=github.com/authplane/go-sdk/core@v"$v" && go mod tidy)
done
git add -A
git commit --allow-empty -m "release: v$v"

git tag -a "core/v$v" -m "core v$v"
git tag -a "mcp/v$v"  -m "mcp v$v"
git tag -a "http/v$v" -m "http v$v"
git tag -a "v$v"      -m "Release v$v"

git push --atomic origin "release/v$v" "core/v$v" "mcp/v$v" "http/v$v" "v$v"
```

After the push, create the GitHub Release and delete the branch:

```bash
sha="$(git rev-parse HEAD)"
{ echo "_Released commit: \`$sha\`_"; echo
  awk "/^## \[$v\]/{f=1;next} /^## \[/{f=0} f" CHANGELOG.md
} > /tmp/notes-v"$v".md

gh release create "v$v" --title "v$v" --notes-file /tmp/notes-v"$v".md
git push origin --delete "release/v$v"
rm -rf /tmp/go-sdk-release-v"$v"
```

Then confirm via step 5 of the happy path.
