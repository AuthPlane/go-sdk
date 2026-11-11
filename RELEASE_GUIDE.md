# Release Guide

How to ship a new version of the Go SDK (`core`, `http`, `mcp`, `mark3labs`). All four modules release together at the same version. See [`RELEASE_POLICY.md`](RELEASE_POLICY.md) for the policy this guide implements.

## Prerequisites

- You are a maintainer on `AuthPlane/go-sdk`.
- **`RELEASE_BOT_APP_ID`** and **`RELEASE_BOT_PRIVATE_KEY`** are set as secrets of the `release` environment, never repository or organization secrets. The Release Bot GitHub App mints a short-lived token used to push the five annotated tags. (`ci.yml` does not need these — the conformance repo is public.) `release.yml` fails fast with a clear error if either secret is missing — the workflow will not silently proceed.
- `CHANGELOG.md` on `main` has a populated `## [Unreleased]` section.

There is no registry to configure. `proxy.golang.org` polls public tags and begins serving the new module versions within seconds of the atomic push — **the tag push is the publish**.

## Release

A release is a pull request. Merging it releases.

### 1. Open the release PR

Open a PR into `main` titled `release: prepare vX.Y.Z` (add ` (major)` for a new major version). It carries the release's changes, with every entry under `## [Unreleased]` in `CHANGELOG.md`.

The **Release** workflow runs on it as a check: a dry run of the commit the merge will create. It refuses a version that exists or is not the next patch, minor or major, and a changelog with no unreleased entries. It renames `## [Unreleased]` to `## [X.Y.Z] - <date>`, bumps `require github.com/authplane/go-sdk/core` (and `http` in `mark3labs`) to `vX.Y.Z`, drops the local `replace` lines, runs vet, lint and every test including conformance, and creates the five tags locally. It pushes nothing and uses no secrets. Make this check required on `main`, so a release PR cannot merge without it.

### 2. Merge it

Squash-merge the PR, keeping its title as the commit subject. The Release workflow then runs on that commit, waits for an approval in the `release` environment, and:

- Runs the same steps again on the merged commit.
- **Atomic-pushes the five tags** (`core/vX.Y.Z`, `mcp/vX.Y.Z`, `http/vX.Y.Z`, `mark3labs/vX.Y.Z`, `vX.Y.Z`). Only the tags go up: the release commit with the require bumps is reachable from them and never lands on `main`. This cannot be undone.
- Creates the GitHub Release with the changelog section as notes.
- Opens `docs(changelog): record vX.Y.Z` against `main`: the changelog as tagged, with an empty `## [Unreleased]` above it.
- Builds a program using all four modules from the module proxy, outside the workspace.

### 3. Confirm

- The `consumer` job passed, and the changelog PR is merged.
- `GOPROXY=proxy.golang.org go list -m github.com/authplane/go-sdk/core@vX.Y.Z` resolves, and the same for `mcp`, `http` and `mark3labs`.

### Settings, once

On `main`: allow squash merges only, with the PR title as the default commit message; make the `release` check required; no merge queue. A real run also refuses a commit that is not the squash merge of one PR whose title names the same version.

In **Settings → Environments**:

- `release`: required reviewers, so every real run waits for an approval. With **Prevent self-review** on, a second person must approve; with one maintainer it has to stay off, and each run then warns that one person can release. Deployment branch `main` only, as a branch, not a tag. The Release Bot secrets (`RELEASE_BOT_APP_ID`, `RELEASE_BOT_PRIVATE_KEY`) as **environment** secrets, never repository or organization secrets. A real run refuses to start without the reviewers and the branch policy, or when it cannot read them.
- `release-check`: no rules and no secrets. Dry runs on pull requests use it.

The tag-pushing token is minted after every test, with permission to write contents only, and no git hook runs during the commit or the push.


## An older version

There is no patch path for an older minor line: every release so far was cut from `main`. If one is ever needed, add it for that case.

## Troubleshooting

### A run fails after the merge

Nothing was pushed unless the run reached the tag push, which is atomic: either all five tags land or none do. Fix the cause on `main`, then dispatch **Release** from `main` with `version`: a dry run first (the default), then `-f dryRun=false -f expectedSha=<sha>` with the commit its summary prints.

### GitHub Release missing

If the tags were pushed but creating the GitHub Release failed, the modules are already live. Create it by hand:

```bash
gh release create vX.Y.Z --title vX.Y.Z --notes-file <path-to-notes>
```

No `--target`: the tag already points at the right commit.

### Changelog PR missing

The run skips it, with a warning, when `CHANGELOG.md` changed on `main` after the merge. Record the released section on `main` by hand, with an empty `## [Unreleased]` above it.

### Tag push blocked

If a ruleset refuses the Release Bot's tag push, fix the ruleset's bypass list and dispatch again. Do not tag from a laptop: the tags must point at the commit the workflow tested.
