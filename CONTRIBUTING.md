# Contributing to the Authplane Go SDK

Thanks for your interest in contributing. This repository is a Go workspace with three modules published via git tags and served by `proxy.golang.org`:

| Module import path | Directory |
|---|---|
| `github.com/authplane/go-sdk/core` | `core/` |
| `github.com/authplane/go-sdk/http` | `http/` |
| `github.com/authplane/go-sdk/mcp` | `mcp/` |

`http` and `mcp` depend on `core`. A single tagged release tags all three (`core/vX.Y.Z`, `http/vX.Y.Z`, `mcp/vX.Y.Z`, plus an umbrella `vX.Y.Z`).

## Reporting Issues

- **Bugs:** open a [bug report](https://github.com/AuthPlane/go-sdk/issues/new?template=bug-report.md). Include module, version, Go version, and a minimal reproduction.
- **MCP compatibility:** use the [MCP Compatibility Report](https://github.com/AuthPlane/go-sdk/issues/new?template=mcp-compatibility.md) template.
- **Feature requests:** open a [feature request](https://github.com/AuthPlane/go-sdk/issues/new?template=feature-request.md). Describe the problem, then the proposed solution.
- **Security vulnerabilities:** do **not** open a public issue. See [SECURITY.md](SECURITY.md).

## Development Setup

### Prerequisites

- Go 1.25+ — required by the workspace (`go.work` pins ≥ 1.25 because `mcp` requires it, forced by `modelcontextprotocol/go-sdk`). Per-module consumer contracts are looser: `core`/`http` declare `go 1.24.0` with `toolchain go1.25.0`; `mcp` declares `go 1.25.0`.
- `git`

### Clone and build

```bash
git clone https://github.com/AuthPlane/go-sdk.git
cd go-sdk
# Workspace resolves the three modules from go.work
go work sync
go build ./...
```

The top-level `go.work` ties `core/`, `http/`, and `mcp/` into a single workspace, so inter-module changes are picked up without publishing.

## Local Verification

Run the same checks CI runs before opening a PR. All commands assume you're at the repo root.

**Vet:**

```bash
go vet ./core/... ./http/... ./mcp/...
```

**Tests:**

```bash
(cd core && go test ./...)
(cd http && go test ./...)
(cd mcp  && go test ./...)
```

**Race detector (for anything concurrent):**

```bash
(cd core && go test -race ./...)
```

**Coverage (core module has an 80% floor in CI):**

```bash
(cd core && go test -coverprofile=coverage.out $(go list ./... | grep -v /conformancetests))
(cd core && go tool cover -func=coverage.out | tail -1)
```

**Vulnerability scan:**

```bash
go install golang.org/x/vuln/cmd/govulncheck@latest
(cd core && govulncheck ./...)
(cd http && govulncheck ./...)
(cd mcp  && govulncheck ./...)
```

## Pull Request Guidelines

- Branch off `main`. Release branches (`release/v*`, `hotfix/v*`) are managed by the release flow — see [RELEASE_POLICY.md](RELEASE_POLICY.md).
- PR titles follow [Conventional Commits](https://www.conventionalcommits.org/): `feat:`, `fix:`, `docs:`, `ci:`, `deps:`, `refactor:`, `test:`, `chore:`.
- Link the related GitHub issue (e.g., `Fixes #123`) in the PR description.
- Fill out the PR template (summary, testing, checklist).
- Run `go mod tidy` in any module whose deps changed; commit the updated `go.sum`.
- Keep PRs focused. Large, multi-theme PRs are hard to review and easy to stall.

## Changelog

User-facing changes go in [`CHANGELOG.md`](CHANGELOG.md) under the `[Unreleased]` heading. Follow the [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) format. Release tooling moves entries from `[Unreleased]` to the release version on tag.

## GitHub Actions — SHA-pinning

All workflow actions must be SHA-pinned with a version comment:

```yaml
uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683  # v4.2.2
```

When editing or adding a workflow, run [`pinact`](https://github.com/suzuki-shunsuke/pinact) to pin any new `uses:` lines before committing:

```bash
pinact run
```

Dependabot opens weekly PRs to bump the SHAs (see [`.github/dependabot.yml`](.github/dependabot.yml)).

## Release Process

Releases are driven by the release workflow. The detailed procedure lives in [RELEASE_POLICY.md](RELEASE_POLICY.md). As a contributor you don't need to trigger releases — maintainers handle them. `proxy.golang.org` indexes tags automatically within seconds of a push, so there is no registry-publish step.

## Code of Conduct

Be kind. Disagree on substance, not people. Projects that aren't kind don't last.
