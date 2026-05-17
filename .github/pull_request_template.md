## Summary

Brief description of what this PR does and why.

## Linked Issue

<!-- e.g., Fixes #123 -->

## Changes

-

## Affected Modules

- [ ] `core` (`github.com/authplane/go-sdk/core`)
- [ ] `http` (`github.com/authplane/go-sdk/http`)
- [ ] `mcp` (`github.com/authplane/go-sdk/mcp`)
- [ ] None (infra / docs / CI only)

## Test Plan

How was this tested? Include relevant test names or manual verification steps.

## Checklist

- [ ] `go vet ./...` passes for affected modules
- [ ] `go test -race ./...` passes for affected modules
- [ ] Coverage unchanged or improved (core module ≥ 80%)
- [ ] `go mod tidy` run if dependencies changed; `go.sum` committed
- [ ] Tests added for new functionality
- [ ] Documentation updated (if applicable)
- [ ] `CHANGELOG.md` entry added under `[Unreleased]` (if user-facing)
- [ ] New workflow actions are SHA-pinned (`pinact run` after changes)
- [ ] No token values, secrets, or key material in logs or test fixtures
