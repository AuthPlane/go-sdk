---
name: Bug Report
about: Report a bug in the Authplane Go SDK or an adapter
title: "[Bug] "
labels: bug
assignees: ""
---

## Description

A clear description of the bug.

## Affected Module

- [ ] `github.com/authplane/go-sdk/core`
- [ ] `github.com/authplane/go-sdk/http`
- [ ] `github.com/authplane/go-sdk/mcp`

## Steps to Reproduce

1. `go get` version(s) ...
2. Configure / call ...
3. Observe ...

Minimal reproducible code snippet:

```go
// paste here
```

## Expected Behavior

What you expected to happen.

## Actual Behavior

What actually happened. Include error values, HTTP status codes, and relevant log output.

## Environment

- **Module version:** (e.g., `github.com/authplane/go-sdk/core v1.2.3`)
- **Go version:** (`go version`)
- **OS:** (e.g., Ubuntu 22.04, macOS 14)
- **Framework (if adapter):** (e.g., mark3labs/mcp-go, Gin, Echo)
- **Authplane `authserver` version / issuer:** (if relevant)

## Configuration

Relevant SDK configuration (redact secrets):

```go
// paste here
```

## Logs

<details>
<summary>Relevant logs</summary>

```
(paste relevant logs here — redact any sensitive data, especially tokens)
```

</details>

## Additional Context

Any other relevant information.
