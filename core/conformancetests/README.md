# Conformance Test Suite

This directory contains the Go SDK conformance tests, mapped to the shared [Authplane Conformance Catalog](https://github.com/AuthPlane/conformance).

## How It Works

### Case-based mapping

Each test is mapped to a catalog case ID via `Case()`:

```go
func TestRFC9068_ValidATJWTMustVerify(t *testing.T) {
    Case(t, "rfc9068-valid-at-jwt-must-verify")

    claims, err := res.VerifyToken(ctx, validToken)
    require.NoError(t, err)
    assert.Equal(t, "user123", claims.Sub())
}
```

There is no external mapping file. The case ID lives on the test itself.

### Coverage metadata

Tests can carry optional coverage metadata via `CaseOption` functions:

```go
func TestRFC9449_DPoPProofJWKMustNotIncludePrivateKeyMaterial(t *testing.T) {
    Case(t, "rfc9449-dpop-proof-jwk-must-not-include-private-key-material",
        Partial("expected.error_hint", "Go rejects the proof but does not expose a stable diagnostic"),
    )
    // ...
}
```

For multiple gaps:

```go
Case(t, "some-case-id",
    PartialWithGaps(
        []string{"expected.field_a", "expected.field_b"},
        "These fields are not yet exposed by the Go SDK",
    ),
)
```

| Function | Description |
|----------|-------------|
| `Partial(gap, note)` | Marks partial coverage with a single gap |
| `PartialWithGaps(gaps, note)` | Marks partial coverage with multiple gaps |

### Not-yet-implemented tests

Tests for features that don't exist yet should still be present with `Case()` and a note explaining the gap. These tests fail intentionally and show up as `failed` with their note in the report:

```go
func TestRFC9449_DPoPInboundNonceMustBeValidatedWhenRequired(t *testing.T) {
    Case(t, "rfc9449-dpop-inbound-nonce-must-be-validated-when-required",
        Partial("", "Not implemented: verifier has no expected_nonce parameter"),
    )
    // test body exercises the expected API -- will fail until implemented
}
```

## Catalog Setup

The conformance tests need access to the catalog YAML file. Two options:

### Option 1: Local sibling directory (monorepo / default)

If the catalog repo is cloned as a sibling directory named `conformance`, the harness finds it automatically:

```text
parent/
├── go-sdk/         # this repo (contains core/, mcp/, http/)
└── conformance/    # catalog repo
    └── oauth-sdk-conformance-catalog.yaml
```

### Option 2: Environment variable

Set `CONFORMANCE_CATALOG_PATH` (or `AUTHPLANE_CONFORMANCE_CATALOG`) to the absolute path of the catalog YAML file:

```bash
# Clone the catalog repo anywhere
git clone git@github.com:AuthPlane/conformance.git /path/to/catalog

# Point the harness at it
export CONFORMANCE_CATALOG_PATH=/path/to/catalog/oauth-sdk-conformance-catalog.yaml
```

This is useful in CI or when the catalog is not a sibling directory.

## Running

```bash
# Run the conformance suite
go test ./conformancetests/ -v

# Run alongside the main test suite
go test ./...
```

## Reports

After each run, two reports are generated in the project root:

- **`conformance-report.json`** -- Machine-readable results with case IDs, status, coverage metadata, and failure details.
- **`conformance-report.md`** -- Human-readable Markdown with summary, cases table (including notes column), failures, and coverage notes.

Report generation is handled by `TestMain` in `harness_test.go`. It runs after all tests complete and produces both files automatically.

## Test Files

| File | Scope |
|------|-------|
| `rfc9068_test.go` | RFC 9068 (JWT Access Token Profile) |
| `rfc8725_test.go` | RFC 8725 (JWT Best Current Practices) |
| `rfc9449_test.go` | RFC 9449 (DPoP) |
| `rfc9728_test.go` | RFC 9728 (Protected Resource Metadata) |
| `rfc8414_test.go` | RFC 8414 (AS Metadata Discovery) |
| `rfc6749_test.go` | RFC 6749 (OAuth 2.0 Framework) |
| `rfc7009_test.go` | RFC 7009 (Token Revocation) |
| `rfc7662_test.go` | RFC 7662 (Token Introspection) |
| `rfc8693_test.go` | RFC 8693 (Token Exchange) |
| `rfc8707_test.go` | RFC 8707 (Resource Indicators) |
| `harness_test.go` | Test harness: `Case()`, result collection, report generation, `TestMain` |
| `catalog_alignment_test.go` | Meta-check: ensures every catalog case ID has a `Case()` registration |

## Catalog Alignment

`catalog_alignment_test.go` provides a `verifyCatalogAlignment()` function called from `TestMain` after all tests run. It verifies that every case ID in the shared catalog has a corresponding `Case()` call somewhere in the suite. If a new case is added to the catalog without a matching test, the suite fails.

The alignment check also detects the reverse: if a test registers a case ID that does not exist in the catalog, it is flagged as an error.
