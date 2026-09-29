package conformancetests

// Tests for loadCatalogMetadata's fail-loudly guards and for the exit-code
// raise TestMain applies when one of them fires.
//
// These guards are the reason the catalog parser exists: a guard that
// under-checks while reporting green is worse than a red run, because the
// report then says "passed" for a contract the suite never fully compared
// itself against. An untested guard is the same failure one level up — it can
// stop firing and nothing notices. So each of the three is pinned here.
//
// The fixtures go through CONFORMANCE_CATALOG_PATH, which loadCatalogMetadata
// reads at call time. That is the documented way to point a run at a specific
// catalog, and t.Setenv restores the previous value when the test ends, so the
// post-run alignment check and report generation in TestMain still see the
// pinned catalog.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// writeCatalog writes body to a file in a temp dir and points
// CONFORMANCE_CATALOG_PATH at it for the duration of the test.
func writeCatalog(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "catalog.yaml")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("write fixture catalog: %v", err)
	}
	t.Setenv("CONFORMANCE_CATALOG_PATH", path)
	return path
}

// A catalog that parses to zero cases must fail the run. Without this guard
// verifyCatalogAlignment's first loop has nothing to iterate, so it reports no
// drift for a catalog it never read — the guard passes precisely because it
// checked nothing. The likely causes are a wrong path or a parser that stopped
// recognizing the cases block, and both look identical to "the catalog is
// fine" from the outside.
func TestLoadCatalogMetadata_RejectsZeroCases(t *testing.T) {
	path := writeCatalog(t, "catalog_version: \"1.2.3\"\ncases:\n")

	_, ids, err := loadCatalogMetadata()
	if err == nil {
		t.Fatalf("loadCatalogMetadata: expected an error for a catalog with no cases, got nil and %d ids", len(ids))
	}
	if !strings.Contains(err.Error(), "no cases parsed") {
		t.Errorf("error = %v, want it to report that no cases were parsed", err)
	}
	if !strings.Contains(err.Error(), path) {
		t.Errorf("error = %v, want it to name the catalog it read (%s) so a wrong path is diagnosable", err, path)
	}
}

// Two cases sharing an id must fail the run. Ids key both the alignment map and
// the report rows, so the second case would overwrite the first: the suite
// would report on one row where the catalog has two, and the case that lost the
// collision would never be asked for. That is a silent shrink of the contract,
// which is exactly what these guards exist to make loud.
func TestLoadCatalogMetadata_RejectsDuplicateCaseID(t *testing.T) {
	writeCatalog(t, `catalog_version: "1.2.3"
cases:
  - id: "rfc9728-prm-1"
    title: "First"
  - id: "rfc8707-resource-1"
    title: "Second"
  - id: "rfc9728-prm-1"
    title: "Third, colliding with the first"
`)

	_, ids, err := loadCatalogMetadata()
	if err == nil {
		t.Fatalf("loadCatalogMetadata: expected an error for a duplicate case id, got nil and ids %v", ids)
	}
	msg := err.Error()
	if !strings.Contains(msg, "duplicate case id") {
		t.Errorf("error = %v, want it to report a duplicate case id", err)
	}
	// The id and both positions are what make the error actionable in a
	// 100+-case catalog; naming only "a duplicate" leaves the operator to find
	// it by hand.
	if !strings.Contains(msg, "rfc9728-prm-1") {
		t.Errorf("error = %v, want it to name the colliding id", err)
	}
	if !strings.Contains(msg, "1") || !strings.Contains(msg, "3") {
		t.Errorf("error = %v, want it to name both colliding case positions", err)
	}
}

// The happy path, as the control for the two guards above: a well-formed
// catalog must load, so a test that fails there fails for the shape it names
// and not because the fixture route itself is broken.
func TestLoadCatalogMetadata_ReadsFixtureCatalog(t *testing.T) {
	writeCatalog(t, `catalog_version: "1.2.3"
cases:
  - id: "rfc9728-prm-1"
    title: "First"
  - id: "rfc8707-resource-1"
    title: "Second"
`)

	version, ids, err := loadCatalogMetadata()
	if err != nil {
		t.Fatalf("loadCatalogMetadata: unexpected error: %v", err)
	}
	if version != "1.2.3" {
		t.Errorf("version = %q, want %q", version, "1.2.3")
	}
	want := []string{"rfc9728-prm-1", "rfc8707-resource-1"}
	if len(ids) != len(want) {
		t.Fatalf("ids = %v, want %v", ids, want)
	}
	for i := range want {
		// Catalog order is the report's row order, so it is part of the
		// contract, not an incidental.
		if ids[i] != want[i] {
			t.Errorf("ids[%d] = %q, want %q", i, ids[i], want[i])
		}
	}
}

// generateReports must surface a catalog it cannot load as an error rather than
// writing a report anyway. It is the only caller of loadCatalogMetadata that
// runs on every invocation, so this is the path by which a broken catalog
// reaches TestMain — and it must reach it as an error, because a report written
// from a catalog that did not load would carry a summary computed over no
// cases.
func TestGenerateReports_FailsOnUnloadableCatalog(t *testing.T) {
	root := projectRoot()
	reports := []string{
		filepath.Join(root, "conformance-report.json"),
		filepath.Join(root, "conformance-report.md"),
	}
	before := make([]os.FileInfo, len(reports))
	for i, path := range reports {
		if fi, statErr := os.Stat(path); statErr == nil {
			before[i] = fi
		}
	}

	missing := filepath.Join(t.TempDir(), "does-not-exist.yaml")
	t.Setenv("CONFORMANCE_CATALOG_PATH", missing)

	err := generateReports(0)
	if err == nil {
		t.Fatal("generateReports: expected an error for a catalog that cannot be read, got nil")
	}
	if !strings.Contains(err.Error(), "load catalog") {
		t.Errorf("error = %v, want it to report a catalog load failure", err)
	}

	// The reports on disk must be left untouched rather than truncated or
	// rewritten from a catalog that did not load. A report written from a
	// failed load would carry a summary computed over no cases at all, which
	// reads as a clean run; a visibly stale report does not.
	for i, path := range reports {
		fi, statErr := os.Stat(path)
		if before[i] == nil {
			if statErr == nil {
				t.Errorf("generateReports created %s after failing to load the catalog", path)
			}
			continue
		}
		if statErr != nil {
			t.Errorf("generateReports removed %s after failing to load the catalog: %v", path, statErr)
			continue
		}
		if !fi.ModTime().Equal(before[i].ModTime()) || fi.Size() != before[i].Size() {
			t.Errorf("generateReports rewrote %s after failing to load the catalog", path)
		}
	}
}

// A guard that fires after m.Run has already returned has no *testing.T to fail,
// so the exit code is the only channel it has. failRun is where that happens:
// TestMain routes both the alignment failure and the report-generation failure
// through it. Before this release a failure there printed to stderr and left
// the exit code alone, so a run whose catalog would not parse still reported
// success — the green-while-under-checking failure the whole guard exists to
// prevent.
func TestFailRun_RaisesGreenAndPreservesRed(t *testing.T) {
	if got := failRun(0); got != 1 {
		t.Errorf("failRun(0) = %d, want 1: a guard failure must turn a green run red", got)
	}
	// A non-zero code already names which tests failed; flattening it to 1
	// would throw that away for no gain, since the guards print their own
	// detail to stderr.
	for _, code := range []int{1, 2, 3} {
		if got := failRun(code); got != code {
			t.Errorf("failRun(%d) = %d, want %d: an existing failure code must be preserved", code, got, code)
		}
	}
}
