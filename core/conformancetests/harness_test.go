// Package conformancetests provides a conformance test harness that maps Go
// tests to the Authplane conformance catalog and generates execution reports
// in JSON and Markdown.
package conformancetests

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

type testStatus string

const (
	statusPassed  testStatus = "passed"
	statusFailed  testStatus = "failed"
	statusSkipped testStatus = "skipped"
	statusNotRun  testStatus = "not_run"
)

// caseResult holds the outcome of a single conformance case.
type caseResult struct {
	CaseID   string         `json:"case_id"`
	Status   testStatus     `json:"status"`
	NodeID   string         `json:"nodeid"`
	Coverage map[string]any `json:"coverage,omitempty"`
	Phase    string         `json:"phase,omitempty"`
	Failure  map[string]any `json:"failure,omitempty"`
}

// testResult holds the outcome of an uncataloged test.
type testResult struct {
	NodeID string     `json:"nodeid"`
	Status testStatus `json:"status"`
	Phase  string     `json:"phase,omitempty"`
}

// conformanceRegistry tracks cataloged and uncataloged test results.
type conformanceRegistry struct {
	mu          sync.Mutex
	cases       map[string]*caseResult
	uncataloged map[string]*testResult
}

// AllCaseIDs returns all registered case IDs (sorted for determinism).
func (r *conformanceRegistry) AllCaseIDs() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	ids := make([]string, 0, len(r.cases))
	for id := range r.cases {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids
}

// registry is the global conformance registry populated by Case() calls.
var registry = &conformanceRegistry{
	cases:       make(map[string]*caseResult),
	uncataloged: make(map[string]*testResult),
}

// ---------------------------------------------------------------------------
// Case registration options
// ---------------------------------------------------------------------------

// caseRegistration holds metadata supplied via CaseOption functions.
type caseRegistration struct {
	level string
	gaps  []string
	note  string
}

// CaseOption configures optional metadata on a conformance case.
type CaseOption func(*caseRegistration)

// Full marks a case as fully covered and records what the test demonstrated.
//
// A green row says only that a test passed; it cannot say how much of the case
// that test drove, so a reader has no way to tell full coverage from a check
// that happened to be green. The note carries what the row cannot: the
// mechanism the case was satisfied through and the bound it was demonstrated
// within.
func Full(note string) CaseOption {
	return func(r *caseRegistration) {
		r.level = "full"
		r.note = note
	}
}

// Partial marks a case as having partial coverage with a single gap.
func Partial(gap, note string) CaseOption {
	return func(r *caseRegistration) {
		r.gaps = []string{gap}
		r.note = note
	}
}

// PartialWithGaps marks a case as having partial coverage with multiple gaps.
func PartialWithGaps(gaps []string, note string) CaseOption {
	return func(r *caseRegistration) {
		r.gaps = make([]string, len(gaps))
		copy(r.gaps, gaps)
		r.note = note
	}
}

// Case registers the current test as the implementation of a conformance
// catalog case. It must be called at the top of each conformance test
// function. The test outcome (pass/fail/skip) is captured automatically via
// t.Cleanup.
func Case(t *testing.T, caseID string, opts ...CaseOption) {
	t.Helper()

	reg := &caseRegistration{}
	for _, o := range opts {
		o(reg)
	}

	coverage := map[string]any{}
	switch {
	case len(reg.gaps) > 0:
		coverage["level"] = "partial"
		coverage["gaps"] = reg.gaps
	case reg.level != "":
		coverage["level"] = reg.level
	}
	if reg.note != "" {
		coverage["note"] = reg.note
	}

	nodeID := fmt.Sprintf("conformancetests/%s", t.Name())

	result := &caseResult{
		CaseID:   caseID,
		Status:   statusNotRun,
		NodeID:   nodeID,
		Coverage: coverage,
		Phase:    "call",
	}

	registry.mu.Lock()
	registry.cases[caseID] = result
	registry.mu.Unlock()

	t.Cleanup(func() {
		registry.mu.Lock()
		defer registry.mu.Unlock()
		if t.Failed() {
			result.Status = statusFailed
			result.Failure = map[string]any{
				"message": fmt.Sprintf("test %s failed", t.Name()),
			}
		} else if t.Skipped() {
			result.Status = statusSkipped
		} else {
			result.Status = statusPassed
		}
	})
}

// ---------------------------------------------------------------------------
// Catalog loading
// ---------------------------------------------------------------------------

// projectRoot returns the absolute path of the Go SDK monorepo root
// (the directory containing core/, mcp/, http/).
func projectRoot() string {
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		panic("conformancetests: unable to determine source file via runtime.Caller")
	}
	// thisFile is .../core/conformancetests/harness_test.go → go up three Dirs
	return filepath.Dir(filepath.Dir(filepath.Dir(thisFile)))
}

var reCatalogVersion = regexp.MustCompile(`(?m)^catalog_version:\s*"([^"]+)"\s*$`)

// loadCatalogMetadata reads the conformance catalog YAML and returns the
// catalog version and the list of case IDs.
//
// The case IDs come from parseCatalogCases, not from a regex over the file. A
// regex reports what it matched and says nothing about what it did not, so a
// case in a shape it did not anticipate was dropped silently — and a dropped
// case is one the alignment guard never asks about, leaving the guard green
// while it under-checks the catalog it claims to enforce. The parser fails the
// run on any shape it cannot read instead.
func loadCatalogMetadata() (version string, caseIDs []string, err error) {
	root := projectRoot()
	catalogPath := os.Getenv("CONFORMANCE_CATALOG_PATH")
	if catalogPath == "" {
		catalogPath = os.Getenv("AUTHPLANE_CONFORMANCE_CATALOG")
	}
	if catalogPath == "" {
		catalogPath = filepath.Join(root, "..", "conformance", "oauth-sdk-conformance-catalog.yaml")
	}

	data, err := os.ReadFile(catalogPath)
	if err != nil {
		return "", nil, fmt.Errorf("read catalog: %w", err)
	}
	text := string(data)

	vMatch := reCatalogVersion.FindStringSubmatch(text)
	if len(vMatch) < 2 {
		return "", nil, fmt.Errorf("catalog_version not found in %s", catalogPath)
	}
	version = vMatch[1]

	if !strings.Contains(text, "cases:") {
		return "", nil, fmt.Errorf("cases section not found in %s", catalogPath)
	}

	cases, err := parseCatalogCases(text)
	if err != nil {
		return "", nil, fmt.Errorf("parse catalog %s: %w", catalogPath, err)
	}

	// A catalog that parses to nothing is a parser or path failure wearing a
	// success. Without this check the alignment guard's first loop has nothing
	// to iterate and the suite passes having compared itself against an empty
	// contract.
	if len(cases) == 0 {
		return "", nil, fmt.Errorf("no cases parsed from %s; the catalog-alignment guard would have nothing to check", catalogPath)
	}

	caseIDs = make([]string, 0, len(cases))
	seen := make(map[string]int, len(cases))
	for _, c := range cases {
		// Ids key the registry and the report, so a duplicate would silently
		// collapse two catalog cases into one row and let the second go
		// unchecked.
		if prev, dup := seen[c.ID]; dup {
			return "", nil, fmt.Errorf("duplicate case id %q in %s (cases %d and %d); ids key the alignment guard, so the later case would be invisible to it", c.ID, catalogPath, prev+1, len(caseIDs)+1)
		}
		seen[c.ID] = len(caseIDs)
		caseIDs = append(caseIDs, c.ID)
	}

	return version, caseIDs, nil
}

// ---------------------------------------------------------------------------
// Report generation
// ---------------------------------------------------------------------------

type reportPayload struct {
	CatalogID          string         `json:"catalog_id"`
	CatalogVersion     string         `json:"catalog_version"`
	GeneratedAt        string         `json:"generated_at"`
	Implementation     map[string]any `json:"implementation"`
	Runner             map[string]any `json:"runner"`
	Summary            map[string]int `json:"summary"`
	UncatalogedSummary map[string]int `json:"uncataloged_summary"`
	Cases              []caseResult   `json:"cases"`
	UncatalogedTests   []testResult   `json:"uncataloged_tests"`
}

func buildSummary(statuses []testStatus) map[string]int {
	s := map[string]int{
		"passed":  0,
		"failed":  0,
		"skipped": 0,
		"not_run": 0,
		"total":   len(statuses),
	}
	for _, st := range statuses {
		s[string(st)]++
	}
	return s
}

func generateReports(exitStatus int) error {
	catalogVersion, catalogIDs, err := loadCatalogMetadata()
	if err != nil {
		return fmt.Errorf("load catalog: %w", err)
	}

	root := projectRoot()

	// Build cases list: one entry per catalog case ID, in catalog order.
	registry.mu.Lock()
	cases := make([]caseResult, 0, len(catalogIDs))
	var caseStatuses []testStatus
	for _, id := range catalogIDs {
		if r, ok := registry.cases[id]; ok {
			cases = append(cases, *r)
			caseStatuses = append(caseStatuses, r.Status)
		} else {
			cases = append(cases, caseResult{
				CaseID: id,
				Status: statusNotRun,
			})
			caseStatuses = append(caseStatuses, statusNotRun)
		}
	}

	// Uncataloged tests (sorted by nodeid for determinism).
	uncataloged := make([]testResult, 0, len(registry.uncataloged))
	for _, r := range registry.uncataloged {
		uncataloged = append(uncataloged, *r)
	}
	registry.mu.Unlock()

	sort.Slice(uncataloged, func(i, j int) bool {
		return uncataloged[i].NodeID < uncataloged[j].NodeID
	})

	var uncatStatuses []testStatus
	for _, u := range uncataloged {
		uncatStatuses = append(uncatStatuses, u.Status)
	}

	payload := reportPayload{
		CatalogID:      "oauth-sdk-conformance-catalog",
		CatalogVersion: catalogVersion,
		GeneratedAt:    time.Now().UTC().Format(time.RFC3339),
		Implementation: map[string]any{
			"name":     "authplane-client-go-sdk",
			"language": "go",
			"version":  "0.1.0",
			"root":     root,
		},
		Runner: map[string]any{
			"tool":        "go test",
			"exit_status": exitStatus,
		},
		Summary:            buildSummary(caseStatuses),
		UncatalogedSummary: buildSummary(uncatStatuses),
		Cases:              cases,
		UncatalogedTests:   uncataloged,
	}

	// Write JSON report.
	jsonPath := filepath.Join(root, "conformance-report.json")
	jsonData, err := json.MarshalIndent(payload, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal report: %w", err)
	}
	if err := os.WriteFile(jsonPath, append(jsonData, '\n'), 0o644); err != nil {
		return fmt.Errorf("write JSON report: %w", err)
	}

	// Write Markdown report.
	mdPath := filepath.Join(root, "conformance-report.md")
	md := buildMarkdownReport(payload)
	if err := os.WriteFile(mdPath, []byte(md), 0o644); err != nil {
		return fmt.Errorf("write MD report: %w", err)
	}

	return nil
}

func buildMarkdownReport(p reportPayload) string {
	impl := p.Implementation
	summary := p.Summary
	uncatSummary := p.UncatalogedSummary

	var b strings.Builder
	b.WriteString("# Conformance Report\n\n")
	fmt.Fprintf(&b, "- Catalog: `%s` `%s`\n", p.CatalogID, p.CatalogVersion)
	fmt.Fprintf(&b, "- Implementation: `%s` `%s`\n", impl["name"], impl["version"])
	fmt.Fprintf(&b, "- Language: `%s`\n", impl["language"])
	fmt.Fprintf(&b, "- Generated: `%s`\n", p.GeneratedAt)
	fmt.Fprintf(&b, "- Runner: `%s` exit status `%v`\n", p.Runner["tool"], p.Runner["exit_status"])
	b.WriteString("\n## Summary\n\n")
	fmt.Fprintf(&b, "- Total: `%d`\n", summary["total"])
	fmt.Fprintf(&b, "- Passed: `%d`\n", summary["passed"])
	fmt.Fprintf(&b, "- Failed: `%d`\n", summary["failed"])
	fmt.Fprintf(&b, "- Skipped: `%d`\n", summary["skipped"])
	fmt.Fprintf(&b, "- Not run: `%d`\n", summary["not_run"])
	b.WriteString("\n## Uncataloged Suite Tests\n\n")
	fmt.Fprintf(&b, "- Total: `%d`\n", uncatSummary["total"])
	fmt.Fprintf(&b, "- Passed: `%d`\n", uncatSummary["passed"])
	fmt.Fprintf(&b, "- Failed: `%d`\n", uncatSummary["failed"])
	fmt.Fprintf(&b, "- Skipped: `%d`\n", uncatSummary["skipped"])
	fmt.Fprintf(&b, "- Not run: `%d`\n", uncatSummary["not_run"])
	b.WriteString("\n## Cases\n\n")
	b.WriteString("| Case ID | Status | Coverage | Phase | Note |\n")
	b.WriteString("|---|---|---|---|---|\n")

	for _, c := range p.Cases {
		level := ""
		note := ""
		if c.Coverage != nil {
			if l, ok := c.Coverage["level"]; ok {
				level = fmt.Sprintf("%v", l)
			} else if len(c.Coverage) > 0 {
				level = "full"
			}
			if n, ok := c.Coverage["note"]; ok {
				note = fmt.Sprintf("%v", n)
			}
		}
		fmt.Fprintf(&b, "| `%s` | `%s` | `%s` | `%s` | %s |\n",
			c.CaseID, c.Status, level, c.Phase, note)
	}

	// Failures section.
	var failures []caseResult
	for _, c := range p.Cases {
		if c.Status == statusFailed {
			failures = append(failures, c)
		}
	}
	if len(failures) > 0 {
		b.WriteString("\n## Failures\n")
		for _, c := range failures {
			fmt.Fprintf(&b, "\n### `%s`\n\n", c.CaseID)
			message := "No failure message captured."
			if c.Failure != nil {
				if m, ok := c.Failure["message"]; ok && m != "" {
					message = fmt.Sprintf("%v", m)
				}
			}
			fmt.Fprintf(&b, "- Message: %s\n", message)
			if c.Failure != nil {
				if p, ok := c.Failure["path"]; ok && p != "" {
					fmt.Fprintf(&b, "- Path: `%v`\n", p)
				}
				if l, ok := c.Failure["line"]; ok && l != nil {
					fmt.Fprintf(&b, "- Line: `%v`\n", l)
				}
				if lr, ok := c.Failure["longrepr"]; ok && lr != "" {
					fmt.Fprintf(&b, "\n```text\n%v\n```\n", lr)
				}
			}
			b.WriteString("\n")
		}
	}

	// Coverage notes section.
	var coverageNotes []caseResult
	for _, c := range p.Cases {
		if c.Coverage != nil {
			if _, ok := c.Coverage["note"]; ok {
				coverageNotes = append(coverageNotes, c)
			}
		}
	}
	if len(coverageNotes) > 0 {
		b.WriteString("\n## Coverage Notes\n")
		for _, c := range coverageNotes {
			fmt.Fprintf(&b, "\n### `%s`\n\n", c.CaseID)
			level := "full"
			if l, ok := c.Coverage["level"]; ok {
				level = fmt.Sprintf("%v", l)
			}
			fmt.Fprintf(&b, "- Level: `%s`\n", level)
			if gaps, ok := c.Coverage["gaps"]; ok {
				if gapSlice, ok := gaps.([]string); ok && len(gapSlice) > 0 {
					parts := make([]string, len(gapSlice))
					for i, g := range gapSlice {
						parts[i] = fmt.Sprintf("`%s`", g)
					}
					fmt.Fprintf(&b, "- Gaps: %s\n", strings.Join(parts, ", "))
				}
			}
			fmt.Fprintf(&b, "- Note: %v\n\n", c.Coverage["note"])
		}
	}

	// Uncataloged test details.
	if len(p.UncatalogedTests) > 0 {
		b.WriteString("\n## Uncataloged Test Details\n\n")
		b.WriteString("| Test | Status | Phase |\n")
		b.WriteString("|---|---|---|\n")
		for _, t := range p.UncatalogedTests {
			fmt.Fprintf(&b, "| `%s` | `%s` | `%s` |\n", t.NodeID, t.Status, t.Phase)
		}
	}

	return b.String()
}

// ---------------------------------------------------------------------------
// TestMain: run tests then generate reports
// ---------------------------------------------------------------------------

func TestMain(m *testing.M) {
	exitCode := m.Run()

	// Post-run catalog alignment check: every catalog case ID must have a test.
	if alignmentErrs := verifyCatalogAlignment(); len(alignmentErrs) > 0 {
		for _, e := range alignmentErrs {
			fmt.Fprintf(os.Stderr, "CATALOG ALIGNMENT: %s\n", e)
		}
		exitCode = failRun(exitCode)
	}

	// A failure here used to print and leave the exit code alone, so a run
	// whose catalog would not parse — or whose report never got written —
	// still reported success, and the report on disk stayed at whatever the
	// last good run left there. Both are the silent-under-check failure the
	// alignment guard exists to prevent, so they fail the run.
	if err := generateReports(exitCode); err != nil {
		fmt.Fprintf(os.Stderr, "conformance report generation failed: %v\n", err)
		exitCode = failRun(exitCode)
	}

	os.Exit(exitCode)
}

// failRun turns a guard failure discovered after m.Run into a red run.
//
// It raises a passing exit code to 1 and leaves a failing one alone: the code
// m.Run returned already identifies which tests failed, and overwriting it with
// a flat 1 would discard that. The guards this serves report their own detail
// to stderr, so the only thing the exit code has to carry for them is "not
// green". Extracted from TestMain so the raise is assertable — TestMain itself
// ends in os.Exit and cannot be called from a test.
func failRun(exitCode int) int {
	if exitCode == 0 {
		return 1
	}
	return exitCode
}
