package conformancetests

// Crafted-shape tests for parseCatalogCases.
//
// The catalog is shared, it changes independently of this repo, and the
// alignment guard keys on the ids this parser produces. So the property under
// test is not "the current catalog parses" — it does, and a regex managed that
// too. It is that a shape the parser cannot read fails the run rather than
// disappearing from the guard's view. Every negative case below is a shape that
// a match-what-you-can extractor returns quietly and incompletely.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// mustParse parses fixture text and fails the test on error.
func mustParse(t *testing.T, yamlText string) []conformanceCase {
	t.Helper()
	cases, err := parseCatalogCases(yamlText)
	if err != nil {
		t.Fatalf("parseCatalogCases: unexpected error: %v", err)
	}
	return cases
}

// mustFail parses fixture text, requires an error, and requires the message to
// mention want — the message is the deliverable here, since its whole job is to
// tell a maintainer which catalog line the parser refused and why.
func mustFail(t *testing.T, yamlText, want string) {
	t.Helper()
	cases, err := parseCatalogCases(yamlText)
	if err == nil {
		t.Fatalf("parseCatalogCases: expected an error, got %d cases: %+v", len(cases), cases)
	}
	if !strings.Contains(err.Error(), want) {
		t.Errorf("error = %q, want it to mention %q", err.Error(), want)
	}
}

func assertCases(t *testing.T, got []conformanceCase, want []conformanceCase) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("got %d cases, want %d: %+v", len(got), len(want), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("case %d = %+v, want %+v", i, got[i], want[i])
		}
	}
}

// An id must accept every scalar style a title does. The regex this replaced
// matched one shape — a double-quoted value alone on its line — and skipped the
// rest in silence, so a plain or single-quoted id, or one carrying an escaped
// quote, was a case the alignment guard never asked about.
func TestParseCatalogCases_IDScalarStyles(t *testing.T) {
	tests := []struct {
		name    string
		yaml    string
		wantID  string
		wantTit string
	}{
		{
			name:    "double-quoted",
			yaml:    "cases:\n  - id: \"a-b\"\n    title: \"T\"\n",
			wantID:  "a-b",
			wantTit: "T",
		},
		{
			name:    "plain unquoted",
			yaml:    "cases:\n  - id: a-b\n    title: T\n",
			wantID:  "a-b",
			wantTit: "T",
		},
		{
			name:    "single-quoted",
			yaml:    "cases:\n  - id: 'a-b'\n    title: 'T'\n",
			wantID:  "a-b",
			wantTit: "T",
		},
		{
			// The ticket's own example: an apostrophe is outside the character
			// class the old regex allowed on an unquoted value, and inside a
			// single-quoted scalar it is written doubled.
			name:    "single-quoted with doubled apostrophe",
			yaml:    "cases:\n  - id: 'client''s-id'\n    title: 'the client''s title'\n",
			wantID:  "client's-id",
			wantTit: "the client's title",
		},
		{
			name:    "double-quoted containing an apostrophe",
			yaml:    "cases:\n  - id: \"client's-id\"\n    title: \"the client's title\"\n",
			wantID:  "client's-id",
			wantTit: "the client's title",
		},
		{
			name:    "double-quoted with an escaped quote",
			yaml:    "cases:\n  - id: \"a\\\"b\"\n    title: \"say \\\"hi\\\"\"\n",
			wantID:  `a"b`,
			wantTit: `say "hi"`,
		},
		{
			name:    "double-quoted with escaped backslash and solidus",
			yaml:    "cases:\n  - id: \"a\\\\b\"\n    title: \"a\\/b\"\n",
			wantID:  `a\b`,
			wantTit: "a/b",
		},
		{
			name:    "double-quoted with tab and newline escapes",
			yaml:    "cases:\n  - id: \"a-b\"\n    title: \"one\\ttwo\\nthree\"\n",
			wantID:  "a-b",
			wantTit: "one\ttwo\nthree",
		},
		{
			name:    "double-quoted with a unicode escape",
			yaml:    "cases:\n  - id: \"a-b\"\n    title: \"RFC 9068 \\u00a72.2\"\n",
			wantID:  "a-b",
			wantTit: "RFC 9068 §2.2",
		},
		{
			// The code points immediately below and above the surrogate block,
			// which the surrogate rejection must not swallow: the guard is on
			// D800-DFFF exactly, not on "high code points".
			name:    "unicode escapes bracketing the surrogate block",
			yaml:    "cases:\n  - id: \"a-b\"\n    title: \"\\ud7ff|\\ue000\"\n",
			wantID:  "a-b",
			wantTit: "\ud7ff|\ue000",
		},
		{
			name:    "plain scalar loses its inline comment",
			yaml:    "cases:\n  - id: a-b # the id\n    title: T # the title\n",
			wantID:  "a-b",
			wantTit: "T",
		},
		{
			// A "#" not preceded by whitespace is data, not a comment.
			name:    "hash inside a plain scalar is data",
			yaml:    "cases:\n  - id: a#b\n    title: T\n",
			wantID:  "a#b",
			wantTit: "T",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assertCases(t, mustParse(t, tt.yaml), []conformanceCase{{ID: tt.wantID, Title: tt.wantTit}})
		})
	}
}

// The catalog emitter wraps every long scalar with an escaped line break plus an
// escaped leading space on the continuation line. A parser that stops at the end
// of the line returns a truncated title, and one that hunts for the next quote
// swallows the lines in between.
func TestParseCatalogCases_WrappedQuotedScalars(t *testing.T) {
	t.Run("escaped line break joins without a space", func(t *testing.T) {
		y := "cases:\n" +
			"  - id: \"a-b\"\n" +
			"    title: \"Follow a metadata rotation using only ordinary\\\n" +
			"      \\ verification traffic\"\n"
		assertCases(t, mustParse(t, y), []conformanceCase{
			{ID: "a-b", Title: "Follow a metadata rotation using only ordinary verification traffic"},
		})
	})

	t.Run("unescaped line break folds to a single space", func(t *testing.T) {
		y := "cases:\n" +
			"  - id: \"a-b\"\n" +
			"    title: \"first part\n" +
			"      second part\"\n"
		assertCases(t, mustParse(t, y), []conformanceCase{
			{ID: "a-b", Title: "first part second part"},
		})
	})

	t.Run("a wrapped id is joined the same way", func(t *testing.T) {
		y := "cases:\n" +
			"  - id: \"very-long-case\\\n" +
			"      \\ -id\"\n" +
			"    title: \"T\"\n"
		assertCases(t, mustParse(t, y), []conformanceCase{
			{ID: "very-long-case -id", Title: "T"},
		})
	})
}

// A case with an id but no title must stay in the list. The guard keys on ids,
// so dropping the case for want of a field the guard never reads would hide it
// from the only check that matters — and the case would read as "not in the
// catalog" rather than "unimplemented".
func TestParseCatalogCases_TitleFallsBackToID(t *testing.T) {
	tests := []struct {
		name string
		yaml string
	}{
		{"no title key at all", "cases:\n  - id: \"a-b\"\n    surface: \"x\"\n"},
		{"empty double-quoted title", "cases:\n  - id: \"a-b\"\n    title: \"\"\n"},
		{"title key with no value", "cases:\n  - id: \"a-b\"\n    title:\n"},
		{"whitespace-only title", "cases:\n  - id: \"a-b\"\n    title: \"   \"\n"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assertCases(t, mustParse(t, tt.yaml), []conformanceCase{{ID: "a-b", Title: "a-b"}})
		})
	}
}

// Structure the parser must read correctly rather than guess at.
func TestParseCatalogCases_BlockStructure(t *testing.T) {
	t.Run("title in a later position is still found", func(t *testing.T) {
		y := "cases:\n" +
			"  - id: \"a-b\"\n" +
			"    surface: \"sdk-verifier\"\n" +
			"    priority: \"high\"\n" +
			"    title: \"T\"\n"
		assertCases(t, mustParse(t, y), []conformanceCase{{ID: "a-b", Title: "T"}})
	})

	t.Run("a title nested deeper is not the case title", func(t *testing.T) {
		y := "cases:\n" +
			"  - id: \"a-b\"\n" +
			"    setup:\n" +
			"      title: \"nested, not mine\"\n" +
			"    title: \"T\"\n"
		assertCases(t, mustParse(t, y), []conformanceCase{{ID: "a-b", Title: "T"}})
	})

	t.Run("nested list items are not new cases", func(t *testing.T) {
		y := "cases:\n" +
			"  - id: \"a-b\"\n" +
			"    title: \"T\"\n" +
			"    standard_refs:\n" +
			"      - \"RFC8414\"\n" +
			"      - \"RFC8725\"\n" +
			"    prohibited_mechanisms:\n" +
			"      - \"force-refresh\"\n" +
			"  - id: \"c-d\"\n" +
			"    title: \"U\"\n"
		assertCases(t, mustParse(t, y), []conformanceCase{
			{ID: "a-b", Title: "T"},
			{ID: "c-d", Title: "U"},
		})
	})

	t.Run("field indentation is derived, not assumed", func(t *testing.T) {
		y := "cases:\n" +
			"    - id: \"a-b\"\n" +
			"      title: \"T\"\n" +
			"    - id: \"c-d\"\n" +
			"      title: \"U\"\n"
		assertCases(t, mustParse(t, y), []conformanceCase{
			{ID: "a-b", Title: "T"},
			{ID: "c-d", Title: "U"},
		})
	})

	t.Run("blank lines inside the block are skipped", func(t *testing.T) {
		y := "cases:\n" +
			"  - id: \"a-b\"\n" +
			"\n" +
			"    title: \"T\"\n" +
			"\n" +
			"  - id: \"c-d\"\n" +
			"    title: \"U\"\n"
		assertCases(t, mustParse(t, y), []conformanceCase{
			{ID: "a-b", Title: "T"},
			{ID: "c-d", Title: "U"},
		})
	})

	// A column-0 comment is not a top-level key. Ending the block on the first
	// unindented line would drop every case after a banner comment — and the
	// report would show those cases as absent from the catalog, not as
	// unimplemented.
	t.Run("a column-0 comment does not end the block", func(t *testing.T) {
		y := "cases:\n" +
			"  - id: \"a-b\"\n" +
			"    title: \"T\"\n" +
			"# ---- RFC 9449 cases ----\n" +
			"  - id: \"c-d\"\n" +
			"    title: \"U\"\n"
		assertCases(t, mustParse(t, y), []conformanceCase{
			{ID: "a-b", Title: "T"},
			{ID: "c-d", Title: "U"},
		})
	})

	t.Run("an indented comment does not end the block", func(t *testing.T) {
		y := "cases:\n" +
			"  - id: \"a-b\"\n" +
			"    # a note about this case\n" +
			"    title: \"T\"\n"
		assertCases(t, mustParse(t, y), []conformanceCase{{ID: "a-b", Title: "T"}})
	})

	// The block ends at the next top-level key, so an "- id:" in a later
	// top-level section is not a case. The regex this replaced took everything
	// after the first "cases:" in the file, so any later block using the same
	// key would have contributed phantom ids.
	t.Run("a top-level key ends the block", func(t *testing.T) {
		y := "cases:\n" +
			"  - id: \"a-b\"\n" +
			"    title: \"T\"\n" +
			"usage_guidance:\n" +
			"  - id: \"not-a-case\"\n" +
			"    title: \"nor this\"\n"
		assertCases(t, mustParse(t, y), []conformanceCase{{ID: "a-b", Title: "T"}})
	})

	t.Run("the document-end marker ends the block", func(t *testing.T) {
		y := "cases:\n" +
			"  - id: \"a-b\"\n" +
			"    title: \"T\"\n" +
			"...\n" +
			"  - id: \"not-a-case\"\n"
		assertCases(t, mustParse(t, y), []conformanceCase{{ID: "a-b", Title: "T"}})
	})

	t.Run("CRLF line endings", func(t *testing.T) {
		y := "cases:\r\n  - id: \"a-b\"\r\n    title: \"T\"\r\n"
		assertCases(t, mustParse(t, y), []conformanceCase{{ID: "a-b", Title: "T"}})
	})
}

// Every shape below must fail the run. A parser that skips instead leaves the
// alignment guard green while it checks less than it reports.
func TestParseCatalogCases_UnreadableShapesFailLoudly(t *testing.T) {
	tests := []struct {
		name string
		yaml string
		want string
	}{
		{
			// A case item whose first key is not "id" would otherwise be folded
			// into the previous case, and its own id — wherever it sits — never
			// seen.
			name: "list item that does not start with id",
			yaml: "cases:\n  - title: \"T\"\n    id: \"a-b\"\n",
			want: "unrecognized case list item",
		},
		{
			name: "bare list item",
			yaml: "cases:\n  - id: \"a-b\"\n    title: \"T\"\n  -\n",
			want: "unrecognized case list item",
		},
		{
			name: "empty double-quoted id",
			yaml: "cases:\n  - id: \"\"\n    title: \"T\"\n",
			want: "empty case id",
		},
		{
			name: "id key with no value",
			yaml: "cases:\n  - id:\n    title: \"T\"\n",
			want: "empty case id",
		},
		{
			// Bounded to the case item: the next "- id:" sits at the case
			// indent, so the quote demonstrably never closed. Consuming to the
			// next quote later in the file would swallow whole cases into this
			// one value.
			name: "unterminated quote bounded by the next case",
			yaml: "cases:\n  - id: \"a-b\n  - id: \"c-d\"\n    title: \"U\"\n",
			want: "leaves the case item before the closing quote",
		},
		{
			name: "unterminated quote bounded by a top-level key",
			yaml: "cases:\n  - id: \"a-b\"\n    title: \"unclosed\n usage_guidance:\n",
			want: "leaves the case item before the closing quote",
		},
		{
			name: "unterminated quote at end of file",
			yaml: "cases:\n  - id: \"a-b\"\n    title: \"unclosed\n",
			want: "unterminated double-quoted scalar",
		},
		{
			name: "unterminated single quote at end of file",
			yaml: "cases:\n  - id: \"a-b\"\n    title: 'unclosed\n",
			want: "unterminated single-quoted scalar",
		},
		{
			name: "unsupported escape",
			yaml: "cases:\n  - id: \"a\\qb\"\n    title: \"T\"\n",
			want: "unsupported escape",
		},
		{
			name: "malformed unicode escape",
			yaml: "cases:\n  - id: \"a-b\"\n    title: \"bad \\u00zz escape\"\n",
			want: "malformed \\uXXXX escape",
		},
		{
			name: "truncated unicode escape",
			yaml: "cases:\n  - id: \"a-b\"\n    title: \"bad \\u00\"\n",
			want: "malformed \\uXXXX escape",
		},
		{
			// The last silent-corruption path: ParseUint accepts D83D and
			// WriteRune encodes every surrogate as U+FFFD, so this used to
			// return a title the catalog never contained. YAML writes a
			// non-BMP code point as \UXXXXXXXX, which default: already
			// rejects, so no valid catalog reaches this arm.
			name: "lone high surrogate",
			yaml: "cases:\n  - id: \"a-b\"\n    title: \"half an emoji \\ud83d\"\n",
			want: "surrogate code point",
		},
		{
			name: "lone low surrogate",
			yaml: "cases:\n  - id: \"a-b\"\n    title: \"half an emoji \\ude00\"\n",
			want: "surrogate code point",
		},
		{
			// A surrogate pair is not a valid escape sequence in YAML either,
			// and it must not be reassembled here: the parser refuses shapes
			// it does not understand rather than guessing at an encoding.
			name: "surrogate pair in an id",
			yaml: "cases:\n  - id: \"a\\ud83d\\ude00b\"\n    title: \"T\"\n",
			want: "surrogate code point",
		},
		{
			name: "literal block scalar indicator",
			yaml: "cases:\n  - id: |\n      a-b\n    title: \"T\"\n",
			want: "block scalar",
		},
		{
			name: "folded block scalar indicator",
			yaml: "cases:\n  - id: \"a-b\"\n    title: >\n      folded\n",
			want: "block scalar",
		},
		{
			// Not a key, not a comment, not the document-end marker. Reading it
			// as the end of the block would hide every case below it.
			name: "unrecognized column-0 line",
			yaml: "cases:\n  - id: \"a-b\"\n    title: \"T\"\n%TAG !x!\n  - id: \"c-d\"\n",
			want: "unrecognized column-0 line",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mustFail(t, tt.yaml, tt.want)
		})
	}
}

// The pinned catalog itself must parse cleanly, every case must carry a
// non-empty id and title, and ids must be unique. This is the smoke test the
// crafted shapes above cannot be: it runs against whatever the pin currently
// points at, so a catalog whose shape drifts past the parser fails here rather
// than quietly shrinking the guard's coverage.
func TestParseCatalogCases_PinnedCatalogParsesCleanly(t *testing.T) {
	root := projectRoot()
	path := filepath.Join(root, "..", "conformance", "oauth-sdk-conformance-catalog.yaml")
	if p := os.Getenv("CONFORMANCE_CATALOG_PATH"); p != "" {
		path = p
	} else if p := os.Getenv("AUTHPLANE_CONFORMANCE_CATALOG"); p != "" {
		path = p
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Skipf("catalog not available at %s: %v", path, err)
	}

	cases, err := parseCatalogCases(string(data))
	if err != nil {
		t.Fatalf("parseCatalogCases over the pinned catalog: %v", err)
	}
	if len(cases) == 0 {
		t.Fatal("parsed 0 cases from the pinned catalog")
	}

	seen := make(map[string]int, len(cases))
	for i, c := range cases {
		if strings.TrimSpace(c.ID) == "" {
			t.Errorf("case %d has an empty id", i)
		}
		if strings.TrimSpace(c.Title) == "" {
			t.Errorf("case %d (%q) has an empty title", i, c.ID)
		}
		// An id that still carries a quote or a stray backslash means the
		// scalar grammar mis-read it rather than parsed it.
		if strings.ContainsAny(c.ID, "\"'\\") {
			t.Errorf("case %d id %q carries quoting artifacts; the scalar was not parsed", i, c.ID)
		}
		if prev, dup := seen[c.ID]; dup {
			t.Errorf("duplicate id %q at cases %d and %d", c.ID, prev, i)
		}
		seen[c.ID] = i
	}
}
