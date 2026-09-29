package conformancetests

// Catalog parsing for the drift guard.
//
// The guard this feeds is a contract, not a convenience: verifyCatalogAlignment
// asserts that every case in the shared catalog has a test here, and the report
// marks anything unregistered as "not_run". Both read the parser's output, so a
// case the parser fails to see is a case the guard cannot ask about — and the
// guard stays green while it under-checks. That is strictly worse than a red
// run: the report says "passed" for a catalog the suite never fully compared
// itself against.
//
// So this file has one rule, and every error below is an instance of it: a
// catalog shape the parser does not understand must fail the run, never be
// skipped. A single regex over the file cannot honor that rule — it matches
// what it matches and is silent about the rest, which is how a case with an
// unquoted id, a single-quoted id, an id carrying an escaped quote, or a
// trailing comment could sit in the catalog and never be asked for. The
// line-oriented state machine here reads the same shapes a YAML parser would
// and refuses the ones it cannot: an unparseable list item, a quoted scalar
// that never closes, an unknown escape, a block scalar indicator, an
// unrecognized column-0 line.
//
// This file deliberately contains no Test functions — it is the parser; the
// crafted shapes that exercise it live in catalog_parser_shapes_test.go.

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// conformanceCase is one catalog entry.
//
// The title is carried even though the alignment guard keys on ids alone. It is
// what makes the id trustworthy: both go through the same scalar grammar, so a
// quoting style the parser gets wrong shows up in a title long before it
// silently mangles an id, and the report can name a case rather than only
// identify it.
type conformanceCase struct {
	ID    string
	Title string
}

var (
	// A case list item's "- id:" key. The value is handed to parseScalar
	// rather than captured by this regex, so an id accepts exactly the
	// quoting a title does.
	reCaseIDKey = regexp.MustCompile(`^(\s*)-\s*id:\s*(.*)$`)

	// A top-level key (e.g. "usage_guidance:"), which is the only thing
	// besides the document-end marker that ends the cases block.
	reTopLevelKey = regexp.MustCompile(`^[A-Za-z_][\w-]*:`)

	// The start of any list item, so a case item whose first key is not "id"
	// is detected rather than folded into the previous case.
	reListItem = regexp.MustCompile(`^(\s*)-(\s|$)`)

	// A case's "title:" key. As with the id, the value needs the scalar
	// grammar, not a regex.
	reTitleKey = regexp.MustCompile(`^(\s*)title:\s*(.*)$`)
)

// parseCatalogCases parses the "cases:" block of the conformance catalog into
// id/title pairs, in catalog order.
//
// Every failure is a shape the parser cannot make sense of. Returning a partial
// list instead would hand the alignment guard a catalog with holes in it and
// nothing to indicate they were there.
func parseCatalogCases(text string) ([]conformanceCase, error) {
	lines := strings.Split(text, "\n")

	var cases []conformanceCase
	var currentID, currentTitle string
	inCases := false
	// -1 means "not yet established". The first list item after "cases:"
	// fixes the case-item indent; the first field line of a case fixes that
	// case's field indent. Both are read off the file rather than assumed to
	// be two spaces, so the parser stays correct for any valid indent width.
	caseIndent, fieldIndent := -1, -1

	flush := func() {
		if strings.TrimSpace(currentID) != "" {
			title := currentTitle
			if strings.TrimSpace(title) == "" {
				// The guard keys on ids, so a case whose title is missing or
				// empty must stay visible to it. Falling back to the id keeps
				// the case in the list instead of dropping it for want of a
				// field the guard never reads.
				title = currentID
			}
			cases = append(cases, conformanceCase{ID: currentID, Title: title})
		}
		currentID, currentTitle = "", ""
	}

	for i := 0; i < len(lines); i++ {
		line := strings.TrimRight(lines[i], "\r")

		if !inCases {
			if strings.TrimSpace(line) == "cases:" {
				inCases = true
			}
			continue
		}

		if strings.TrimSpace(line) == "" {
			continue
		}

		// A full-line comment carries no content at any indent. A column-0
		// comment in particular is not a top-level key and must not end the
		// cases block — splitting on the first unindented line would drop
		// every case after it.
		if strings.HasPrefix(strings.TrimLeft(line, " \t"), "#") {
			continue
		}

		if line[0] != ' ' && line[0] != '\t' && line[0] != '-' {
			// Only a top-level key or the document-end marker ends the block.
			// Anything else at column 0 is a shape this parser does not
			// understand, and reading it as the end of the block would
			// silently drop every remaining case.
			if reTopLevelKey.MatchString(line) || strings.TrimRight(line, " \t") == "..." {
				break
			}
			return nil, fmt.Errorf("unrecognized column-0 line at line %d inside the cases block: %q; treating it as the end of the block would hide every remaining case from the catalog-alignment guard", i+1, strings.TrimSpace(line))
		}

		if m := reListItem.FindStringSubmatch(line); m != nil {
			indent := len(m[1])
			if caseIndent < 0 {
				caseIndent = indent
			}
			// Deeper items belong to a nested list (standard_refs, notes,
			// prohibited_mechanisms, ...), not to a new case.
			if indent > caseIndent {
				continue
			}

			idm := reCaseIDKey.FindStringSubmatch(line)
			if idm == nil {
				return nil, fmt.Errorf("unrecognized case list item at line %d: %q; every catalog case starts with `- id:`, and skipping this item would hide it from the catalog-alignment guard", i+1, strings.TrimSpace(line))
			}

			flush()
			fieldIndent = -1
			id, err := parseScalar(lines, &i, strings.TrimSpace(idm[2]), caseIndent)
			if err != nil {
				return nil, err
			}
			if strings.TrimSpace(id) == "" {
				return nil, fmt.Errorf("empty case id at line %d; a case without an id is invisible to the catalog-alignment guard", i+1)
			}
			currentID = id
			continue
		}

		lineIndent := len(line) - len(strings.TrimLeft(line, " \t"))
		if currentID != "" && fieldIndent < 0 && caseIndent >= 0 && lineIndent > caseIndent {
			fieldIndent = lineIndent
		}

		// Only a title at the case's own field indent belongs to the case. An
		// identically named key nested deeper — inside setup:, or in a
		// variants: entry — does not, and taking it would attach the wrong
		// title to the case.
		if tm := reTitleKey.FindStringSubmatch(line); tm != nil &&
			currentID != "" && currentTitle == "" && len(tm[1]) == fieldIndent {
			title, err := parseScalar(lines, &i, strings.TrimSpace(tm[2]), caseIndent)
			if err != nil {
				return nil, err
			}
			currentTitle = title
		}
	}

	flush()
	return cases, nil
}

// parseScalar parses a YAML flow scalar — double-quoted, single-quoted or plain
// — beginning at rest, consuming the continuation lines of a wrapped quoted
// scalar and advancing i past them.
//
// It covers the styles the catalog actually uses. Double-quoted values may
// carry apostrophes, the JSON escape set plus "\ " and "\uXXXX", and — because
// the catalog emitter writes every long scalar that way — wrap with an escaped
// line break followed by an escaped leading space on the continuation line.
// Single-quoted values escape an apostrophe by doubling it. A plain scalar
// loses its inline comment.
//
// Everything else is an error rather than a degraded value: an escape outside
// that set, a block scalar indicator (the emitter pins double-quoted style, so
// "|" and ">" never legitimately arrive), a quoted scalar that never closes,
// and a continuation line that leaves the case item — an indent at or below
// caseIndent, which also covers the next "- id:" — instead of swallowing every
// line up to the next quote in the file.
func parseScalar(lines []string, i *int, rest string, caseIndent int) (string, error) {
	if rest == "" {
		return "", nil
	}

	if rest[0] == '|' || rest[0] == '>' {
		return "", fmt.Errorf("block scalar (%q) at line %d is not supported; returning the indicator as the value would silently corrupt it, and the catalog emitter pins double-quoted style", rest, *i+1)
	}

	if rest[0] != '"' && rest[0] != '\'' {
		// Plain scalar. A "#" at the start of the value, or preceded by
		// whitespace, begins a comment (RFC-independent YAML rule) and is not
		// part of the value.
		for p := 0; p < len(rest); p++ {
			if rest[p] == '#' && (p == 0 || rest[p-1] == ' ' || rest[p-1] == '\t') {
				return strings.TrimRight(rest[:p], " \t"), nil
			}
		}
		return rest, nil
	}

	quote := rest[0]
	var value strings.Builder
	startLine := *i + 1
	chunk := rest[1:]

	for {
		closed := false
		joinNextWithoutSpace := false

		for p := 0; p < len(chunk); p++ {
			c := chunk[p]

			if quote == '"' && c == '\\' {
				if p == len(chunk)-1 {
					// A trailing backslash is an escaped line break: the
					// continuation line joins with no folded space.
					joinNextWithoutSpace = true
					break
				}

				switch esc := chunk[p+1]; esc {
				case '"', '\\', '/', ' ':
					value.WriteByte(esc)
				case 'n':
					value.WriteByte('\n')
				case 't':
					value.WriteByte('\t')
				case 'r':
					value.WriteByte('\r')
				case '0':
					value.WriteByte(0)
				case 'u':
					if p+6 > len(chunk) {
						return "", fmt.Errorf("malformed \\uXXXX escape in double-quoted scalar at line %d: %q", *i+1, chunk[p:])
					}
					cp, err := strconv.ParseUint(chunk[p+2:p+6], 16, 32)
					if err != nil {
						return "", fmt.Errorf("malformed \\uXXXX escape in double-quoted scalar at line %d: %q", *i+1, chunk[p:p+6])
					}
					// A lone surrogate is the last silent-corruption path left
					// in this parser: ParseUint returns 0xD83D happily and
					// strings.Builder.WriteRune encodes every surrogate as
					// U+FFFD, so the value would come back with a replacement
					// character the catalog never contained — the exact silent
					// substitution this file exists to refuse. YAML 1.2 has no
					// surrogate-pair escape either (a non-BMP code point is
					// written \UXXXXXXXX, which this switch already rejects
					// through default:), so there is no valid catalog in which
					// D800-DFFF appears here.
					if cp >= 0xD800 && cp <= 0xDFFF {
						return "", fmt.Errorf("malformed \\uXXXX escape in double-quoted scalar at line %d: %q is a surrogate code point, which has no encoding and would be substituted with U+FFFD", *i+1, chunk[p:p+6])
					}
					value.WriteRune(rune(cp))
					// The loop's own p++ accounts for the sixth byte.
					p += 4
				default:
					return "", fmt.Errorf("unsupported escape %q in double-quoted scalar at line %d; passing the character through unescaped would silently corrupt the value", `\`+string(esc), *i+1)
				}

				// Step over the escaped byte; the loop's p++ does the rest.
				p++
				continue
			}

			if c == quote {
				if quote == '\'' && p < len(chunk)-1 && chunk[p+1] == '\'' {
					// Single-quoted style escapes an apostrophe by doubling it.
					value.WriteByte('\'')
					p++
					continue
				}
				closed = true
				break
			}

			value.WriteByte(c)
		}

		if closed {
			return value.String(), nil
		}

		if *i+1 >= len(lines) {
			return "", fmt.Errorf("unterminated %s-quoted scalar starting at line %d; refusing to return a truncated value", quoteName(quote), startLine)
		}

		// A continuation line must stay inside the case item. An indent at or
		// below the case-item indent means the quote never closed — the next
		// "- id:" is such a line — and consuming lines until the next quote
		// somewhere later in the file would swallow whole cases into this
		// value, which is exactly the silent drop this parser exists to
		// prevent.
		next := strings.TrimRight(lines[*i+1], "\r")
		if len(next)-len(strings.TrimLeft(next, " \t")) <= caseIndent {
			return "", fmt.Errorf("unterminated %s-quoted scalar starting at line %d: line %d leaves the case item before the closing quote; refusing to return a truncated value", quoteName(quote), startLine, *i+2)
		}

		if !joinNextWithoutSpace {
			// An unescaped line break inside a quoted scalar folds to a space.
			value.WriteByte(' ')
		}

		*i++
		chunk = strings.TrimLeft(strings.TrimRight(lines[*i], "\r"), " \t")
	}
}

func quoteName(quote byte) string {
	if quote == '"' {
		return "double"
	}
	return "single"
}
