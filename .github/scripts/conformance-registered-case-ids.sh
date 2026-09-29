#!/usr/bin/env bash
#
# Print the conformance case ids THIS SDK registers, one per line.
#
# This is the repo-specific half of the case-body drift check: the id source
# depends on how this repo's harness records registrations, so it lives here and
# conformance-case-body-drift.sh stays generic.
#
# For this repo the ids come out of conformance-report.json, which the
# conformance suite writes from TestMain. That is the harness's own record of
# what registered, so it cannot disagree with what the suite actually did — the
# reason for reading the report rather than grepping Case(t, "...") calls out of
# the test sources, which would be a second, weaker id extractor that reports
# what it matched and stays silent about what it missed.
#
# The report lists one entry per CATALOG case, so presence in it is not
# registration. `nodeid` is: Case() sets it at registration time, and the
# placeholder entries the report synthesizes for uncovered catalog cases leave
# it empty. Reading `nodeid` rather than `status` matters — a registered case
# whose test failed or skipped is still registered, and still needs its body
# watched, but its status is not "passed".
#
# Requires the suite to have run, so the report on disk belongs to this commit.
#
# Inputs (environment):
#   CONFORMANCE_REPORT  path to conformance-report.json
#                       (default: $GITHUB_WORKSPACE/conformance-report.json)
#
# Exit status:
#   0  ids printed on stdout
#   1  the report is missing, unreadable, or holds no registered case

set -euo pipefail

REPORT="${CONFORMANCE_REPORT:-${GITHUB_WORKSPACE:-.}/conformance-report.json}"

fail() {
  echo "::error::$1" >&2
  exit 1
}

if ! command -v jq > /dev/null 2>&1; then
  fail "registered case ids: jq is not available, so the conformance report cannot be read."
fi

if [[ ! -f "$REPORT" ]]; then
  fail "registered case ids: '$REPORT' does not exist. The conformance suite writes it from TestMain, so either the suite did not run or it failed before the report was written."
fi

if ! jq -e . "$REPORT" > /dev/null 2>&1; then
  fail "registered case ids: '$REPORT' is not valid JSON."
fi

if ! jq -e '(.cases | type) == "array" and (.cases | length) > 0' "$REPORT" > /dev/null 2>&1; then
  fail "registered case ids: '$REPORT' has no non-empty .cases array."
fi

# An entry with a case_id that is not a string, or empty, would silently drop
# out of the filter below and take a real registration with it.
if ! jq -e 'all(.cases[]; (.case_id | type) == "string" and (.case_id | length) > 0)' "$REPORT" > /dev/null 2>&1; then
  fail "registered case ids: '$REPORT' holds a case entry with a missing or non-string case_id."
fi

ids="$(jq -r '.cases[] | select((.nodeid // "") != "") | .case_id' "$REPORT")"

if [[ -z "$ids" ]]; then
  fail "registered case ids: '$REPORT' records no case with a nodeid, so no conformance marker registered. Any check restricted to this list would be vacuously green."
fi

printf '%s\n' "$ids"
