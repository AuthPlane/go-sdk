#!/usr/bin/env bash
set -euo pipefail

# Tests for fetch-conformance-catalog.sh.
#
# Every workflow that needs the catalog reads the pin through this one script,
# so a guard that stops holding here stops holding everywhere. An edit that
# drops a guard, mistypes the catalog filename or softens a refusal is still
# valid shell, so shellcheck — the only other gate on it — sees nothing. What
# changes is the diagnosis: an unpinned ref silently tracks a moving target, a
# destination in the working tree is staged as a gitlink or checked out over
# this repo, and a fetch that lands no catalog surfaces much later, in another
# job, as a harness problem. These tests pin each refusal to its own message so
# such an edit fails at PR time.
#
# Nothing here reaches the network. The cases that need a real fetch redirect
# the catalog URL at a local fixture repo through a per-invocation `insteadOf`,
# and GIT_ALLOW_PROTOCOL=file turns a redirect that failed to apply into a hard
# failure rather than a real clone. The ambient git configuration is neutralised
# for the same reason: a developer's own url rewrite must not get to decide what
# these tests exercise.
#
# Run: .github/scripts/fetch-conformance-catalog.test.sh

SCRIPTDIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
FETCH="$SCRIPTDIR/fetch-conformance-catalog.sh"
CATALOG_FILE="oauth-sdk-conformance-catalog.yaml"
CATALOG_URL="https://github.com/AuthPlane/conformance.git"

export GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_SYSTEM=/dev/null

failures=0

# One root that an EXIT trap removes, so a fixture still gets cleaned up when
# `set -e` kills the shell from inside a helper — the moment a leak is least
# welcome. The per-case RETURN traps below do not fire then.
TESTROOT="$(mktemp -d)"
trap 'rm -rf "$TESTROOT"' EXIT

pass() { printf '  ok   %s\n' "$1"; }
fail() { printf '  FAIL %s\n     %s\n' "$1" "$2"; failures=$((failures + 1)); }

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

# Builds a one-commit repo at $1 and prints its commit SHA. With $2 == "catalog"
# the commit carries the catalog file; otherwise it carries an unrelated file,
# which is the tree the missing-catalog refusal exists for.
make_repo() {
  local dir="$1" contents="$2"
  git init -q -b main "$dir"
  # The script fetches a bare commit SHA rather than a ref, which the default
  # upload-pack policy refuses.
  git -C "$dir" config uploadpack.allowAnySHA1InWant true
  if [[ "$contents" == "catalog" ]]; then
    printf 'cases: []\n' > "$dir/$CATALOG_FILE"
  else
    printf 'this commit carries no catalog\n' > "$dir/README.md"
  fi
  git -C "$dir" add -A
  git -C "$dir" -c user.name=fixture -c user.email=fixture@example.invalid \
    -c commit.gpgsign=false commit -q -m "fixture"
  git -C "$dir" rev-parse HEAD
}

WITH_CATALOG="$TESTROOT/fixture-with-catalog"
WITHOUT_CATALOG="$TESTROOT/fixture-without-catalog"
WITH_CATALOG_SHA="$(make_repo "$WITH_CATALOG" catalog)"
WITHOUT_CATALOG_SHA="$(make_repo "$WITHOUT_CATALOG" bare)"

# Lays out the workspace and runner temp the script requires under $1, pinned to
# $2. The literal "none" writes no pin file at all.
make_case() {
  local root="$1" ref="$2"
  mkdir -p "$root/ws" "$root/tmp"
  [[ "$ref" == "none" ]] || printf '%s\n' "$ref" > "$root/ws/.conformance-catalog-ref"
}

# Runs the script against the workspace and runner temp under $1, with the
# catalog URL redirected at the fixture repo $2. Any further arguments are
# passed through as VAR=VALUE environment entries; they come after the ones set
# here, so a case that needs a different GITHUB_WORKSPACE can say so. The call
# is made from inside the workspace, which is where a `run:` step starts, so a
# relative destination resolves as it would on a runner. Captures stdout and
# stderr together into $out and the exit status into $rc — both declared `local`
# by the caller.
run_fetch() {
  local root="$1" fixture="$2"
  shift 2
  rc=0
  out="$(cd "$root/ws" && env \
    GITHUB_WORKSPACE="$root/ws" \
    RUNNER_TEMP="$root/tmp" \
    GIT_ALLOW_PROTOCOL=file \
    GIT_CONFIG_COUNT=1 \
    GIT_CONFIG_KEY_0="url.file://$fixture.insteadOf" \
    GIT_CONFIG_VALUE_0="$CATALOG_URL" \
    "$@" \
    "$FETCH" 2>&1)" || rc=$?
}

# ---------------------------------------------------------------------------
# fetch-conformance-catalog.sh
# ---------------------------------------------------------------------------

# --- the positive control ------------------------------------------------------
# Without this every refusal below could be satisfied by a script that fails
# unconditionally, and the suite would look green while guarding nothing.
t_catalog_present_succeeds() {
  local root; root="$(mktemp -d "$TESTROOT/XXXXXX")"; trap 'rm -rf "$root"' RETURN
  make_case "$root" "$WITH_CATALOG_SHA"

  local out rc
  run_fetch "$root" "$WITH_CATALOG"
  if [[ "$rc" -ne 0 ]]; then
    fail "a fetch that lands the catalog succeeds" "exit $rc, want 0: ${out##*$'\n'}"
  elif [[ ! -f "$root/tmp/conformance/$CATALOG_FILE" ]]; then
    fail "a fetch that lands the catalog succeeds" "no catalog under the default destination"
  elif ! grep -q "checked out at $WITH_CATALOG_SHA in $root/tmp/conformance" <<<"$out"; then
    fail "a fetch that lands the catalog succeeds" "it did not report the ref and destination: ${out##*$'\n'}"
  else
    pass "a fetch that lands the catalog exits 0, reporting the ref and destination"
  fi
}

# --- the destination override --------------------------------------------------
# The drift workflow holds the pinned catalog and the catalog tip side by side in
# one job, so it cannot let both land on the default path. An override that
# stopped being honoured would put the pinned checkout on top of the tip clone,
# where the two then compare equal and the check reports green forever.
t_destination_override_is_honoured() {
  local root; root="$(mktemp -d "$TESTROOT/XXXXXX")"; trap 'rm -rf "$root"' RETURN
  make_case "$root" "$WITH_CATALOG_SHA"

  local out rc
  run_fetch "$root" "$WITH_CATALOG" CONFORMANCE_CATALOG_DEST="$root/elsewhere"
  if [[ "$rc" -ne 0 ]]; then
    fail "CONFORMANCE_CATALOG_DEST is honoured" "exit $rc, want 0: ${out##*$'\n'}"
  elif [[ ! -f "$root/elsewhere/$CATALOG_FILE" ]]; then
    fail "CONFORMANCE_CATALOG_DEST is honoured" "no catalog under the override"
  elif [[ -e "$root/tmp/conformance" ]]; then
    fail "CONFORMANCE_CATALOG_DEST is honoured" "it wrote the default destination as well"
  elif ! grep -q "checked out at $WITH_CATALOG_SHA in $root/elsewhere" <<<"$out"; then
    fail "CONFORMANCE_CATALOG_DEST is honoured" "it did not report the override: ${out##*$'\n'}"
  else
    pass "CONFORMANCE_CATALOG_DEST moves the checkout and nothing lands on the default path"
  fi
}

# --- a destination that is not an absolute path --------------------------------
# A relative destination resolves against the caller's working directory, which
# for a `run:` step is $GITHUB_WORKSPACE, so the clone lands in the tree and
# `git add -A` in the release commit stages it as a 160000 gitlink — all of it
# at exit 0. The refusal has to echo the value, because what the workflow author
# reads in the log is a path that looks nothing like where the clone went.
t_relative_destination_fails() {
  local root; root="$(mktemp -d "$TESTROOT/XXXXXX")"; trap 'rm -rf "$root"' RETURN
  make_case "$root" "$WITH_CATALOG_SHA"

  local out rc
  run_fetch "$root" "$WITH_CATALOG" CONFORMANCE_CATALOG_DEST=relative/path
  if [[ "$rc" -ne 1 ]]; then
    fail "a relative destination is rejected" "exit $rc, want 1: ${out##*$'\n'}"
  elif ! grep -qF "must be an absolute path, got 'relative/path'" <<<"$out"; then
    fail "a relative destination is rejected" "it did not name the rule and echo the value: ${out##*$'\n'}"
  elif [[ -e "$root/ws/relative" ]]; then
    fail "a relative destination is rejected" "it resolved it against the workspace and cloned into the tree"
  elif [[ -e "$root/tmp/conformance" ]]; then
    fail "a relative destination is rejected" "it initialised the default destination before refusing"
  else
    pass "a relative destination is rejected, naming the rule, before anything is initialised"
  fi
}

# --- a destination inside the workspace ----------------------------------------
# The same out-of-tree rule, reached with an absolute path. A destination under
# the workspace puts the clone in the tree directly; a destination equal to the
# workspace root is worse, because the checkout then replaces this repo's own
# working tree with the catalog and still exits 0. The third pair pins the
# trailing-slash strip: a workspace written with one must still match, or the
# prefix test looks for a doubled slash and lets every destination through.
t_in_workspace_destination_fails() {
  local root; root="$(mktemp -d "$TESTROOT/XXXXXX")"; trap 'rm -rf "$root"' RETURN
  make_case "$root" "$WITH_CATALOG_SHA"

  # Cases are labelled by the workspace-relative tail of each path: the roots
  # are mktemp names, and the trailing slash is the whole point of the third.
  local spec dest ws label out rc
  for spec in "$root/ws/inside|$root/ws" "$root/ws|$root/ws" "$root/ws/inside|$root/ws/"; do
    dest="${spec%%|*}"
    ws="${spec##*|}"
    label="'${dest#"$root/"}' under GITHUB_WORKSPACE '${ws#"$root/"}'"
    rm -rf "${root:?}/tmp/conformance" "$root/ws/inside" "$root/ws/.git"
    run_fetch "$root" "$WITH_CATALOG" \
      CONFORMANCE_CATALOG_DEST="$dest" GITHUB_WORKSPACE="$ws"
    if [[ "$rc" -ne 1 ]]; then
      fail "$label is rejected" "exit $rc, want 1: ${out##*$'\n'}"
    elif ! grep -qF "must be outside \$GITHUB_WORKSPACE (${ws%/}), got '$dest'" <<<"$out"; then
      fail "$label is rejected" "it did not name the workspace and echo the value: ${out##*$'\n'}"
    elif [[ -e "$dest/.git" ]]; then
      fail "$label is rejected" "it initialised a repo in the working tree"
    elif [[ -e "$root/tmp/conformance" ]]; then
      fail "$label is rejected" "it initialised the default destination before refusing"
    else
      pass "$label is rejected as inside the workspace, before anything is initialised"
    fi
  done
}

# --- a fetch that produces no catalog ------------------------------------------
# The branch this suite is here for. Downstream the miss surfaces as a failed
# alignment assertion, which reports a harness problem rather than the truth:
# the fetch succeeded and the catalog is not in the tree it produced.
t_fetch_without_catalog_fails() {
  local root; root="$(mktemp -d "$TESTROOT/XXXXXX")"; trap 'rm -rf "$root"' RETURN
  make_case "$root" "$WITHOUT_CATALOG_SHA"

  local out rc
  run_fetch "$root" "$WITHOUT_CATALOG"
  if [[ "$rc" -ne 1 ]]; then
    fail "a fetch that lands no catalog fails" "exit $rc, want 1: ${out##*$'\n'}"
  elif ! grep -q "$CATALOG_FILE is not in the catalog at $WITHOUT_CATALOG_SHA" <<<"$out"; then
    fail "a fetch that lands no catalog fails" "it did not name the file and the ref: ${out##*$'\n'}"
  elif ! grep -q "produced no catalog in $root/tmp/conformance" <<<"$out"; then
    fail "a fetch that lands no catalog fails" "it did not name the destination: ${out##*$'\n'}"
  else
    pass "a fetch that lands no catalog fails, naming the file, the ref and the destination"
  fi
}

# Same miss, reached through the override, because that is the call site where
# "which fetch failed" is a real question: one job runs the script twice.
t_fetch_without_catalog_fails_under_override() {
  local root; root="$(mktemp -d "$TESTROOT/XXXXXX")"; trap 'rm -rf "$root"' RETURN
  make_case "$root" "$WITHOUT_CATALOG_SHA"

  local out rc
  run_fetch "$root" "$WITHOUT_CATALOG" CONFORMANCE_CATALOG_DEST="$root/elsewhere"
  if [[ "$rc" -ne 1 ]]; then
    fail "the miss is reported against the override" "exit $rc, want 1: ${out##*$'\n'}"
  elif ! grep -q "produced no catalog in $root/elsewhere" <<<"$out"; then
    fail "the miss is reported against the override" "it named the wrong destination: ${out##*$'\n'}"
  else
    pass "the miss names the overridden destination, not the default one"
  fi
}

# --- the pin file is not there -------------------------------------------------
# The workspace is the repo checkout, so an absent pin file means the pin was
# deleted rather than left unset — the catalog revision is then whatever the
# default branch happens to hold, which is the state this script exists to make
# impossible.
t_missing_ref_file_fails() {
  local root; root="$(mktemp -d "$TESTROOT/XXXXXX")"; trap 'rm -rf "$root"' RETURN
  make_case "$root" none

  local out rc
  run_fetch "$root" "$WITH_CATALOG"
  if [[ "$rc" -ne 1 ]]; then
    fail "a missing pin file fails" "exit $rc, want 1: ${out##*$'\n'}"
  elif ! grep -q "$root/ws/.conformance-catalog-ref is missing" <<<"$out"; then
    fail "a missing pin file fails" "it did not name the path: ${out##*$'\n'}"
  elif ! grep -q "conformance catalog revision is unpinned" <<<"$out"; then
    fail "a missing pin file fails" "wrong diagnosis: ${out##*$'\n'}"
  elif [[ -e "$root/tmp/conformance" ]]; then
    fail "a missing pin file fails" "it initialised a destination before refusing"
  else
    pass "a missing pin file fails before anything is fetched, naming the path"
  fi
}

# --- a pin that is not a full commit SHA ---------------------------------------
# A branch or tag name fetches fine and tracks a moving target, so the guard has
# to run before the fetch, not after it: the failure it prevents is a green run,
# not a red one.
t_unpinned_ref_fails_before_the_fetch() {
  local root; root="$(mktemp -d "$TESTROOT/XXXXXX")"; trap 'rm -rf "$root"' RETURN

  local ref out rc
  for ref in main v1.2.3 "${WITH_CATALOG_SHA:0:7}" "${WITH_CATALOG_SHA^^}"; do
    rm -rf "${root:?}"/*
    make_case "$root" "$ref"
    run_fetch "$root" "$WITH_CATALOG"
    if [[ "$rc" -ne 1 ]]; then
      fail "'$ref' is rejected as a pin" "exit $rc, want 1: ${out##*$'\n'}"
    elif ! grep -q "must be a 40-hex commit SHA, got '$ref'" <<<"$out"; then
      fail "'$ref' is rejected as a pin" "it did not echo the rejected ref: ${out##*$'\n'}"
    elif [[ -e "$root/tmp/conformance" ]]; then
      fail "'$ref' is rejected as a pin" "it initialised a destination, so the guard ran after the fetch"
    else
      pass "'$ref' is rejected before anything is fetched"
    fi
  done
}

# --- a pin that is well formed but not there -----------------------------------
# The refusal the missing-catalog branch has to stay distinguishable from: a ref
# the catalog repo no longer serves is a different problem from a ref it serves
# without a catalog in it.
t_unreachable_ref_fails() {
  local root; root="$(mktemp -d "$TESTROOT/XXXXXX")"; trap 'rm -rf "$root"' RETURN
  make_case "$root" "0000000000000000000000000000000000000000"

  local out rc
  run_fetch "$root" "$WITH_CATALOG"
  if [[ "$rc" -ne 1 ]]; then
    fail "an unreachable pin fails" "exit $rc, want 1: ${out##*$'\n'}"
  elif ! grep -q "0000000000000000000000000000000000000000 is unreachable" <<<"$out"; then
    fail "an unreachable pin fails" "wrong diagnosis: ${out##*$'\n'}"
  elif grep -q "produced no catalog" <<<"$out"; then
    fail "an unreachable pin fails" "it reported the miss as a missing catalog instead"
  else
    pass "an unreachable pin fails as unreachable, not as a missing catalog"
  fi
}

echo "fetch-conformance-catalog.sh — pin, fetch and catalog checks"
t_catalog_present_succeeds
t_destination_override_is_honoured
t_relative_destination_fails
t_in_workspace_destination_fails
t_fetch_without_catalog_fails
t_fetch_without_catalog_fails_under_override
t_missing_ref_file_fails
t_unpinned_ref_fails_before_the_fetch
t_unreachable_ref_fails

if [[ "$failures" -gt 0 ]]; then
  echo "$failures failing"
  exit 1
fi
echo "all passing"
