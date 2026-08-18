#!/usr/bin/env bash
set -euo pipefail

# Tests for backport-fixes.sh --from ref resolution.
#
# The script has no other test, and the case it regressed on is not one a reader
# would guess: --from accepts a branch OR a tag, and only the branch form has a
# remote-tracking ref. After a release, release.yml deletes the release branch,
# so the tag is the only ref naming those commits — the tag form is the one
# backport-fixes.yml's input description and release.yml's job summary both tell
# you to use.
#
# Each case builds a throwaway origin + clone in a temp dir, so nothing here
# touches the real repository or the network.
#
# Run: scripts/backport-fixes.test.sh

# Pin out the ambient git config, so "nothing here touches the real repository"
# is enforced rather than asserted. make_fixture sets user.* per-repo but
# nothing else, and a global `commit.gpgsign = true` — common on developer
# machines — made the fixture die with `error: cannot run gpg` mid-suite: no
# test name, no failure count, and a leaked temp dir. This also pins out
# core.hooksPath, init.templateDir and fetch.prune.
#
# GIT_CONFIG_NOSYSTEM, not GIT_CONFIG_SYSTEM=/dev/null: the latter only redirects
# the one path git calls "the" system file, and Apple Git reads a second one that
# it does not cover, so the isolation was silently partial on the platform half
# this suite runs on:
#
#   $ GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_SYSTEM=/dev/null \
#       /usr/bin/git config --show-origin --list
#   file:/Applications/Xcode.app/.../git-core/gitconfig  credential.helper=osxkeychain
#   file:/Applications/Xcode.app/.../git-core/gitconfig  init.defaultbranch=main
#
#   $ GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_NOSYSTEM=1 /usr/bin/git config --list
#   (nothing)
#
# GIT_CONFIG_GLOBAL has no such spelling and is simply ignored before git 2.32,
# which would put the global file back in scope with no sign that it had — the
# failure mode being a suite that passes for the wrong reason on the one machine
# whose config breaks it. Assert the version instead of documenting it.
export GIT_CONFIG_GLOBAL=/dev/null
export GIT_CONFIG_NOSYSTEM=1

git_version="$(git --version | awk '{print $3}')"
git_major="${git_version%%.*}"
git_rest="${git_version#*.}"
git_minor="${git_rest%%.*}"
if [[ "$git_major" -lt 2 || ( "$git_major" -eq 2 && "$git_minor" -lt 32 ) ]]; then
  echo "error: these tests need git >= 2.32 for GIT_CONFIG_GLOBAL; found $git_version" >&2
  echo "       older git ignores it and the suite would read your real ~/.gitconfig" >&2
  exit 1
fi

SCRIPT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/backport-fixes.sh"
failures=0

# Every fixture is created under one root that an EXIT trap removes. The
# per-case `trap ... RETURN` below still cleans up as it goes, but it does not
# fire when `set -e` kills the shell from inside make_fixture — which is exactly
# when a leak is least welcome.
TESTROOT="$(mktemp -d)"
trap 'rm -rf "$TESTROOT"' EXIT

pass() { printf '  ok   %s\n' "$1"; }
fail() { printf '  FAIL %s\n     %s\n' "$1" "$2"; failures=$((failures + 1)); }

# Builds: origin with `main`, a v1.0.0 tag, and one commit after the tag that is
# only reachable from the tag's branch — the shape of a fix landed on a release
# branch at step 3 of the release flow.
make_fixture() {
  local root="$1"
  # -b main explicitly: the default branch name comes from init.defaultBranch,
  # which differs between a developer machine and a CI runner. Without it the
  # fixture builds `master` somewhere and every checkout of `main` fails.
  git init -q -b main "$root/origin"
  git -C "$root/origin" config user.email t@example.com
  git -C "$root/origin" config user.name "Test"
  echo base > "$root/origin/f.txt"
  git -C "$root/origin" add -A
  git -C "$root/origin" commit -qm "base"

  # Clone before the tag exists. A clone made afterwards fetches every tag, which
  # leaves refs/tags/v1.0.0 populated locally and hides whether the script's own
  # fetch materialises it — the exact blind spot that let a broken resolver pass.
  # The real scenario is a maintainer who last fetched before the release.
  git clone -q "$root/origin" "$root/clone"

  git -C "$root/origin" checkout -q -b release/v1.0.0
  echo fix > "$root/origin/f.txt"
  git -C "$root/origin" commit -qam "fix: something landed on the release branch"
  # Annotated, matching release.yml's `git tag -a`. A lightweight tag resolves
  # the same way here, but the fixture should produce what the flow it models
  # produces.
  git -C "$root/origin" tag -a v1.0.0 -m "v1.0.0"
  git -C "$root/origin" checkout -q main
  git -C "$root/clone" config user.email t@example.com
  git -C "$root/clone" config user.name "Test"
}

# --- a branch as --from keeps working -----------------------------------------
t_branch() {
  local root; root="$(mktemp -d "$TESTROOT/XXXXXX")"; trap 'rm -rf "$root"' RETURN
  make_fixture "$root"
  local out
  if out="$(cd "$root/clone" && "$SCRIPT" --from release/v1.0.0 --to main 2>&1)"; then
    if git -C "$root/clone" log --oneline main..HEAD | grep -q "landed on the release branch"; then
      pass "a branch as --from cherry-picks its commits"
    else
      fail "a branch as --from cherry-picks its commits" "branch created but the commit is missing"
    fi
  else
    fail "a branch as --from cherry-picks its commits" "script exited non-zero: ${out##*$'\n'}"
  fi
}

# --- a tag as --from: the regression ------------------------------------------
# Before the fix this exited 1 with "origin/v1.0.0 not found on remote", because
# origin/<name> resolves only against refs/remotes and a tag has none.
t_tag() {
  local root; root="$(mktemp -d "$TESTROOT/XXXXXX")"; trap 'rm -rf "$root"' RETURN
  make_fixture "$root"
  local out
  if out="$(cd "$root/clone" && "$SCRIPT" --from v1.0.0 --to main 2>&1)"; then
    if git -C "$root/clone" log --oneline main..HEAD | grep -q "landed on the release branch"; then
      pass "a tag as --from cherry-picks its commits"
    else
      fail "a tag as --from cherry-picks its commits" "branch created but the commit is missing"
    fi
  else
    fail "a tag as --from cherry-picks its commits" "script exited non-zero: ${out##*$'\n'}"
  fi
}

# --- an unknown ref fails, and leaves nothing behind ---------------------------
# It fails at the resolver, which is what the assertion below pins: the name is
# simply absent from the single `git ls-remote` answer, neither the branch nor
# the tag arm matches, and the script prints its own message before any fetch.
# What matters is the contract: non-zero, and no branch created.
t_unknown() {
  local root; root="$(mktemp -d "$TESTROOT/XXXXXX")"; trap 'rm -rf "$root"' RETURN
  make_fixture "$root"
  local out
  if out="$(cd "$root/clone" && "$SCRIPT" --from does-not-exist --to main 2>&1)"; then
    fail "an unknown --from fails" "script exited zero"
  elif [[ -n "$(git -C "$root/clone" branch --list 'backport/*')" ]]; then
    fail "an unknown --from fails" "it created a backport branch anyway"
  elif ! grep -q "as a branch or a tag" <<<"$out"; then
    fail "an unknown --from fails" "reached the fetch, not the resolver: ${out##*$'\n'}"
  else
    pass "an unknown --from fails at the resolver, creating no branch"
  fi
}

# --- --to is branch-only ------------------------------------------------------
# A tag resolves and `git checkout -b` would even work, but the workflow opens a
# PR with `--base "$TO"`, which needs a branch on the remote. Rejecting it here
# beats failing after the cherry-picks have run.
t_to_rejects_a_tag() {
  local root; root="$(mktemp -d "$TESTROOT/XXXXXX")"; trap 'rm -rf "$root"' RETURN
  make_fixture "$root"
  local out
  if out="$(cd "$root/clone" && "$SCRIPT" --from main --to v1.0.0 2>&1)"; then
    fail "--to rejects a tag" "script exited zero"
  elif grep -q "must be a branch" <<<"$out"; then
    pass "--to rejects a tag, naming the reason"
  else
    fail "--to rejects a tag" "unexpected message: ${out##*$'\n'}"
  fi
}

# --- a force-pushed source branch still backports ------------------------------
# What the `+` on the refspecs is for. Without it the fetch is a non-fast-forward
# rejection, and the resolver would report that as "not found on origin as a
# branch or a tag" — sending the maintainer after a ref that is present and
# current. Amending a release commit during release prep is routine, and the
# bare-name form this replaces handled it (its remote-tracking update came
# through remote.origin.fetch, which is forced), so losing it would be a
# regression against main rather than a pre-existing bug.
t_force_pushed_source() {
  local root; root="$(mktemp -d "$TESTROOT/XXXXXX")"; trap 'rm -rf "$root"' RETURN
  make_fixture "$root"

  # Seed the remote-tracking ref at the pre-amend commit: the state of a
  # maintainer who last fetched before the force-push. Without this the clone
  # has no origin/release/v1.0.0 at all and any fetch is trivially a
  # fast-forward, which is how a missing `+` would go unnoticed.
  git -C "$root/clone" fetch -q origin \
    '+refs/heads/release/v1.0.0:refs/remotes/origin/release/v1.0.0'

  git -C "$root/origin" checkout -q release/v1.0.0
  echo amended > "$root/origin/f.txt"
  git -C "$root/origin" commit -q --amend -am "fix: something landed on the release branch (amended)"
  git -C "$root/origin" checkout -q main

  local out
  if out="$(cd "$root/clone" && "$SCRIPT" --from release/v1.0.0 --to main 2>&1)"; then
    if git -C "$root/clone" log --oneline main..HEAD | grep -q "(amended)"; then
      pass "a force-pushed source branch backports the rewritten commit"
    else
      fail "a force-pushed source branch backports the rewritten commit" \
        "it backported the pre-amend commit"
    fi
  else
    fail "a force-pushed source branch backports the rewritten commit" \
      "script exited non-zero: ${out##*$'\n'}"
  fi
}

# --- a branch wins when a branch and a tag share the name ----------------------
# The arm order in fetch_source_ref decides this and --help now states it, so it
# needs a case: a repo that tags v1.0.0 and later cuts a branch of the same name
# would otherwise silently change which commits get backported.
t_branch_beats_tag() {
  local root; root="$(mktemp -d "$TESTROOT/XXXXXX")"; trap 'rm -rf "$root"' RETURN
  make_fixture "$root"

  # A branch literally named v1.0.0, carrying a commit the tag does not.
  git -C "$root/origin" checkout -q -b v1.0.0 main
  echo from-branch > "$root/origin/f.txt"
  git -C "$root/origin" commit -qam "fix: reached through the branch"
  git -C "$root/origin" checkout -q main

  local out
  if out="$(cd "$root/clone" && "$SCRIPT" --from v1.0.0 --to main 2>&1)"; then
    if git -C "$root/clone" log --oneline main..HEAD | grep -q "reached through the branch"; then
      pass "a branch wins over a tag of the same name"
    else
      fail "a branch wins over a tag of the same name" "it resolved the tag instead"
    fi
  else
    fail "a branch wins over a tag of the same name" "script exited non-zero: ${out##*$'\n'}"
  fi
}

# --- an unreachable remote is not a missing ref --------------------------------
# `git ls-remote --exit-code` answers 2 for "asked, and the remote has no such
# ref" and 128 for "could not ask" — unreachable, or refused. The 128 arm is the
# one that separates them, and without a case a regression in it is invisible:
# the suite passes while a network failure is reported as a missing ref, sending
# the operator after a ref that is fine.
#
# It asserts the absence of the resolver's message rather than the presence of
# git's, because the wording of `fatal: Could not read from remote repository.`
# is git's to change. What must hold is that the script does not add a claim
# about the ref on top of it.
t_unreachable_remote() {
  local root; root="$(mktemp -d "$TESTROOT/XXXXXX")"; trap 'rm -rf "$root"' RETURN
  make_fixture "$root"
  git -C "$root/clone" remote set-url origin /nonexistent

  local out
  if out="$(cd "$root/clone" && "$SCRIPT" --from release/v1.0.0 --to main 2>&1)"; then
    fail "an unreachable remote is not reported as a missing ref" "script exited zero"
  elif grep -q "not found on origin" <<<"$out"; then
    fail "an unreachable remote is not reported as a missing ref" \
         "the network failure was reported as a missing ref"
  elif [[ -n "$(git -C "$root/clone" branch --list 'backport/*')" ]]; then
    fail "an unreachable remote is not reported as a missing ref" "it created a backport branch anyway"
  else
    pass "an unreachable remote is not reported as a missing ref"
  fi
}

# --- a glob as --from is rejected, not resolved --------------------------------
# `git ls-remote` matches its argument as a glob, and `*` is legal in a fetch
# refspec, so `release/*` passed the resolver AND the fetch: origin/release/*
# became FROM_REF, `git cherry` fatalled on a ref that is not a commit, and the
# `|| true` on that line turned the fatal into an empty candidate list. The
# script printed "Nothing to backport" and exited 0 — and backport-fixes.yml
# renders that as a green run with a ::notice::. fromBranch is a free-text
# workflow_dispatch input, so this is typeable.
#
# The exit-0 arm is the assertion that matters: a non-zero with a confusing
# message would be a bad error, but exit 0 is a tooling failure reported to the
# operator as a fact about the refs.
t_glob_from() {
  local root; root="$(mktemp -d "$TESTROOT/XXXXXX")"; trap 'rm -rf "$root"' RETURN
  make_fixture "$root"
  local out
  if out="$(cd "$root/clone" && "$SCRIPT" --from 'release/*' --to main 2>&1)"; then
    fail "a glob as --from is rejected" \
      "script exited zero: ${out##*$'\n'}"
  elif grep -q "Nothing to backport" <<<"$out"; then
    fail "a glob as --from is rejected" "it reported the failure as an empty backport"
  elif [[ -n "$(git -C "$root/clone" branch --list 'backport/*')" ]]; then
    fail "a glob as --from is rejected" "it created a backport branch anyway"
  elif [[ -n "$(git -C "$root/clone" for-each-ref --format='%(refname)' 'refs/tags/*')" ]]; then
    fail "a glob as --from is rejected" "it fetched refs before rejecting the input"
  elif ! grep -q "not a valid git ref name" <<<"$out"; then
    fail "a glob as --from is rejected" "unexpected message: ${out##*$'\n'}"
  else
    pass "a glob as --from is rejected before any network round trip"
  fi
}

# --- --from resolving to a non-commit is caught --------------------------------
# The companion to the glob case, and the reason validating the input is not on
# its own enough: a tag may point at a tree or a blob, `treetag` is a perfectly
# valid ref name, and ls-remote reports it like any other ref. Only a
# `rev-parse --verify <ref>^{commit}` after resolution sees it. Same failure
# shape as the glob without the guard — `git cherry` fatals, and pre-fix the
# `|| true` reported it as "Nothing to backport", exit 0.
t_from_is_not_a_commit() {
  local root; root="$(mktemp -d "$TESTROOT/XXXXXX")"; trap 'rm -rf "$root"' RETURN
  make_fixture "$root"
  local tree
  tree="$(git -C "$root/origin" rev-parse 'main^{tree}')"
  git -C "$root/origin" tag treetag "$tree"

  local out
  if out="$(cd "$root/clone" && "$SCRIPT" --from treetag --to main 2>&1)"; then
    fail "--from that is not a commit is caught" "script exited zero: ${out##*$'\n'}"
  elif grep -q "Nothing to backport" <<<"$out"; then
    fail "--from that is not a commit is caught" "it reported the failure as an empty backport"
  elif ! grep -q "does not name a commit" <<<"$out"; then
    fail "--from that is not a commit is caught" "unexpected message: ${out##*$'\n'}"
  else
    pass "--from that resolves to a non-commit is caught, not counted as zero commits"
  fi
}

# --- a bad --to writes nothing to the user's repo ------------------------------
# Resolution used to fetch the source ref and only then ask about --to, so a
# typo'd --to still left refs/tags/v1.0.0 (or a remote-tracking ref) behind on
# the way to an error. Both names resolve from one ls-remote answer now, and the
# single fetch runs only once both have.
t_bad_to_writes_nothing() {
  local root; root="$(mktemp -d "$TESTROOT/XXXXXX")"; trap 'rm -rf "$root"' RETURN
  make_fixture "$root"
  local out
  if out="$(cd "$root/clone" && "$SCRIPT" --from v1.0.0 --to nope 2>&1)"; then
    fail "a bad --to writes nothing" "script exited zero"
  elif [[ -n "$(git -C "$root/clone" for-each-ref --format='%(refname)' 'refs/tags/*')" ]]; then
    fail "a bad --to writes nothing" "it fetched the tag before rejecting --to"
  elif [[ -n "$(git -C "$root/clone" for-each-ref --format='%(refname)' 'refs/remotes/origin/release/*')" ]]; then
    fail "a bad --to writes nothing" "it fetched the source branch before rejecting --to"
  else
    pass "a bad --to leaves no fetched refs behind"
  fi
}

# --- the branch name --help promises -------------------------------------------
# --help claims `--from v0.6.0` yields `backport/v0.6.0`, which is true only
# because the flattening arm happens to leave a bare tag alone. Neither that nor
# --branch had a case; t_tag asserts the commit landed, not the branch name.
t_branch_naming() {
  local root; root="$(mktemp -d "$TESTROOT/XXXXXX")"; trap 'rm -rf "$root"' RETURN
  make_fixture "$root"

  if ! (cd "$root/clone" && "$SCRIPT" --from v1.0.0 --to main >/dev/null 2>&1); then
    fail "a tag --from names the branch backport/<tag>" "script exited non-zero"
  elif [[ "$(git -C "$root/clone" rev-parse --abbrev-ref HEAD)" != "backport/v1.0.0" ]]; then
    fail "a tag --from names the branch backport/<tag>" \
      "got $(git -C "$root/clone" rev-parse --abbrev-ref HEAD)"
  else
    pass "a tag --from names the branch backport/<tag>"
  fi

  local root2; root2="$(mktemp -d "$TESTROOT/XXXXXX")"; trap 'rm -rf "$root" "$root2"' RETURN
  make_fixture "$root2"
  if ! (cd "$root2/clone" && "$SCRIPT" --from v1.0.0 --to main --branch mine >/dev/null 2>&1); then
    fail "--branch overrides the derived name" "script exited non-zero"
  elif [[ "$(git -C "$root2/clone" rev-parse --abbrev-ref HEAD)" != "mine" ]]; then
    fail "--branch overrides the derived name" \
      "got $(git -C "$root2/clone" rev-parse --abbrev-ref HEAD)"
  else
    pass "--branch overrides the derived name"
  fi
}

# --- both spellings of a flag, and a flag with no value ------------------------
# `--from=v1.0.0` took the unknown-argument arm and exited 2, and a trailing
# `--from` exited 1 with no message at all, because `shift 2` fails under
# `set -e`. --help leads with --from, so neither answer was defensible.
t_arg_forms() {
  local root; root="$(mktemp -d "$TESTROOT/XXXXXX")"; trap 'rm -rf "$root"' RETURN
  make_fixture "$root"

  local out
  if ! out="$(cd "$root/clone" && "$SCRIPT" --from=v1.0.0 --to=main 2>&1)"; then
    fail "--flag=value is accepted" "script exited non-zero: ${out##*$'\n'}"
  elif ! git -C "$root/clone" log --oneline main..HEAD | grep -q "landed on the release branch"; then
    fail "--flag=value is accepted" "branch created but the commit is missing"
  else
    pass "--flag=value is accepted"
  fi

  local rc=0
  out="$(cd "$root/clone" && "$SCRIPT" --to main --from 2>&1)" || rc=$?
  if [[ "$rc" -ne 2 ]]; then
    fail "a flag with no value is a usage error" "exit $rc, want 2"
  elif ! grep -q -- "--from requires a value" <<<"$out"; then
    fail "a flag with no value is a usage error" "no message: ${out:-(empty)}"
  else
    pass "a flag with no value is a usage error, not a silent exit 1"
  fi
}

# --- a bad --branch is a usage error, before the network ------------------------
# --branch was the one ref-shaped flag with no ref-name check, so it failed at
# `git checkout -b` with git's exit 128 — after the ls-remote, the fetch and the
# printed candidate list. The exit code is half the point; the refs assertion
# below is the other half, and it is the one that pins "before any round trip"
# rather than merely "with a nicer message".
t_bad_branch_override() {
  local root; root="$(mktemp -d "$TESTROOT/XXXXXX")"; trap 'rm -rf "$root"' RETURN
  make_fixture "$root"
  local out rc=0
  out="$(cd "$root/clone" && "$SCRIPT" --from release/v1.0.0 --to main --branch 'bad/*name' 2>&1)" || rc=$?
  if [[ "$rc" -ne 2 ]]; then
    fail "a bad --branch is a usage error" "exit $rc, want 2"
  elif ! grep -q "not a valid git ref name" <<<"$out"; then
    fail "a bad --branch is a usage error" "unexpected message: ${out##*$'\n'}"
  elif [[ -n "$(git -C "$root/clone" for-each-ref --format='%(refname)' 'refs/remotes/origin/release/*' 'refs/tags/*')" ]]; then
    fail "a bad --branch is a usage error" "it fetched refs before rejecting the input"
  else
    pass "a bad --branch is rejected at exit 2 before any network round trip"
  fi
}

# --- an empty --branch is a usage error, not the derived name -------------------
# `--branch=` used to reach the derivation and produce backport/v1.0.0 at exit 0,
# because BRANCH_OVERRIDE cannot tell "not passed" from "passed empty". --to,
# which defaults to a non-empty value, always caught its own empty form. Both
# spellings are covered: the `=` form and a separate empty word.
t_empty_branch_override() {
  local root; root="$(mktemp -d "$TESTROOT/XXXXXX")"; trap 'rm -rf "$root"' RETURN
  make_fixture "$root"

  local out rc=0
  out="$(cd "$root/clone" && "$SCRIPT" --from release/v1.0.0 --to main --branch= 2>&1)" || rc=$?
  if [[ "$rc" -ne 2 ]]; then
    fail "--branch= is a usage error" "exit $rc, want 2"
  elif ! grep -q -- "--branch cannot be empty" <<<"$out"; then
    fail "--branch= is a usage error" "unexpected message: ${out##*$'\n'}"
  elif [[ -n "$(git -C "$root/clone" branch --list 'backport/*')" ]]; then
    fail "--branch= is a usage error" "it fell back to the derived name"
  else
    pass "--branch= is a usage error, not a silent fallback to the derived name"
  fi

  rc=0
  out="$(cd "$root/clone" && "$SCRIPT" --from release/v1.0.0 --to main --branch "" 2>&1)" || rc=$?
  if [[ "$rc" -ne 2 ]]; then
    fail "--branch '' is a usage error" "exit $rc, want 2"
  else
    pass "--branch with an empty value is a usage error in both spellings"
  fi
}

# --- a branch --from leaves no tags behind -------------------------------------
# --no-tags was dropped when the bare-name refspecs were replaced with explicit
# ones, and git's automatic tag following filled the gap: a branch --from
# downloaded every tag reachable from the fetched history, so a maintainer who
# had never fetched v1.0.0 got it anyway. --help says the script fetches "those
# two refs — not the whole remote", and t_tag only proves the tag path still
# works, not that the branch path stays out of refs/tags.
t_branch_from_leaves_no_tags() {
  local root; root="$(mktemp -d "$TESTROOT/XXXXXX")"; trap 'rm -rf "$root"' RETURN
  make_fixture "$root"
  local out
  if ! out="$(cd "$root/clone" && "$SCRIPT" --from release/v1.0.0 --to main 2>&1)"; then
    fail "a branch --from fetches no tags" "script exited non-zero: ${out##*$'\n'}"
  elif [[ -n "$(git -C "$root/clone" for-each-ref --format='%(refname)' 'refs/tags/*')" ]]; then
    fail "a branch --from fetches no tags" \
      "it left $(git -C "$root/clone" for-each-ref --format='%(refname)' 'refs/tags/*' | tr '\n' ' ')behind"
  else
    pass "a branch --from fetches no tags into the user's repo"
  fi
}

# --- outside a repo, the missing repo is the error -----------------------------
# check-ref-format needs no repository, so the ref-name guards ran first and
# someone outside a repo was told their ref name was wrong — fixing which only
# earned them the real blocker on the next run. Ordering only; both errors are
# still reported, and the guards are still ahead of the network.
t_outside_a_repo() {
  local root; root="$(mktemp -d "$TESTROOT/XXXXXX")"; trap 'rm -rf "$root"' RETURN
  local out rc=0
  out="$(cd "$root" && "$SCRIPT" --from 'release/*' --to main 2>&1)" || rc=$?
  if [[ "$rc" -ne 1 ]]; then
    fail "outside a repo, the missing repo is the error" "exit $rc, want 1"
  elif ! grep -q "not inside a git repository" <<<"$out"; then
    fail "outside a repo, the missing repo is the error" "unexpected message: ${out##*$'\n'}"
  else
    pass "outside a repo, the missing repo is reported before the ref name"
  fi
}

echo "backport-fixes.sh — --from ref resolution"
t_branch
t_tag
t_unknown
t_to_rejects_a_tag
t_force_pushed_source
t_branch_beats_tag
t_unreachable_remote
t_glob_from
t_from_is_not_a_commit
t_bad_to_writes_nothing
t_branch_naming
t_arg_forms
t_bad_branch_override
t_empty_branch_override
t_branch_from_leaves_no_tags
t_outside_a_repo

if [[ "$failures" -gt 0 ]]; then
  echo "$failures failing"
  exit 1
fi
echo "all passing"
