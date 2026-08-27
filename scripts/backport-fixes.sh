#!/usr/bin/env bash
set -euo pipefail

# Cherry-pick commits from a release/hotfix branch — or from the tag that
# names them once the branch is gone — to a local backport branch off main
# (or another target). Does NOT push, create PRs, or touch remotes beyond
# `git fetch`.
#
# Conflicts use git's native cherry-pick state machine — resolve, then
# `git cherry-pick --continue` (or --skip / --abort). Re-running this
# script is not needed after a conflict; git's sequencer handles it.
#
# Uses `git cherry` for patch-ID-based matching, so commits already
# cherry-picked to the target (under different SHAs) are correctly
# detected and excluded.

usage() {
  cat <<'EOF'
Usage:
  backport-fixes.sh --from <branch|tag> [--to <branch>] [--branch <name>]

Options:
  --from <branch|tag>
                     Source branch OR tag on origin (e.g. release/v0.6.0,
                     hotfix/v0.5.1, v0.6.0). Do not include 'origin/'.
                     Required. After a release, release.yml has deleted
                     release/vX.Y.Z, so the tag is the only ref naming
                     those commits — which is what release.yml's summary
                     and backport-fixes.yml both tell you to pass. A
                     branch wins if a branch and a tag share the name.
  --to <branch>      Target branch on origin (default: main). Branch only:
                     backport-fixes.yml opens a PR with --base, which
                     needs a branch that exists on the remote.
  --branch <name>    Name for the local backport branch (default:
                     `backport/vX.Y.Z` derived from --from when it
                     matches release/vX.Y.Z or hotfix/vX.Y.Z. Anything
                     else — a tag included — is flattened into
                     `backport/<flattened-from>`, so --from v0.6.0 gives
                     `backport/v0.6.0`).
  -h, --help         Show this help.

Behavior:
  1. Asks origin what <from> and <to> name (git ls-remote), then fetches
     those two refs — not the whole remote.
  2. Lists commits on the resolved <from> ref — origin/<from> for a
     branch, refs/tags/<from> for a tag — that aren't already on
     origin/<to>, and commits that are already there (skipped).
  3. Creates the backport branch off origin/<to>.
  4. Runs `git cherry-pick -x` with the candidates, oldest-first.
  5. On conflict: stops. Resolve, then `git cherry-pick --continue`.

If the backport branch already exists locally, the script fails — delete
it (`git branch -D <name>`) or pass `--branch <other-name>` to override.

No push. No PR. The branch stays local; you decide what to do next.

Example:
  backport-fixes.sh --from release/v0.6.0
EOF
}

FROM=""
TO="main"
BRANCH_OVERRIDE=""
BRANCH_SET=0

while [[ $# -gt 0 ]]; do
  case "$1" in
    # Both spellings. `--from=v1.0.0` used to take the `*)` arm and exit 2 as an
    # unknown argument, and a trailing `--from` with no value exited 1 with no
    # message at all — `shift 2` fails under `set -e`. Neither is a defensible
    # answer for the flag --help now leads with.
    --from=*)   FROM="${1#*=}";            shift ;;
    --to=*)     TO="${1#*=}";              shift ;;
    --branch=*) BRANCH_OVERRIDE="${1#*=}"; BRANCH_SET=1; shift ;;
    --from|--to|--branch)
      if [[ $# -lt 2 ]]; then
        echo "error: $1 requires a value" >&2
        exit 2
      fi
      case "$1" in
        --from)   FROM="$2" ;;
        --to)     TO="$2" ;;
        --branch) BRANCH_OVERRIDE="$2"; BRANCH_SET=1 ;;
      esac
      shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "error: unknown argument: $1" >&2; usage >&2; exit 2 ;;
  esac
done

if [[ -z "$FROM" ]]; then
  echo "error: --from is required" >&2
  usage >&2
  exit 2
fi
if [[ -z "$TO" ]]; then
  echo "error: --to cannot be empty" >&2
  exit 2
fi
# An empty --branch used to fall through to the derived name and exit 0, because
# "not passed" and "passed empty" are the same empty string in BRANCH_OVERRIDE —
# whereas --to, which defaults to a non-empty value, caught its own empty form
# above. BRANCH_SET is what separates the two, so `--branch=` is now the usage
# error it obviously is rather than a silent fallback to a name nobody asked for.
if [[ "$BRANCH_SET" -eq 1 && -z "$BRANCH_OVERRIDE" ]]; then
  echo "error: --branch cannot be empty" >&2
  exit 2
fi
if [[ "$FROM" == origin/* || "$TO" == origin/* ]]; then
  echo "error: branch names must not include 'origin/'" >&2
  exit 2
fi
if [[ "$FROM" == "$TO" ]]; then
  echo "error: --from and --to must differ" >&2
  exit 2
fi

# Both values are interpolated into fetch refspecs below, so they have to be
# valid ref names before they get anywhere near one. `git ls-remote` matches its
# arguments as globs and `*` is legal in a refspec too, so an unvalidated
# `--from 'release/*'` passed the resolver, fetched wildcard-expanded, and left
# a ref name that is not a commit.
#
# `git check-ref-format` is git's own definition of the grammar, so this rejects
# `*`, `?`, `[`, `~`, `^`, `:`, `..`, control characters, trailing `.lock` and
# the rest without keeping a hand-written metacharacter list here that would
# drift from git's. Checking before the network also means a typo costs no round
# trip and touches no refs.
require_ref_name() {
  if ! git check-ref-format "refs/heads/$2"; then
    echo "error: $1 '$2' is not a valid git ref name" >&2
    exit 2
  fi
}

# Must be in a git repo. Ahead of the ref-name checks on purpose: those need no
# repo, so running them first meant someone outside a repo was told their ref
# name was wrong, fixed it, and only then learned the real blocker. The one
# precondition nothing else can proceed without is reported first.
if ! git rev-parse --git-dir >/dev/null 2>&1; then
  echo "error: not inside a git repository" >&2
  exit 1
fi

require_ref_name --from "$FROM"
require_ref_name --to "$TO"
# --branch was the one ref-shaped flag that skipped this, so a bad value survived
# all the way to `git checkout -b` and failed with git's exit 128 — after the
# ls-remote, the fetch and the printed candidate list. Nothing unsafe reached
# git: `-b` consumes the next word, so no value could turn into an option. It is
# the exit code and the timing that were wrong, and both are the same principle
# the --from guard above is built on: a usage error costs no round trip.
if [[ -n "$BRANCH_OVERRIDE" ]]; then
  require_ref_name --branch "$BRANCH_OVERRIDE"
fi

# Detect in-progress cherry-pick first — gives a more actionable error
# than the generic dirty-tree check, which also trips during a conflict.
if [[ -f "$(git rev-parse --git-dir)/CHERRY_PICK_HEAD" ]]; then
  echo "error: a cherry-pick is already in progress. Finish or abort it first:" >&2
  echo "       git cherry-pick --continue | --skip | --abort" >&2
  exit 1
fi

# Require clean working tree — cherry-picks onto a dirty tree are unsafe.
if ! git diff --quiet || ! git diff --cached --quiet; then
  echo "error: working tree has uncommitted changes. Commit or stash first." >&2
  exit 1
fi

echo "Fetching origin..."

# Ask the remote what every name is in one query, decide what to fetch, then
# fetch once. Asking per name and fetching between the asks cost four round
# trips for a branch --from and five for a tag; over SSH with a hardware-token
# key that is one touch each. It also fetched the source before establishing
# that --to exists, so a bad --to left a new tag or remote-tracking ref behind
# in the user's repo on the way to an error. Nothing is written now until both
# names have resolved.
#
# No --exit-code: without it, "the remote answered and has no such ref" is exit
# 0 with the name simply absent from the output, and any non-zero is
# unambiguously "could not ask" — unreachable, or refused. Reporting that as a
# missing ref sends the operator after a ref that is fine, so that arm exits
# without adding a claim about the ref; git has already described the failure on
# stderr and a guess on top of it would only mislead.
ls_out=""
if ! ls_out="$(git ls-remote origin \
      "refs/heads/$FROM" "refs/tags/$FROM" "refs/heads/$TO")"; then
  exit 1
fi

# Exact match on the ref name, not a substring: an annotated tag also emits a
# `refs/tags/<name>^{}` peel line, and `refs/heads/v1.0` must not answer for
# `refs/heads/v1.0.1`.
has_remote_ref() {
  awk -v want="$1" '$2 == want { hit = 1 } END { exit hit ? 0 : 1 }' <<<"$ls_out"
}

FROM_REF=""
TO_REF=""
refspecs=()

# --from accepts a branch or a tag. After a release, release.yml has deleted
# release/vX.Y.Z, so the tag is the only ref naming those commits. A branch wins
# on a name collision, which is what --help states.
#
# A bare-name refspec — `git fetch origin v1.0.0` — writes FETCH_HEAD and
# nothing else: no refs/tags entry, no remote-tracking ref. That is why looking
# the name up as `origin/<name>` afterwards could never see a tag. The explicit
# destinations below materialise it.
if has_remote_ref "refs/heads/$FROM"; then
  FROM_REF="origin/$FROM"
  refspecs+=("+refs/heads/$FROM:refs/remotes/origin/$FROM")
elif has_remote_ref "refs/tags/$FROM"; then
  # A re-cut tag (deleted on origin and re-pushed at a new commit) lands here.
  # `+` overwrites the stale local tag, which otherwise keeps pointing at the
  # superseded release and would backport the wrong commits.
  FROM_REF="refs/tags/$FROM"
  refspecs+=("+refs/tags/$FROM:refs/tags/$FROM")
else
  echo "error: $FROM not found on origin as a branch or a tag" >&2
  exit 1
fi

# --to is branch-only, deliberately. A tag would resolve and `git checkout -b`
# would even work, but backport-fixes.yml opens a PR with `--base "$TO"`, which
# needs a branch that exists on the remote.
if has_remote_ref "refs/heads/$TO"; then
  TO_REF="origin/$TO"
  refspecs+=("+refs/heads/$TO:refs/remotes/origin/$TO")
else
  echo "error: $TO not found on origin as a branch (--to must be a branch)" >&2
  exit 1
fi

# Every refspec carries a leading `+`: the bare-name form they replaced still
# got its remote-tracking update through `remote.origin.fetch`, whose refspec is
# forced. Writing the destination out without the `+` silently drops that force,
# and a source branch that was force-pushed — routine during release prep, e.g.
# an amended release commit — stops fast-forwarding and fails a backport that
# used to work.
#
# Without -q on purpose: -q suppresses the per-ref status table, which is where
# `! [rejected]` is written, so a fetch that fails after ls-remote said the ref
# was there would exit with no explanation at all.
#
# --no-tags disables git's automatic tag following only; an explicit
# `refs/tags/<name>` refspec is still fetched, which is what the tag --from path
# depends on. Without it a branch --from downloaded every tag reachable from the
# fetched history as a side effect, so `--from release/v1.0.0` left refs/tags/*
# in the user's repo — refs nobody asked for, and more than the "those two refs
# — not the whole remote" that --help promises.
git fetch --no-tags origin "${refspecs[@]}" || exit 1

# Resolution established that the ref exists. This establishes that it names a
# commit, which is not the same claim: a tag may point at a tree or a blob, and
# such a tag has a perfectly valid ref name, so check-ref-format cannot see it
# and ls-remote reports it like any other ref. `git cherry` fatals on it.
#
# --quiet covers "no such ref"; it does not suppress the type-mismatch error,
# which is left alone on purpose — it names the type git actually found, which
# this script cannot. The line below adds only the mapping from what the
# operator typed to the ref it landed on.
if ! git rev-parse --verify --quiet "${FROM_REF}^{commit}" >/dev/null; then
  echo "error: $FROM resolved to $FROM_REF, which does not name a commit" >&2
  exit 1
fi

# `git cherry -v <upstream> <head>` prints one line per commit:
#   + <sha> <subject>   -> not on upstream (candidate for backport)
#   - <sha> <subject>   -> already on upstream via patch-ID match
#
# Not `|| true`. git-cherry documents no meaningful non-zero exit, so a non-zero
# means it could not answer the question — and swallowing that turns a fatal
# into an empty candidate list, which this script then reports as "Nothing to
# backport" and exit 0: a tooling failure told to the operator as a fact about
# the refs, and a green run in backport-fixes.yml.
cherry_out=""
if ! cherry_out="$(git cherry -v "$TO_REF" "$FROM_REF")"; then
  echo "error: git cherry could not compare $FROM_REF against $TO_REF" >&2
  exit 1
fi

candidates_pretty="$(echo "$cherry_out" | awk '$1 == "+" { sub(/^\+ /, ""); print }')"
already_pretty="$(echo   "$cherry_out" | awk '$1 == "-" { sub(/^- /, "");  print }')"
shas="$(echo "$cherry_out" | awk '$1 == "+" { print $2 }')"

n_candidates=0
[[ -n "$candidates_pretty" ]] && n_candidates=$(echo "$candidates_pretty" | wc -l | tr -d ' ')
n_already=0
[[ -n "$already_pretty" ]] && n_already=$(echo "$already_pretty" | wc -l | tr -d ' ')

echo
echo "=== Commits on $FROM_REF not yet on $TO_REF ($n_candidates) ==="
if [[ "$n_candidates" -gt 0 ]]; then
  echo "$candidates_pretty"
else
  echo "(none)"
fi

if [[ "$n_already" -gt 0 ]]; then
  echo
  echo "=== Already on $TO_REF, excluded ($n_already) ==="
  echo "$already_pretty"
fi

if [[ "$n_candidates" -eq 0 ]]; then
  echo
  echo "Nothing to backport."
  exit 0
fi

if [[ -n "$BRANCH_OVERRIDE" ]]; then
  branch="$BRANCH_OVERRIDE"
elif [[ "$FROM" =~ ^(release|hotfix)/v([0-9]+\.[0-9]+\.[0-9]+)$ ]]; then
  branch="backport/v${BASH_REMATCH[2]}"
else
  flat="$(echo "$FROM" | sed -E 's|/|-|g; s/[^a-zA-Z0-9._-]+/-/g')"
  branch="backport/${flat}"
fi

if git show-ref --verify --quiet "refs/heads/$branch"; then
  echo "error: local branch '$branch' already exists." >&2
  echo "       Delete it (git branch -D $branch) or pass --branch <other-name>." >&2
  exit 1
fi

echo
echo "Creating branch $branch off $TO_REF..."
git checkout -b "$branch" "$TO_REF"

echo
echo "Cherry-picking $n_candidates commit(s) with -x, oldest first..."
echo "If git stops on a conflict:"
echo "  - Resolve, 'git add <files>', then 'git cherry-pick --continue'."
echo "  - To drop the conflicting commit: 'git cherry-pick --skip'."
echo "  - To bail out entirely:           'git cherry-pick --abort'."
echo

# shellcheck disable=SC2086 # intentional word-split: $shas is a hex-only list
exec git cherry-pick -x $shas
