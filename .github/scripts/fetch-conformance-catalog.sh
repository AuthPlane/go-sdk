#!/usr/bin/env bash
#
# Fetch the conformance catalog at the revision this repo pins.
#
# The catalog lives in github.com/AuthPlane/conformance and is updated
# independently of this repo, so cloning its default branch would let a catalog
# change turn an unrelated PR red here. The ref is pinned instead, single-sourced
# from the tracked .conformance-catalog-ref at the repo root — bump it there when
# adopting new catalog cases, together with the coverage for them, so a catalog
# change can never break CI on its own.
#
# This script exists because the read/guard/fetch sequence is needed by more than
# one workflow (ci.yml and release.yml). Keeping it inline in both meant the
# guard could be tightened in one and not the other; the pin was single-sourced
# but the logic reading it was not.
#
# Clones into $RUNNER_TEMP — outside $GITHUB_WORKSPACE — so the catalog stays out
# of the working tree: it must never trip `go list ./...` or a coverage glob, and
# `git add -A` in the release commit must never stage it as a gitlink.
#
# Requires: GITHUB_WORKSPACE, RUNNER_TEMP.

set -euo pipefail

: "${GITHUB_WORKSPACE:?GITHUB_WORKSPACE must be set}"
: "${RUNNER_TEMP:?RUNNER_TEMP must be set}"

REF_FILE="$GITHUB_WORKSPACE/.conformance-catalog-ref"
DEST="$RUNNER_TEMP/conformance"
CATALOG_REPO="https://github.com/AuthPlane/conformance.git"

if [[ ! -f "$REF_FILE" ]]; then
  echo "::error::$REF_FILE is missing; the conformance catalog revision is unpinned"
  exit 1
fi

CONFORMANCE_CATALOG_REF="$(tr -d '[:space:]' < "$REF_FILE")"

# Guard against un-pinning: the ref must be a full commit SHA, not a branch or
# tag name, either of which would silently track a moving target.
if ! grep -Eq '^[0-9a-f]{40}$' <<< "$CONFORMANCE_CATALOG_REF"; then
  echo "::error::.conformance-catalog-ref must be a 40-hex commit SHA, got '$CONFORMANCE_CATALOG_REF'"
  exit 1
fi

git init -q "$DEST"
if ! git -C "$DEST" fetch --depth=1 "$CATALOG_REPO" "$CONFORMANCE_CATALOG_REF"; then
  echo "::error::Pinned conformance catalog ref $CONFORMANCE_CATALOG_REF is unreachable"
  exit 1
fi
git -C "$DEST" checkout -q FETCH_HEAD

echo "Conformance catalog checked out at $CONFORMANCE_CATALOG_REF"
