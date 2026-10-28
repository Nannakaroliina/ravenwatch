#!/bin/sh
# ravenwatch git pre-push hook
# Blocks `git push` from any terminal until the commits being pushed are covered
# by a passing (or explicitly accepted) review from /ravenwatch:review in Claude Code.
#
# This hook is the authoritative check: git hands it the exact objects being pushed,
# and it asks the remote itself (git ls-remote) which branches and tags it already
# has, so local remote-tracking refs cannot make unreviewed commits look published.
#
# Verdict state (written by `ravenwatch.py mark`, key=value lines, first value of a key wins):
#   <git-dir>/ravenwatch/verdicts/<commit>  one file per reviewed commit
#   <git-dir>/ravenwatch/status             the most recent verdict
#   keys: head (reviewed commit), base (start of the reviewed range, or the empty tree),
#         verdict (pass | warn | accepted unlock; block does not), report (stored report path)
#
# Bypass once:   git push --no-verify
# Disable:       RAVENWATCH_DISABLE=1 git push
# A hook that existed before installation is kept as pre-push.local and runs first.

hook_dir=$(dirname "$0")
input=$(cat)

if [ -x "$hook_dir/pre-push.local" ]; then
  printf '%s\n' "$input" | "$hook_dir/pre-push.local" "$@" || exit $?
fi

if [ "$RAVENWATCH_CHECKS_RUNNING" = "1" ]; then
  echo "✋ ravenwatch: pushing is disabled while the review's checks run." >&2
  exit 1
fi
[ "$RAVENWATCH_DISABLE" = "1" ] && exit 0
[ -n "$input" ] || exit 0

remote_name=$1
remote_url=${2:-$1}
# For messages only: never print credentials embedded in the URL.
shown_url=$(printf '%s' "$remote_url" | sed 's#://[^/@]*@#://***@#')
state_dir=$(git rev-parse --git-path ravenwatch 2>/dev/null)
empty_tree=$(git hash-object -t tree /dev/null)
# Never let rev-list fetch missing objects from a promisor remote (partial clones).
GIT_NO_LAZY_FETCH=1
export GIT_NO_LAZY_FETCH

tmp=$(mktemp -d "${TMPDIR:-/tmp}/ravenwatch.XXXXXX") || exit 1
trap 'rm -rf "$tmp"' EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

REVIEW="Run /ravenwatch:review in Claude Code, then push again."

# fail <what happened> [<what to do next>]; the next step defaults to a new review.
fail() {
  echo "" >&2
  echo "✋ ravenwatch: $1" >&2
  echo "   ${2:-$REVIEW}" >&2
  echo "   (Bypass once with: git push --no-verify)" >&2
  echo "" >&2
  exit 1
}

is_sha() { case "$1" in "" | *[!0-9a-f]*) return 1 ;; *) return 0 ;; esac; }
is_null() { case "$1" in "" | *[!0]*) return 1 ;; *) return 0 ;; esac; }

# The verdict for a commit: its own verdict file if it was reviewed, else the most recent verdict.
verdict_file() {
  if is_sha "$1" && [ -f "$state_dir/verdicts/$1" ]; then echo "$state_dir/verdicts/$1"; else echo "$state_dir/status"; fi
}
get() { sed -n "s/^$2=//p" "$1" 2>/dev/null | head -n 1; }

# The remote we list must be the remote git is pushing to.
check_target() {
  for key in receivepack uploadpack; do
    if [ -n "$(git config --get "remote.$remote_name.$key" 2>/dev/null)" ]; then
      fail "remote.$remote_name.$key is set, so the gate cannot be sure which repository it is checking." \
        "Unset it (git config --unset remote.$remote_name.$key) or push without the gate."
    fi
  done
  args=$(ps -ww -o args= -p "$PPID" 2>/dev/null)
  [ -n "$args" ] || fail "could not inspect the push command (ps is unavailable), so the push target cannot be verified." \
    "Push from a shell where ps works."
  # git accepts abbreviations: --e[xec], --rec[eive-pack], and --rec[urse-submodules] pushes submodules
  # through their own hooks.
  if printf '%s\n' "$args" | grep -Eq -- '(^|[[:space:]])--(e[a-z]*|rec[a-z-]*)([=[:space:]]|$)'; then
    fail "this push overrides the receive command or recurses into submodules, so the gate cannot check it." \
      "Push again without --exec/--receive-pack/--recurse-submodules (push submodules from inside each one)."
  fi
  # The same recursion, switched on in git config: refused whenever it is on, whether or not submodules can
  # be found (git finds them in places a hook would miss). push.recurseSubmodules and submodule.recurse both
  # set it and the one git reads last wins (the order --get-regexp lists them in); any value not known to
  # mean off counts as on (git reads submodule.recurse=2 as true). Same rule as the Claude guard.
  recurse=0
  while IFS=' ' read -r key value; do
    value=$(printf '%s' "$value" | tr 'A-Z' 'a-z')
    case "$(printf '%s' "$key" | tr 'A-Z' 'a-z')" in
      push.recursesubmodules) case "$value" in check | no | false | off | 0) recurse=0 ;; *) recurse=1 ;; esac ;;
      submodule.recurse) case "$value" in false | no | off | 0) recurse=0 ;; *) recurse=1 ;; esac ;;
    esac
  done <<EOF
$(git config --get-regexp '^(push\.recursesubmodules|submodule\.recurse)$' 2>/dev/null)
EOF
  [ "$recurse" = 1 ] && fail "push.recurseSubmodules / submodule.recurse is on, so git may push submodules through their own hooks, which the gate cannot check." \
    "Set push.recurseSubmodules to check (or submodule.recurse to false) in this repository's config, and push submodules from inside each one."
  listed=$(git ls-remote --get-url "$remote_url" 2>/dev/null)
  if [ "$listed" != "$remote_url" ]; then
    fail "url.*.insteadOf rewrites the push URL to a different one for reads; the gate cannot check this push." \
      "Remove the insteadOf/pushInsteadOf rule that covers $shown_url, or push without the gate."
  fi
  path=${remote_url#file://}
  if [ -d "$path" ]; then
    # git exports GIT_DIR to hooks in worktrees and submodules; it would override -C.
    theirs=$(unset GIT_DIR GIT_WORK_TREE GIT_COMMON_DIR GIT_INDEX_FILE GIT_PREFIX
      git -C "$path" rev-parse --path-format=absolute --git-common-dir 2>/dev/null)
    ours=$(git rev-parse --path-format=absolute --git-common-dir 2>/dev/null)
    [ -n "$theirs" ] && [ "$theirs" = "$ours" ] && fail "the push target $shown_url is this repository itself." \
      "Push to a different repository."
  fi
}

# Branches and tags the remote already has (not refs/pull/* and the like, which anyone can create).
load_tips() {
  [ -f "$tmp/tips" ] && return 0
  check_target
  git ls-remote --heads --tags "$remote_url" </dev/null >"$tmp/listing" 2>"$tmp/err" ||
    fail "could not list the refs on $shown_url: $(sed 's#://[^/@]*@#://***@#' "$tmp/err" | tail -n 3)" \
      "Check your network and credentials for $remote_name, then push again."
  awk '$1 ~ /^[0-9a-f]+$/ { print $1 }' "$tmp/listing" | sort -u >"$tmp/shas"
  sed 's/^/^/' "$tmp/shas" >"$tmp/tips"
  # Remote tips we have not fetched can't exclude anything; count them to give a useful next step.
  unfetched=$(git cat-file --batch-check='%(objectname)' <"$tmp/shas" 2>/dev/null | grep -c ' missing$')
}

# Next step for a review-related refusal: fetching may be all that's needed.
review_next() {
  if [ "${unfetched:-0}" -gt 0 ]; then
    echo "First run \`git fetch $remote_name\` (the remote has $unfetched branch/tag tip(s) you haven't fetched) and push again; if it still fails, run /ravenwatch:review."
  else
    echo "$REVIEW"
  fi
}

# First commit reachable from $1 that the remote does not have; $2 is git's view of the remote ref.
first_new() {
  { echo "$1"; is_null "$2" || echo "^$2"; cat "$tmp/tips"; } |
    git rev-list -n 1 --ignore-missing --stdin
}

while read -r local_ref local_sha remote_ref remote_sha; do
  [ -n "$local_sha" ] || continue
  # Branch deletion: nothing to review.
  is_null "$local_sha" && continue
  # Remote already has this exact object: nothing new.
  [ "$local_sha" = "$remote_sha" ] && continue

  short=$(echo "$local_sha" | cut -c1-8)
  commit=$(git rev-parse --verify -q "$local_sha^{commit}") ||
    fail "$local_ref ($short) is a $(git cat-file -t "$local_sha" 2>/dev/null), not a commit; only commits can be reviewed." \
      "Push only branches and tags that point at commits."

  load_tips
  # git's own view of this remote ref must match the listing, or we are looking at another repository.
  case "$remote_ref" in
    refs/heads/* | refs/tags/*)
      listed=$(awk -v r="$remote_ref" '$2 == r { print $1; exit }' "$tmp/listing")
      if is_null "$remote_sha"; then [ -z "$listed" ]; else [ "$listed" = "$remote_sha" ]; fi ||
        fail "the remote's ref list does not match what git is pushing to for $remote_ref; the gate cannot check this push." \
          "Someone may have pushed meanwhile: run \`git fetch $remote_name\` and push again."
      ;;
  esac

  new=$(first_new "$commit" "$remote_sha") ||
    fail "could not work out which commits in $short ($local_ref) are new." "Run \`git fetch $remote_name\` and push again."
  [ -z "$new" ] && continue

  vfile=$(verdict_file "$commit")
  reviewed=$(get "$vfile" head)
  verdict=$(get "$vfile" verdict)
  base=$(get "$vfile" base)
  is_sha "$reviewed" || fail "no review has been recorded for this repository."
  # A new tip must be exactly the reviewed commit: the review read the final state, so an earlier
  # commit (for example one whose changes a later commit reverted) was never reviewed as a tip.
  if [ "$commit" != "$reviewed" ]; then
    if git merge-base --is-ancestor "$commit" "$reviewed" 2>/dev/null; then
      fail "$short ($local_ref) is an earlier commit than the reviewed one ($(echo "$reviewed" | cut -c1-8)); only a reviewed commit can be pushed as a new tip." \
        "Push the reviewed commit, or check out $local_ref and run /ravenwatch:review."
    fi
    fail "commit $short ($local_ref) has not been reviewed (the most recent review covered $(echo "$reviewed" | cut -c1-8))." \
      "$(review_next)"
  fi

  case "$verdict" in
    pass|warn|accepted) ;;
    *) report=$(get "$vfile" report)
       fail "the review of $short returned BLOCK${report:+ — see $report}." \
         "Fix the findings and run /ravenwatch:review again, or tell Claude you accept the risk to record it." ;;
  esac

  # The review must cover every new commit: none of them may be at or before the reviewed range's base.
  is_sha "$base" || fail "the recorded review has no valid range."
  if [ "$base" != "$empty_tree" ]; then
    bases=$(git merge-base --all "$commit" "$base" 2>/dev/null)
    [ $? -le 1 ] || fail "could not compare $short ($local_ref) with the reviewed range."
    if [ -n "$bases" ]; then
      before=$({ printf '%s\n' $bases; is_null "$remote_sha" || echo "^$remote_sha"; cat "$tmp/tips"; } |
        git rev-list -n 1 --ignore-missing --stdin) || fail "could not compare $short ($local_ref) with the reviewed range."
      [ -z "$before" ] ||
        fail "$short ($local_ref) includes new commits from before the reviewed range (started at $(echo "$base" | cut -c1-8))." \
          "$(review_next) If the branch's upstream was deleted or rewritten, review with --base <the remote's default branch>."
    fi
  fi
done <<EOF
$input
EOF

exit 0
