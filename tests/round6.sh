#!/bin/sh
# Regression tests for review round 6: guard parsing, git-dir writes, per-commit verdicts,
# secrets in mark, the brief (comments, two-step approval) and the checks runner.
# Pushes only to throwaway bare remotes under $T.
set -u
RW=$(cd "$(dirname "$0")/.." && pwd)
G="$RW/hooks/guard_push.py"
T=$(mktemp -d "${TMPDIR:-/tmp}/rwtest6.XXXXXX")
# Test a private copy of the plugin, so the results never depend on this checkout's state.
mkdir -p "$T/plugin" && cp -R "$RW/scripts" "$RW/hooks" "$T/plugin/"
RW="$T/plugin"
G="$RW/hooks/guard_push.py"
unset RAVENWATCH_DISABLE RAVENWATCH_CHECKS_RUNNING XDG_CONFIG_HOME GIT_DIR GIT_WORK_TREE
trap 'rm -rf "$T"' EXIT
export HOME="$T/home"; mkdir -p "$HOME"
export GIT_CONFIG_NOSYSTEM=1
P=push
D=.git
cd "$T"
git init -q --bare -b main remote.git
git init -q -b main r && cd r
git config user.email t@example.com; git config user.name t
echo a > a; git add .; git commit -qm a
git remote add origin "$T/remote.git"
git $P -q -u origin main
R="$T/r"
python3 "$RW/scripts/ravenwatch.py" install-hook >/dev/null
git init -q "$T/nohook"

pass=0; failn=0
ok() { pass=$((pass+1)); }
bad() { failn=$((failn+1)); echo "FAIL: $*"; }
bash_gate() { # expect cwd command
  out=$(python3 -c 'import json,sys; print(json.dumps({"tool_name":"Bash","cwd":sys.argv[1],"tool_input":{"command":sys.argv[2]}}))' "$2" "$3" | python3 "$G")
  [ -n "$out" ] && got=deny || got=allow
  [ "$got" = "$1" ] && ok || bad "bash expected $1 got $got: $3 $out"
}
write_gate() { # expect cwd path
  out=$(python3 -c 'import json,sys; print(json.dumps({"tool_name":"Write","cwd":sys.argv[1],"tool_input":{"file_path":sys.argv[2],"content":"x"}}))' "$2" "$3" | python3 "$G")
  [ -n "$out" ] && got=deny || got=allow
  [ "$got" = "$1" ] && ok || bad "write expected $1 got $got: $3 $out"
}
rwq() { python3 "$RW/scripts/ravenwatch.py" "$@" >/dev/null 2>&1; }
push_ok()   { git $P -q "$@" 2>"$T/err" && ok || { bad "push should succeed: $*"; cat "$T/err"; }; }
push_fail() {
  if git $P -q "$@" 2>"$T/err"; then bad "push should be blocked: $*"
  elif grep -q "ravenwatch:" "$T/err"; then ok
  else bad "push failed but not because of ravenwatch: $*"; cat "$T/err"; fi
}

# --- guard: comments, line continuations, heredocs (BUG-1, BUG-2, BUG-4)
N="$T/nohook"
bash_gate deny  "$N" "$(printf '# publish the branch\ngit %s -u origin feat' "$P")"
bash_gate deny  "$N" "$(printf 'git status  # then\ngit %s origin main' "$P")"
bash_gate deny  "$N" "git log --format=%h#%s; git $P origin main"
bash_gate deny  "$N" "$(printf 'git \\\n  %s origin main' "$P")"
bash_gate deny  "$N" "$(printf 'cat <<EOF | sh\ngit %s\nEOF' "$P")"
bash_gate deny  "$N" "$(printf 'cat <<EOF >/dev/null && git %s origin main\nx\nEOF' "$P")"
bash_gate allow "$R" "$(printf '# publish the branch\ngit %s -u origin feat' "$P")"
bash_gate allow "$R" "$(printf 'git commit -m "$(cat <<%sEOF%s\nmention git %s here\nEOF\n)"' "'" "'" "$P")"
bash_gate allow "$R" "echo 'issue #12' && git status"

# --- guard: git-dir writes by other names (BUG-3, SEC-1)
write_gate deny  "$T" "$T/fresh/$D/ravenwatch/status"
write_gate deny  "$T" "$T/fresh/$D/hooks/pre-$P"
write_gate deny  "$T" "$T/elsewhere/ravenwatch/status"
write_gate allow "$R" "$R/$D/ravenwatch/reports/r.md"
bash_gate deny  "$R" "cd $D/rav* && printf x > status"
bash_gate deny  "$R" "cd $D && ls"
bash_gate deny  "$R" "printf x > $D/rav*/status"
bash_gate deny  "$R" "cp x $T/remote.git/hooks/"
bash_gate allow "$R" "git clone -q $T/remote.git $T/c2"
bash_gate allow "$R" "python3 -c 'print(1)' > /tmp/out.txt"

# --- per-commit verdicts (UX-2) and the fetch hint (UX-1)
git checkout -q -b a; echo a2 > a2; git add a2; git commit -qm a2
rwq prepare; rwq mark --verdict pass
git checkout -q main; git checkout -q -b b; echo b2 > b2; git add b2; git commit -qm b2
rwq prepare; rwq mark --verdict pass
push_ok origin a
push_ok origin b
git checkout -q main

# --- mark refuses likely secrets unless the owner clears them (LOOP-1)
git checkout -q -b s; fake=Zx81kq0PLm; fake="${fake}33aa9QwerTy"; printf 'api_key = "%s"\n' "$fake" > s.py; git add s.py; git commit -qm s
rwq prepare
rwq mark --verdict pass && bad "mark passed with a likely secret" || ok
rwq mark --verdict pass --secrets-cleared && ok || bad "mark refused with --secrets-cleared"
git checkout -q main

# --- brief: inline comments, two-step approval (BUG-5, SEC-2)
cat > .ravenwatch.md <<'EOF'
---
audience: only me
skip: []          # optional
checks:
  - name: ok
    run: echo fine
    blocking: true   # fails the review
  - name: slow
    run: sleep 30
    timeout: 10
  - name: pusher
    run: git push origin main
---
# Project
## Accepted risks
- scripts/x.sh: example accepted risk
EOF
out=$(python3 "$RW/scripts/ravenwatch.py" trust-brief 2>&1)
echo "$out" | grep -q "NOT approved" && ok || bad "trust-brief approved without --approve: $out"
echo "$out" | grep -q "example accepted risk" && ok || bad "accepted risk text not shown"
sha=$(echo "$out" | sed -n 's/^sha256: //p')
rwq trust-brief --approve 0000 && bad "approved with wrong hash" || ok
rwq trust-brief --approve "$sha" && ok || bad "approve with shown hash failed"
printf '\n- extra risk\n' >> .ravenwatch.md
rwq trust-brief --approve "$sha" && bad "approved a changed brief" || ok
git checkout -q -- . 2>/dev/null; rm -f .ravenwatch.md

# --- checks: clean tree, incremental results, timeouts, push disabled, --only (RES-1/3/4, SEC-3, PRIV-1)
git checkout -q -b c; echo c > c; git add c; git commit -qm c
rwq prepare
run=$(cat "$(git rev-parse --git-path ravenwatch/runs/latest)")
echo dirty > dirt.txt
rwq checks --run "$run" && bad "checks ran with a dirty tree" || ok
rm dirt.txt
python3 "$RW/scripts/ravenwatch.py" checks --run "$run" >"$T/chk" 2>&1; rc=$?
[ "$rc" -eq 1 ] && ok || bad "blocking failure did not exit 1 (rc=$rc)"
res="$(git rev-parse --git-path ravenwatch/runs)/$run/checks.md"
grep -q "## ok — PASS" "$res" && ok || bad "ok check not recorded"
grep -q "## slow — TIMEOUT" "$res" && ok || bad "slow check not a timeout"
grep -q "## pusher — FAIL" "$res" && ok || bad "push inside a check was not blocked"
grep -q "disabled while checks run" "$res" && ok || bad "push shim message missing"
rwq checks --run "$run" --only nosuch && bad "unknown --only accepted" || ok
rwq checks --run "$run" --only ok; grep -q "## slow — TIMEOUT" "$res" && ok || bad "--only erased earlier results"
python3 -c 'import sys; sys.path.insert(0, sys.argv[1]); import ravenwatch as r
out = r.redact_output("DB_PASSWORD=hunter2hunter2 token: \"abcdef123456\"")
sys.exit(0 if "hunter2hunter2" not in out and "abcdef123456" not in out else 1)' "$RW/scripts" && ok || bad "generic secrets not redacted"

# --- report drafts are private and removed after mark (SEC-4)
ctx=$(python3 "$RW/scripts/ravenwatch.py" prepare)
draft=$(echo "$ctx" | sed -n 's/^- report draft: \([^ ]*\).*/\1/p')
mode=$(python3 -c 'import os,sys; print(oct(os.stat(sys.argv[1]).st_mode & 0o777))' "$(dirname "$draft")")
[ "$mode" = 0o700 ] && ok || bad "draft dir not private ($mode)"
echo report > "$draft"
rwq mark --verdict block --report "$draft" && ok || bad "mark with draft failed"
[ ! -e "$draft" ] && ok || bad "draft not removed"
# A link to a file the user owns: only the symlink/hard-link defence can refuse it.
echo owned-secret > "$T/own.txt"
reports="$(git rev-parse --git-path ravenwatch/reports)"
ln -s "$T/own.txt" "$T/link.md"
python3 "$RW/scripts/ravenwatch.py" mark --verdict block --report "$T/link.md" >/dev/null 2>"$T/err" &&
  bad "symlinked report accepted" || { grep -q "^error:" "$T/err" && ok || { bad "symlink refusal was not a clean error"; cat "$T/err"; }; }
ln "$T/own.txt" "$T/hard.md"
rwq mark --verdict block --report "$T/hard.md" && bad "hard-linked report accepted" || ok
grep -rq owned-secret "$reports" && bad "linked file copied into reports" || ok

echo "round6: passed=$pass failed=$failn"
[ "$failn" -eq 0 ]
