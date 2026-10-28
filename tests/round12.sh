#!/bin/sh
# Regression tests for the round 6 review findings (0.4.2): variable values that go on after a quote or
# `$(…)`, alias chains too deep to follow and Bash writes to git config files; a lone CR in the secret scan;
# a secret scan that ran out of time; NUL-byte and `binary` files in the scan; local overrides outside the
# reviewed range; and segments() reading quotes through quoting().
# Pushes only to throwaway bare remotes under $T.
set -u
RW=$(cd "$(dirname "$0")/.." && pwd)
T=$(mktemp -d "${TMPDIR:-/tmp}/rwtest12.XXXXXX")
# Test a private copy of the plugin, so the results never depend on this checkout's state.
mkdir -p "$T/plugin" && cp -R "$RW/scripts" "$RW/hooks" "$T/plugin/"
RW="$T/plugin"
G="$RW/hooks/guard_push.py"
unset RAVENWATCH_DISABLE RAVENWATCH_CHECKS_RUNNING XDG_CONFIG_HOME GIT_DIR GIT_WORK_TREE CDPATH
export GIT_CONFIG_NOSYSTEM=1
trap 'rm -rf "$T"' EXIT
export HOME="$T/home"; mkdir -p "$HOME"
P=push
cd "$T"
git init -q --bare -b main remote.git
git init -q -b main r && cd r
git config user.email t@example.com; git config user.name t
echo a > a; git add .; git commit -qm a
git remote add origin "$T/remote.git"
git $P -q -u origin main
R="$T/r"
RV="$RW/scripts/ravenwatch.py"
python3 "$RV" install-hook >/dev/null

pass=0; failn=0
ok() { pass=$((pass+1)); }
bad() { failn=$((failn+1)); echo "FAIL: $*"; }
bash_gate() { # expect cwd command [text the reason must contain]
  out=$(python3 -c 'import json,sys; print(json.dumps({"tool_name":"Bash","cwd":sys.argv[1],"tool_input":{"command":sys.argv[2]}}))' "$2" "$3" | python3 "$G")
  [ -n "$out" ] && got=deny || got=allow
  [ "$got" = "$1" ] && ok || bad "expected $1 got $got: $3 $out"
  if [ $# -ge 4 ] && [ "$1" = deny ]; then
    echo "$out" | grep -q -- "$4" && ok || bad "reason for '$3' lacks '$4': $out"
  fi
}
k=AKIA  # credential-like fixtures are built from split pieces

# --- BUG-1: a variable's value goes on after a quote or `$(…)`, or has quotes inside a bare word
bash_gate deny  "$R" "X='$R'/.git; printf 'verdict=pass' > \"\$X/ravenwatch/status\"" "can't tell where"
bash_gate deny  "$R" "X=\"$R\"/.git; cp evil \"\$X/hooks/pre-$P\"" "can't tell where"
bash_gate deny  "$R" "X=\$HOME'/../r/.git'; cp evil \"\$X/hooks/pre-$P\"" "can't tell where"
bash_gate deny  "$R" "X=\$(mktemp -d)/../../../..$R/.git; cp evil \"\$X/hooks/pre-$P\"" "can't tell where"
bash_gate deny  "$R" "X=$R/.gi''t; cp evil \"\$X/hooks/pre-$P\"" "can't tell where"
bash_gate deny  "$R" "X=\"$R/.gi\\t\"; cp evil \"\$X/hooks/pre-$P\"" "can't tell where"
# Whole-word values are still followed, both ways.
bash_gate deny  "$R" "X='$R/.git'; cp evil \"\$X/hooks/pre-$P\"" "inside a git directory"
bash_gate allow "$R" "X='/tmp/a b'; cp f \"\$X/c\""
bash_gate allow "$R" "D=\$(mktemp -d); cp f \"\$D/c\""
bash_gate allow "$R" "X=/tmp/x; cp f \$X/c"

# --- SEC-1: an alias chain the guard can't follow to its end, and Bash writes to git config files
git config alias.a1 a2; git config alias.a2 a3; git config alias.a3 a4; git config alias.a4 a5
git config alias.a5 a6; git config alias.a6 "$P --no-verify"
bash_gate deny  "$R" "git a1 origin main" "too deep"
git config alias.l1 l2; git config alias.l2 l1
bash_gate deny  "$R" "git l1 origin main" "too deep"
git config alias.st status; git config alias.st2 st
bash_gate allow "$R" "git st2"
bash_gate allow "$R" "git status"
bash_gate deny  "$R" "printf '[alias]\\n' >> ~/.gitconfig" "git config file"
bash_gate deny  "$R" "printf x | tee -a $HOME/.config/git/config" "git config file"
bash_gate deny  "$R" "cp evil ~/.gitconfig" "git config file"
bash_gate allow "$R" "cat ~/.gitconfig"

# --- DES-1: segments() takes comments, continuations and literal `$` from quoting()
python3 - "$RW/hooks" <<'EOF' && ok || bad "segments()"
import sys; sys.path.insert(0, sys.argv[1]); import guard_push as g
cases = {
    "echo a\\ #x; git status": [["echo", "a #x"], ["git", "status"]],
    "echo hi # c\ngit status": [["echo", "hi"], ["git", "status"]],
    "echo hi #": [["echo", "hi"]],
    "echo a#b": [["echo", "a#b"]],
    "ls \\\n -la": [["ls", "-la"]],
    "echo \"$(echo 'a$b')\"": [["echo", "$(echo 'a" + g.LITERAL["$"] + "b')"]],
}
bad = {c: [s[0] for s in g.segments(c)] for c in cases if [s[0] for s in g.segments(c)] != cases[c]}
sys.exit(print(bad) or 1 if bad else 0)
EOF

# --- RES-1: a lone CR doesn't end a line for the secret scan
printf 'x = 1\rKEY = "%s"\r' "${k}Q7RTYU2X9ZPLM4KD" > cr.py
printf 'a = 1\rdiff --git x y\nKEY = "%s"\n' "${k}W3EDFR5T6YHJU8KL" > crdiff.py
git add cr.py crdiff.py; git commit -qm cr
ctx=$(python3 "$RV" prepare)
echo "$ctx" | grep -q "AWS access key ID at cr.py" && ok || bad "a key after a lone CR was not scanned"
echo "$ctx" | grep -q "AWS access key ID at crdiff.py" && ok || bad "a CR + 'diff ' piece hid the rest of the hunk"
git rm -q cr.py crdiff.py; git commit -qm uncr

# --- TEST-1: NUL bytes and the `binary` attribute can't hide a key from the scan
printf 'KEY = "%s"\n\000\n' "${k}Z1XCVB2NMQ3WER4T" > blob.py
git add blob.py; git commit -qm blob
ctx=$(python3 "$RV" prepare)
echo "$ctx" | grep -q "AWS access key ID at blob.py" && ok || bad "a NUL byte hid a key from the scan"
echo "$ctx" | grep "binary in the diff" | grep -q "blob.py" && ok || bad "NUL-byte file not listed as binary"
git rm -q blob.py; git commit -qm unblob
printf 'KEY = "%s"\n' "${k}P9OIUY8TREWQ7LKJ" > bin.py
echo "bin.py binary" > .gitattributes
git add bin.py .gitattributes; git commit -qm bin
python3 "$RV" prepare | grep -q "AWS access key ID at bin.py" && ok || bad "the binary attribute hid a key from the scan"
git rm -q bin.py .gitattributes; git commit -qm unbin

# --- TEST-2 / RES-2: a scan out of time falls back to HEAD, says so, and mark won't pass over it
printf 'KEY = "%s"\n' "${k}M5NB4VC3XZ2LK1JH" > head.py
git add head.py; git commit -qm head
python3 - "$RW/scripts" > "$T/ctx" 2>"$T/err" <<'EOF' || bad "prepare with no history budget failed: $(cat "$T/err")"
import sys; sys.path.insert(0, sys.argv[1]); import ravenwatch as r
r.HISTORY_SCAN_SECONDS = 0
sys.argv = ["ravenwatch.py", "prepare"]
sys.exit(r.main())
EOF
grep -q "history scan incomplete" "$T/ctx" && ok || bad "no warning for a scan out of time: $(cat "$T/ctx")"
grep -q "AWS access key ID at head.py" "$T/ctx" && ok || bad "the fallback scan of HEAD missed a key"
grep -q "^- clean" "$T/ctx" && bad "a scan out of time was reported clean" || ok
python3 "$RV" mark --verdict pass --secrets-cleared >/dev/null 2>"$T/err" && bad "mark passed over a scan out of time" || ok
grep -q "ran out of time" "$T/err" && ok || bad "incomplete-scan refusal unclear: $(cat "$T/err")"
python3 "$RV" mark --verdict warn --secrets-cleared --scan-incomplete-accepted >/dev/null 2>"$T/err" && ok \
  || bad "mark refused the owner's --scan-incomplete-accepted: $(cat "$T/err")"
grep -q "scan_incomplete=history+accepted" "$(git rev-parse --git-dir)/ravenwatch/verdicts/$(git rev-parse HEAD)" && ok \
  || bad "verdict doesn't record the incomplete scan"
# git waits on stdin (still open) until the timer kills it at the deadline: a cut, not a failure.
sleep 5 | python3 -c '
import sys, time; sys.path.insert(0, sys.argv[1]); import ravenwatch as r
state = {"cut": False}
list(r.git_lines("hash-object", "--stdin", deadline=time.monotonic() + 0.3, state=state))
sys.exit(0 if state["cut"] else print(state) or 1)' "$RW/scripts" && ok || bad "git_lines killed at its deadline"
git rm -q head.py; git commit -qm unhead

echo "round12: passed=$pass failed=$failn"
[ "$failn" -eq 0 ]
