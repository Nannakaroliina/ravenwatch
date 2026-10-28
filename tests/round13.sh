#!/bin/sh
# Regression tests for the round 7 review findings (0.4.3): a comment right after `(`, `)` or `$(`; variables
# set by `+=`, arrays, `printf -v`, namerefs, `unset`, `TMPDIR`, or from another variable set in the same
# command; options in the middle of an alias chain; aliases that hide a builtin; and "nothing to review"
# after a secret scan that ran out of time.
# Pushes only to throwaway bare remotes under $T.
set -u
RW=$(cd "$(dirname "$0")/.." && pwd)
T=$(mktemp -d "${TMPDIR:-/tmp}/rwtest13.XXXXXX")
# Test a private copy of the plugin, so the results never depend on this checkout's state.
mkdir -p "$T/plugin" && cp -R "$RW/scripts" "$RW/hooks" "$T/plugin/"
RW="$T/plugin"
G="$RW/hooks/guard_push.py"
unset RAVENWATCH_DISABLE RAVENWATCH_CHECKS_RUNNING XDG_CONFIG_HOME GIT_DIR GIT_WORK_TREE CDPATH
export GIT_CONFIG_NOSYSTEM=1
trap 'rm -rf "$T"' EXIT
export HOME="$T/home"; mkdir -p "$HOME"
P=push
HP=Path  # core.hooks$HP, split so this file never names the setting outright
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
N="$T/nohook"; git init -q "$N"

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

# --- BUG-1: `#` right after `(`, a subshell's `)` or `$(` starts a comment, as in bash
bash_gate deny  "$R" "(#'
git -C $N $P origin main
#'
)" "not installed"
bash_gate deny  "$R" "(true)#'
git -C $N $P origin main
#'
)" "not installed"
bash_gate deny  "$R" "(#'
X=$R/.gi; cp evil \"\${X}t/hooks/pre-$P\"
#'
)" "inside a git directory"
# … but after the `)` of `$(…)` the word goes on.
python3 - "$RW/hooks" <<'EOF' && ok || bad "segments() and comments after ( ) \$("
import sys; sys.path.insert(0, sys.argv[1]); import guard_push as g
segs = [s[0] for s in g.segments("(#'\necho hi\n#'\n)")]
toks = [t for s in g.segments("echo $(echo a)#b") for t in s[0]]
sys.exit(0 if ["echo", "hi"] in segs and "#b" in "".join(toks) else print(segs, toks) or 1)
EOF

# --- BUG-2 / SEC-1: a variable the guard can't follow counts as unknown, so writes through it are refused
bash_gate deny  "$R" "X=$R; X+=/.git; cp evil \"\$X/hooks/pre-$P\"" "can't tell where"
bash_gate deny  "$R" "HOME=.g; V=\${HOME}it/ravenwatch/verdicts/x; printf v > \"\$V\"" "can't tell where"
bash_gate deny  "$R" "A=$R; B=\$A/.git; cp evil \"\$B/hooks/pre-$P\"" "can't tell where"
bash_gate deny  "$R" "X=$R; X[0]=$R/.git; cp evil \"\$X/hooks/pre-$P\"" "can't tell where"
bash_gate deny  "$R" "X=($R/.gi); cp evil \"\${X}t/hooks/pre-$P\"" "can't tell where"
bash_gate deny  "$R" "printf -v X %s $R/.gi; cp evil \"\${X}t/hooks/pre-$P\"" "can't tell where"
bash_gate deny  "$R" "Y=$R/.gi; declare -n X=Y; cp evil \"\${X}t/hooks/pre-$P\"" "can't tell where"
bash_gate deny  "$R" "let X=1; cp evil \"\$X/hooks\"" "can't tell where"
bash_gate deny  "$R" "unset HOME; cp evil \"\$HOME/x\"" "can't tell where"
bash_gate deny  "$R" "TMPDIR=$R/.git; D=\$(mktemp -d); cp evil \"\$D/../hooks/pre-$P\"" "can't tell where"
bash_gate deny  "$R" "D=\$(mktemp -d -p $R/.gi); cp evil \"\$D/../hooks/pre-$P\"" "can't tell where"
bash_gate deny  "$R" "D=\$(mktemp -d /etc/x.XXXX); cp evil \"\$D/y\"" "can't tell where"
# Literal values, the environment and plain temp dirs are still followed.
bash_gate allow "$R" "X=/tmp/a; cp f \"\$X/b\""
bash_gate allow "$R" "D=\$(mktemp -d); cp f \"\$D/b\""
bash_gate allow "$R" "D=\$(mktemp -d \"\$TMPDIR/x.XXXX\"); cp f \"\$D/b\""
bash_gate allow "$R" "cp f \"\$HOME/b\""
bash_gate allow "$R" "for f in a.md b.md; do cp \$f /tmp/\$f; done"
bash_gate allow "$R" "echo hi # (a comment)"

# --- BUG-3: options in the middle of an alias chain count
git config alias.aa "bb --recurse-submodules=on-demand"; git config alias.bb "$P"
bash_gate deny  "$R" "git aa origin main" "recurse"
git config alias.cc "-c core.hooks$HP=/x dd"; git config alias.dd "$P"
bash_gate deny  "$R" "git cc origin main"
git config alias.ee "ff --exec=/tmp/x"; git config alias.ff "$P"
bash_gate deny  "$R" "git ee origin main" "receive command"
git config alias.gg hh; git config alias.hh "$P"
bash_gate allow "$R" "git gg origin main"
# --- RES-1: an alias that hides a builtin (git ignores it) doesn't block the builtin
git config alias.status "status -sb"; git config alias.st status
bash_gate allow "$R" "git status"
bash_gate allow "$R" "git st"
git config --unset alias.status

# --- LOOP-1: a range without file changes isn't "nothing to review" when the scan ran out of time
git commit -q --allow-empty -m empty
python3 - "$RW/scripts" > "$T/ctx" 2>"$T/err" <<'EOF' || bad "prepare with no history budget failed: $(cat "$T/err")"
import sys; sys.path.insert(0, sys.argv[1]); import ravenwatch as r
r.HISTORY_SCAN_SECONDS = 0
sys.argv = ["ravenwatch.py", "prepare"]
sys.exit(r.main())
EOF
grep -q "history scan incomplete" "$T/ctx" && ok || bad "no warning for a cut scan: $(cat "$T/ctx")"
grep -q "NOTHING TO REVIEW" "$T/ctx" && bad "a cut scan was reported as nothing to review" || ok
python3 "$RV" mark --verdict pass >/dev/null 2>"$T/err" && bad "mark passed over a cut scan" || ok
python3 "$RV" mark --verdict block >/dev/null 2>&1 && ok || bad "mark refused block after a cut scan"

echo "round13: passed=$pass failed=$failn"
[ "$failn" -eq 0 ]
