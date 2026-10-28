#!/bin/sh
# Regression tests for review round 10: option values that are patterns, `cd` behind builtin/command/if/
# time/!, popd and subshell tracking, the glob cap and the guard's own time budget; template-looking secret
# values, distinct keys with the same prefix, and untracked files git is configured to hide.
# Pushes only to throwaway bare remotes under $T.
set -u
RW=$(cd "$(dirname "$0")/.." && pwd)
T=$(mktemp -d "${TMPDIR:-/tmp}/rwtest10.XXXXXX")
# Test a private copy of the plugin, so the results never depend on this checkout's state.
mkdir -p "$T/plugin" && cp -R "$RW/scripts" "$RW/hooks" "$T/plugin/"
RW="$T/plugin"
G="$RW/hooks/guard_push.py"
unset RAVENWATCH_DISABLE RAVENWATCH_CHECKS_RUNNING XDG_CONFIG_HOME GIT_DIR GIT_WORK_TREE CDPATH
export GIT_CONFIG_NOSYSTEM=1
trap 'rm -rf "$T"' EXIT
export HOME="$T/home"; mkdir -p "$HOME"
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
RV="$RW/scripts/ravenwatch.py"
python3 "$RV" install-hook >/dev/null

pass=0; failn=0
ok() { pass=$((pass+1)); }
bad() { failn=$((failn+1)); echo "FAIL: $*"; }
tool_gate() { # expect cwd json-tool-input tool-name; prints the reason into $out
  out=$(python3 -c 'import json,sys; print(json.dumps({"tool_name":sys.argv[3],"cwd":sys.argv[1],"tool_input":json.loads(sys.argv[2])}))' "$2" "$3" "$4" | python3 "$G")
  [ -n "$out" ] && got=deny || got=allow
  [ "$got" = "$1" ] && ok || bad "$4 expected $1 got $got: $3 $out"
}
bash_gate() { # expect cwd command [text the reason must contain]
  cmd=$(python3 -c 'import json,sys; print(json.dumps({"command":sys.argv[1]}))' "$3")
  tool_gate "$1" "$2" "$cmd" Bash
  if [ $# -ge 4 ] && [ "$1" = deny ]; then
    # Since 0.5.0 a command that isn't plain gets one refusal for every reason: it counts for any of them.
    echo "$out" | grep -q -e "$4" -e "must be plain" && ok || bad "reason for '$3' lacks '$4': $out"
  fi
}
rwq() { python3 "$RV" "$@" >/dev/null 2>&1; }
runs_dir() { echo "$(git rev-parse --git-path ravenwatch/runs)"; }
latest_run() { cat "$(runs_dir)/latest"; }
approve() {
  sha=$(python3 "$RV" trust-brief --private 2>&1 | sed -n 's/^sha256: //p')
  rwq trust-brief --private --approve "$sha" || bad "approve failed"
}
commit() { echo "$1" > "$1"; git add "$1"; git commit -qm "$1"; }

# --- BUG-G1: values of exclude/include options are patterns, not paths
bash_gate allow "$R" "grep -rn --exclude-dir=.git TODO ."
bash_gate allow "$R" "tar --exclude=.git -czf $T/out.tgz ."
bash_gate allow "$R" "du -sh --exclude=.git ."
bash_gate deny  "$R" "cp --target-directory=$RW/hooks /tmp/x" "installed ravenwatch plugin"

# --- SEC-G1: `cd` behind builtin/command/if/time/! is followed too; `eval cd` makes the directory unknown
bash_gate deny  "$R" "builtin cd /tmp && git $P -q origin main" "not a git repository"
bash_gate deny  "$R" "command cd /tmp && git $P -q origin main" "not a git repository"
bash_gate deny  "$R" "if cd /tmp; then :; fi; git $P -q origin main" "not a git repository"
bash_gate deny  "$R" "time cd /tmp && git $P -q origin main" "not a git repository"
bash_gate deny  "$R" "! cd /tmp; git $P -q origin main" "not a git repository"
bash_gate deny  "$R" "builtin cd $T && cp /dev/null plugin/hooks/guard_push.py" "installed ravenwatch plugin"
bash_gate deny  "$R" "eval cd /tmp && printf x > ravenwatch/status" "can't tell which directory"
bash_gate allow "$R" "command -v git && git status"

# --- TEST-1 (round 9): only the popd and subshell tracking can bring the start directory back here
bash_gate deny  "$T" "pushd /tmp && popd && cp /dev/null plugin/hooks/guard_push.py" "installed ravenwatch plugin"
bash_gate deny  "$T" "(cd /tmp && :) && cp /dev/null plugin/hooks/guard_push.py" "installed ravenwatch plugin"
bash_gate allow "$T" "(cd /tmp && :) && ls"

# --- glob cap: a pattern with too many matches can't be checked
mkdir -p "$T/many"; (cd "$T/many" && python3 -c 'import os; [open("f%d" % i, "w").close() for i in range(2100)]')
bash_gate deny  "$R" "cp /dev/null $T/many/*" "matches more than"
bash_gate allow "$R" "ls $T/many/f1*"

# --- BUG-G2 / RES-1: out of time, the guard decides itself (no exception a library can swallow)
slow() { # command → what the alarm handler prints
  python3 -c 'import sys; sys.path.insert(0, sys.argv[1]); import guard_push as g
g._CURRENT.update(command=sys.argv[2], target=""); g._too_slow(14, None)' "$RW/hooks" "$1"
}
slow "tee /*/*/*/zz /U*/*/r*/*/.g?t/h??ks/pre-$P" | grep -q '"deny"' && ok || bad "timeout let a glob write through"
slow "git $P origin main" | grep -q '"deny"' && ok || bad "timeout let a push through"
[ -z "$(slow "ls")" ] && ok || bad "timeout refused a harmless command"
grep -q "raise TimeoutError" "$G" && bad "the alarm still raises a swallowable exception" || ok

# --- SEC-H1: template-looking values count as placeholders only when they look like names
python3 - "$RW/scripts" <<'EOF' && ok || bad "placeholder rules for template-looking values"
import sys; sys.path.insert(0, sys.argv[1]); import ravenwatch as r
def ph(line, pattern):
    return [h[4] for h in r.scan_added_lines(["+++ b/x.py", "@@ -0,0 +1 @@", "+" + line]) if h[2] == pattern]
G, U = "Generic secret assignment", "Credentials in URL"
# Values are built from pieces so this file never holds a credential-looking literal.
pw, sec, fer = "pass" + "word", "$uper" + "Secret2024", "Testa" + "rossa2024"
real = [ph(f'{pw} = "{sec}"', G), ph(f'u = "postgres://app:{sec}@db.prod/x"', U),
        ph('api_secret = "{Hunter2' + 'Real99}"', G), ph(f'{pw} = "{fer}"', G)]
fake = [ph('u = "https://x:$GITHUB_TOKEN@h/x"', U), ph('u = f"https://x:{password}@h/x"', U),
        ph("tok" + 'en = "mock.' + 'abcdefghijklmnopqrstuvwxyz"', G)]
sys.exit(0 if all(v == [False] for v in real) and all(v == [True] for v in fake) else print(real, fake) or 1)
EOF

# --- SEC-H2: two different keys with the same prefix in one file are both listed
git checkout -q -b keys
a=ghp_; b=ghp_
printf 'A = "%s"\nB = "%s"\n' "${a}Qz81kq0PLm55bb7RtyUiWq90XcVb34NmLk12" "${b}Pw42LmZx77Qa1RtYuI0opAsDf9Gh8Jk7Lz65" > tokens.py
git add tokens.py; git commit -qm tokens
[ "$(python3 "$RV" prepare | grep -c 'GitHub token at tokens.py')" -eq 2 ] && ok || bad "two different tokens listed once"
git checkout -q main; git branch -q -D keys

# --- RES-2: untracked files count even when git is configured to hide them
printf -- '---\nchecks:\n  - name: gen\n    run: echo x > made.txt\n---\n# P\n' > .ravenwatch.md
approve
git config status.showUntrackedFiles no
commit c1; rwq prepare; run=$(latest_run)
echo x > stray.txt
python3 "$RV" checks --run "$run" 2>&1 | grep -q "stray.txt" && ok || bad "hidden untracked file not seen before checks"
rm -f stray.txt
python3 "$RV" checks --run "$run" 2>&1 | grep -q "left files behind: made.txt" && ok || bad "hidden untracked output not seen after a check"
rm -f made.txt
git config --unset status.showUntrackedFiles

echo "round10: passed=$pass failed=$failn"
[ "$failn" -eq 0 ]
