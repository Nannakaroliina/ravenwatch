#!/bin/sh
# Regression tests for the round 8 review findings and the 0.5.0 guard: only plain commands are parsed (a `#`
# after a backtick or `<(…)`, zsh glob qualifiers and `=(…)` on the helper can no longer hide anything);
# commands with other shell features pass only when they can't touch git, write or run code; heredocs piped
# into a shell; abbreviated or repeated `mark` options; nested infra folders; and the guard failing closed
# when its checks crash.
# Pushes only to throwaway bare remotes under $T.
set -u
RW=$(cd "$(dirname "$0")/.." && pwd)
T=$(mktemp -d "${TMPDIR:-/tmp}/rwtest14.XXXXXX")
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

# --- round 8 BUG-1 / BUG-2: a `#` after a backtick or after `<(…)`/`X=(…)` can't hide the rest of the line
bash_gate deny  "$R" "echo \`#\`; cd .git && cd ravenwatch && printf 'verdict=pass' > status" "must be plain"
bash_gate deny  "$R" "true <(:)#x; cd .git && cd ravenwatch && printf 'verdict=pass' > status" "must be plain"
bash_gate deny  "$R" "X=(a)#b; cd .git && cd ravenwatch && printf x > status" "must be plain"
# --- round 8 SEC-1: the helper gets no shortcut; zsh glob qualifiers and =(…) are not plain
bash_gate deny  "$R" "python3 $RV prepare *(e:'touch /tmp/rw14':)" "must be plain"
bash_gate deny  "$R" "python3 $RV prepare =(touch /tmp/rw14)" "must be plain"
bash_gate allow "$R" "python3 $RV status"
bash_gate allow "$R" "python3 $RV mark --verdict block --run x --report $R/.git/ravenwatch/reports/r.md"
bash_gate deny  "$R" "python3 $RV mark --verdict block --run x --report $R/.git/ravenwatch/reports/../status"

# --- 0.5.0: commands that aren't plain pass only when they can't touch git, write or run code
bash_gate allow "$R" 'echo $HOME'
bash_gate allow "$R" 'x=$(date); echo "$x"'
bash_gate allow "$R" 'for f in *.md; do echo "$f"; done'
bash_gate allow "$R" 'docker '$P' "$IMAGE"'
bash_gate allow "$R" 'curl -s -H "Authorization: Bearer $TOKEN" https://example.com/api'
bash_gate deny  "$R" 'curl -so "$F" https://example.com' "must be plain"
bash_gate deny  "$R" 'curl $OPTS https://example.com' "must be plain"
bash_gate deny  "$R" 'W=c; W=${W}p; $W evil x' "must be plain"
bash_gate deny  "$R" '`printf c; printf p` evil x' "must be plain"
bash_gate deny  "$R" 'git log "$(git merge-base main HEAD)"..HEAD' "must be plain"
bash_gate deny  "$R" 'cp e .gi{t,x}/hooks/pre-'$P "must be plain"
bash_gate deny  "$R" "sh -c 'X=.gi; cp e \${X}t/hooks/pre-$P'" "must be plain"
bash_gate deny  "$R" "eval 'X=.gi; cp e \${X}t/hooks/pre-$P'" "must be plain"
# Plain commands keep working, comments of plain words included.
bash_gate allow "$R" "# publish the branch
git $P origin main"
bash_gate allow "$R" "echo a#b > /tmp/rw14.txt"
bash_gate allow "$R" "find . -name '*.py' -exec grep -l x {} +"
bash_gate allow "$R" "grep -rn '$P\$' . | awk -F: '{print \$1}'"
bash_gate allow "$R" "set -e && git $P origin main"
bash_gate allow "$R" "git commit -m \"\$(cat <<'EOF'
Enable $P, hash \$things and \`ticks\`

Co-Authored-By: t <t@example.com>
EOF
)\""
bash_gate allow "$R" "cat > /tmp/rw14-notes.txt <<EOF
plain text, no expansions
EOF"
# A push can't come with shell changes, or from text a shell or interpreter reads.
bash_gate deny  "$R" "export HOME=/tmp/x; git $P origin main" "change the shell"
bash_gate deny  "$R" "HOME=/tmp/x git $P origin main" "change the shell"
bash_gate deny  "$R" "cat <<EOF | sh
git $P origin main
EOF" "from a heredoc"
bash_gate deny  "$R" "printf 'git $P origin main' | sh" "piped into it"
bash_gate deny  "$R" "printf '.gi%%st/hoo%%sks/pre-$P' t k | xargs touch" "feeds paths"
bash_gate deny  "$R" "find . -name pre-$P -exec cp e {} ';'" "runs \`cp\`"
bash_gate deny  "$R" "find . -name x -delete" "deletes"

# --- round 8 LOOP-1: mark takes no abbreviated options and no repeated ones
python3 "$RV" mark --verdict block --sc >/dev/null 2>"$T/err" && bad "mark took --sc as an abbreviation" || ok
grep -q "unrecognized arguments: --sc" "$T/err" && ok || bad "abbreviation refusal unclear: $(cat "$T/err")"
python3 "$RV" mark --verdict block --v pass >/dev/null 2>&1 && bad "mark took --v as --verdict" || ok
python3 "$RV" mark --verdict block --note x --verdict pass >/dev/null 2>"$T/err" && bad "mark took a second --verdict" || ok
grep -q "more than once" "$T/err" && ok || bad "repeated-option refusal unclear: $(cat "$T/err")"

# --- round 8 IMP-2: infrastructure folders count at any depth
mkdir -p packages/api/infra; echo "export const q = 1" > packages/api/infra/queue.ts
git add packages; git commit -qm infra
python3 "$RV" prepare | grep -q "infrastructure as code" && ok || bad "nested infra/ folder gave no infra signal"

# --- round 8 TEST-1: when the checks crash, writes and pushes are refused, harmless commands are not
python3 - "$RW/hooks" <<'EOF' && ok || bad "the guard doesn't fail closed on a crash"
import io, json, sys
sys.path.insert(0, sys.argv[1])
import guard_push as g
def boom(*a, **k):
    raise ZeroDivisionError("boom")
g.check_bash = boom
def run(cmd):
    sys.stdin, out = io.StringIO(json.dumps({"tool_name": "Bash", "cwd": "/tmp", "tool_input": {"command": cmd}})), io.StringIO()
    real, sys.stdout = sys.stdout, out
    try:
        g.main()
    except SystemExit:
        pass
    finally:
        sys.stdout = real
    return out.getvalue()
denied = ["cp a b", "echo x > f", "curl -o x https://e.com", "rm $X", "git " + "pu" + "sh"]
allowed = ["ls", "echo hi", "npm test"]
bad = [c for c in denied if "internal error" not in run(c)] + [c for c in allowed if run(c)]
sys.exit(print(bad) or 1 if bad else 0)
EOF

echo "round14: passed=$pass failed=$failn"
[ "$failn" -eq 0 ]
