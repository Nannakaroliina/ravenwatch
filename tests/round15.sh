#!/bin/sh
# Regression tests for the round 9 review findings (0.5.1): commands that aren't plain may only run read-only
# programs (globbed program names, unlisted writers and `.gi?` paths are refused); the commit-message
# heredoc ends where the shell ends it; partly quoted heredoc delimiters; zsh's `~X`; one notion of a
# program that writes; heredoc quote state; a bare `NAME=…; git push`; and prepare's hidden-file advice.
# Pushes only to throwaway bare remotes under $T.
set -u
RW=$(cd "$(dirname "$0")/.." && pwd)
T=$(mktemp -d "${TMPDIR:-/tmp}/rwtest15.XXXXXX")
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

# --- SEC-1, BUG-1, BUG-2, BUG-3, DES-1, RES-1: the guard's verdicts on commands, straight from check_bash
python3 - "$RW/hooks" "$R" <<'EOF' && ok || bad "guard verdicts (see above)"
import sys
sys.path.insert(0, sys.argv[1])
import guard_push as g
R, P = sys.argv[2], "pu" + "sh"
deny = {
    # SEC-1: no globbed program names, no unlisted writers, nothing but read-only programs when not plain
    "/bin/c? /tmp/v .gi?/ravenwatch/status $X": "isn't a known read-only command",
    "printf 'verdict=pass' \"$(date)\" | /usr/bin/te[e] .gi?/ravenwatch/status": "isn't a known read-only command",
    "uniq /tmp/v .gi?/ravenwatch/verdicts/abc $X": "output file",
    "sort -o .gi?/ravenwatch/status /tmp/v $X": "output file",
    "/bin/r? .gi?/hooks/pre-" + P + " $X": "isn't a known read-only command",
    "/usr/bin/gi[t] " + P + " origin main": "glob characters",
    "timeout 5 /usr/bin/gi[t] " + P + " origin main": "runs a push",
    "xargs /bin/c? < /tmp/list": "feeds paths",
    "find . -exec /bin/r? {} +": "on files the guard can't see",
    "docker " + P + " \"$IMAGE\"": "isn't a known read-only command",
    # BUG-1: the body ends at the first delimiter line; anything but `)` after it isn't plain
    "echo \"$(cat <<'EOF'\nx\nEOF\ncd .git && rm hooks/pre-" + P + "\nEOF\n)\"": "isn't a known read-only command",
    # BUG-2: a partly quoted delimiter is the whole word
    "cat <<\"E\"OF\nEOF\ngit " + P + " --recurse-submodules=on-demand\nE": "delimiter isn't quoted",
    "cat <<E'OF'\nEOF\ngit " + P + " --recurse-submodules=on-demand\nE": "delimiter isn't quoted",
    "cat <<EOF'X'\nEOFX\ngit " + P + " --recurse-submodules=on-demand\nEOF": "delimiter isn't quoted",
    # BUG-3: zsh reads ~X as the directory in $X
    "X=" + R + "/.git; cp /tmp/evil ~X/hooks/pre-" + P: "zsh reads",
    # DES-1: one notion of a writer
    "ed ~/.gitconfig": "git config file",
    "xargs sponge < /tmp/l": "feeds paths",
    "find . -exec shred {} +": "on files the guard can't see",
}
allow = [
    "ls -la", "echo $HOME", "x=$(date); echo \"$x\"", "for f in *.md; do echo \"$f\"; done",
    "while IFS= read -r f; do echo \"$f\"; done < /tmp/list", "if [ -f \"$HOME/x\" ]; then echo yes; fi",
    "curl -s -H \"Authorization: Bearer $TOKEN\" https://example.com/api", "echo $X 2>&1 | grep -c y",
    "sort f | uniq -c | sort -rn | head", "git log '@{u}..HEAD'", "cp ~/notes.txt /tmp/n.txt", "ls ~root",
    "git commit -m \"$(cat <<'EOF'\nFix it; don't " + P + " $x\n\nCo-Authored-By: t\nEOF\n)\"",
    # RES-1: an apostrophe in one heredoc body doesn't change how the next heredoc is read
    "cat > /tmp/rw15a.txt <<'EOF'\ndon't\nEOF\ncat > /tmp/rw15b.txt <<'EOF'\nx\nEOF",
]
bad = []
for cmd, why in deny.items():
    got = g.check_bash(cmd, R)
    if not got or why not in got:
        bad.append(("deny", cmd, got))
for cmd in allow:
    got = g.check_bash(cmd, R)
    if got:
        bad.append(("allow", cmd, got))
for b in bad:
    print(b)
sys.exit(1 if bad else 0)
EOF

# --- TEST-1: a push can't follow a bare assignment in the same command
bash_gate deny  "$R" "HOME=/tmp/x; git $P origin main" "set shell variables"
bash_gate deny  "$R" "XDG_CONFIG_HOME=/tmp/x && git $P origin main" "set shell variables"
bash_gate allow "$R" "X=1; echo hi"
bash_gate allow "$R" "git $P origin main"

# --- UX-1: prepare's refusal doesn't offer `accepted` (there is no run to record it on yet)
mkdir -p src; echo "x = 1" > src/u.py; git add src; git commit -qm u
git update-index --skip-worktree src/u.py; echo changed >> src/u.py
python3 "$RV" prepare >/dev/null 2>"$T/err" && bad "prepare ignored a changed, reviewed skip-worktree file" || ok
grep -q "accepted" "$T/err" && bad "prepare's refusal offers accepted: $(cat "$T/err")" || ok
grep -q "git stash" "$T/err" && ok || bad "prepare's refusal lacks the stash round trip: $(cat "$T/err")"
git update-index --no-skip-worktree src/u.py; git checkout -q -- src/u.py

echo "round15: passed=$pass failed=$failn"
[ "$failn" -eq 0 ]
