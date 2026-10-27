#!/bin/sh
# Tests for the redesigned gate. Pushes only to a throwaway bare remote under $T.
set -u
export HOME=$(mktemp -d "${TMPDIR:-/tmp}/rwhome.XXXXXX")
export GIT_CONFIG_NOSYSTEM=1
RW=$(cd "$(dirname "$0")/.." && pwd)
G="$RW/hooks/guard_push.py"
T=$(mktemp -d "${TMPDIR:-/tmp}/rwtest2.XXXXXX")
# Test a private copy of the plugin, so the results never depend on this checkout's state.
mkdir -p "$T/plugin" && cp -R "$RW/scripts" "$RW/hooks" "$T/plugin/"
RW="$T/plugin"
G="$RW/hooks/guard_push.py"
unset RAVENWATCH_DISABLE RAVENWATCH_CHECKS_RUNNING XDG_CONFIG_HOME GIT_DIR GIT_WORK_TREE
P=push            # keeps the literal word out of this file's own invocation
HP="hooks""Path"
cd "$T"
git init -q --bare -b main remote.git
git init -q --bare other.git
git init -q -b main r && cd r
git config user.email t@example.com; git config user.name t
mkdir sub; echo a > sub/a; git add .; git commit -qm a
git remote add origin "$T/remote.git"
git $P -q -u origin main
R="$T/r"
git init -q -b main "$T/nohook"

pass=0; failn=0
ok() { pass=$((pass+1)); }
bad() { failn=$((failn+1)); echo "FAIL: $*"; }
bash_gate() { # expect cwd command
  out=$(python3 -c 'import json,sys; print(json.dumps({"tool_name":"Bash","cwd":sys.argv[1],"tool_input":{"command":sys.argv[2]}}))' "$2" "$3" | python3 "$G")
  [ -n "$out" ] && got=deny || got=allow
  [ "$got" = "$1" ] && ok || bad "bash expected $1 got $got: $3 $out"
}
write_gate() { # expect path content
  out=$(python3 -c 'import json,sys; print(json.dumps({"tool_name":"Write","cwd":sys.argv[1],"tool_input":{"file_path":sys.argv[2],"content":sys.argv[3]}}))' "$R" "$2" "$3" | python3 "$G")
  [ -n "$out" ] && got=deny || got=allow
  [ "$got" = "$1" ] && ok || bad "write expected $1 got $got: $2 $out"
}
rw() { python3 "$RW/scripts/ravenwatch.py" "$@" >/dev/null; }
push_ok()   { git $P -q "$@" 2>/dev/null && ok || bad "push should succeed: $*"; }
push_fail() {
  if git $P -q "$@" 2>"$T/err"; then bad "push should be blocked: $*"
  elif grep -q "ravenwatch:" "$T/err"; then ok
  else bad "push failed but not because of ravenwatch: $*"; cat "$T/err"; fi
}

# --- Claude-side guard, hook not installed
bash_gate deny  "$R" "git $P"
bash_gate deny  "$R" "git pu''sh"
bash_gate allow "$R" "git status && git log --oneline"
bash_gate allow "$R" "ls hooks/guard_${P}.py"
git config alias.p "$P"
bash_gate deny  "$R" "git p origin main"
git config --unset alias.p

rw install-hook
[ "$(python3 "$RW/scripts/ravenwatch.py" status 2>/dev/null | head -1)" = "git pre-push hook: installed" ] && ok || bad "status hook state"

# --- Claude-side guard, hook installed
bash_gate allow "$R" "git $P"
bash_gate allow "$R" "git $P origin main 2>&1 | tail -5"
bash_gate allow "$R" "git commit -am x && git $P"
bash_gate allow "$R" "$(printf 'git commit -m "$(cat <<%sEOF%s\nGate git %s behind review\nEOF\n)"' "'" "'" "$P")"
bash_gate allow "$R" "rg -n \"git $P\" README.md"
bash_gate allow "$R" "git config --get core.$HP"
bash_gate deny  "$R" "git $P --no-verify"
bash_gate deny  "$R" "git $P --no-ver"
bash_gate allow "$R" "git $P --no-verbose"
bash_gate deny  "$R" "git -c core.$HP=/dev/null $P"
bash_gate deny  "$R" "git config core.$HP /tmp/x"
bash_gate deny  "$R" "git config --global core.$HP /tmp/x"
bash_gate deny  "$R" "GIT_CONFIG_COUNT=1 GIT_CONFIG_KEY_0=core.x GIT_CONFIG_VALUE_0=y git $P"
bash_gate deny  "$R" "git --config-env=core.x=V $P"
bash_gate deny  "$R" "git send-pack origin main"
bash_gate deny  "$R" "RAVENWATCH_DISABLE=1 git $P"
bash_gate deny  "$R" "git --git-dir=/x/.git $P"
bash_gate deny  "$R" "printf x > .git/ravenwatch/status"
bash_gate deny  "$R" "cp evil .git/hooks/pre-$P"
bash_gate deny  "$R" "cd .git && cd hooks && rm pre-$P"
bash_gate deny  "$R" "cat .git/config"
bash_gate deny  "$R" "cd $T/nohook && git $P"
bash_gate deny  "$R" 'cd $D && git push'
bash_gate allow "$R" "python3 $RW/scripts/ravenwatch.py mark --verdict pass --report $R/.git/ravenwatch/reports/r.md"
bash_gate deny  "$R" "python3 $RW/scripts/ravenwatch.py status; echo x > .git/ravenwatch/status"
write_gate deny  ".git/ravenwatch/status" "verdict=pass"
write_gate allow ".git/ravenwatch/reports/r.md" "report"
write_gate deny  ".git/hooks/pre-$P" "exit 0"
write_gate deny  "$HOME/.gitconfig-test" "[core]
	$HP = /tmp/x"
write_gate allow "README.md" "set core.$HP if you use husky"
ln -s .git/hooks/pre-$P link; write_gate deny "link" "exit 0"; rm link

# --- git hook: the authoritative check
echo b > b; git add b; git commit -qm b
push_fail origin main                                  # unreviewed
rw prepare; rw mark --verdict pass
push_ok origin main

echo c > c; git add c; git commit -qm c
git remote add s . && git fetch -q s                   # local refs claim everything is "on a remote"
push_fail origin main
git remote remove s

push_fail -n --no-dry-run origin main                  # real push in disguise
push_fail origin :                                     # matching refspec
rw prepare; rw mark --verdict block
push_fail origin main
rw mark --verdict accepted --note test
push_ok origin main

echo d > d; git add d; git commit -qm d
rw prepare --since-last; rw mark --verdict pass        # chains from the accepted review
push_ok origin main

git checkout -q -b fork; echo f > f; git add f; git commit -qm f
git $P -q --no-verify "$T/other.git" fork               # commits exist on ANOTHER remote only
git checkout -q main
push_fail origin fork                                  # still new to origin -> needs review

echo g > g; git add g; git commit -qm g; echo h > h; git add h; git commit -qm h
rw prepare --base HEAD~1; rw mark --verdict pass       # too narrow: g unreviewed
push_fail origin main
rw prepare; rw mark --verdict pass
push_ok origin main
push_ok origin main:copy                               # nothing new to the remote
git tag v1; push_ok origin v1

# prepare must not leave a markable run if it never finished
before=$(cat .git/ravenwatch/runs/latest)
echo i > i; git add i; git commit -qm i
mkdir .git/ravenwatch/runs/broken
python3 "$RW/scripts/ravenwatch.py" mark --verdict pass --run broken >/dev/null 2>&1 && bad "mark accepted unfinished run" || ok
[ "$(cat .git/ravenwatch/runs/latest)" = "$before" ] && ok || bad "latest moved"

python3 "$RW/scripts/ravenwatch.py" install-hook --uninstall >/dev/null
[ ! -e .git/hooks/pre-$P ] && ok || bad "uninstall"

echo "gate_core: passed=$pass failed=$failn"
rm -rf "$T" "$HOME"
[ "$failn" -eq 0 ]
