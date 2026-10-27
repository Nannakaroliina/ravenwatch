#!/bin/sh
# ravenwatch gate_guard: round-5 regression tests. Pushes only to throwaway bare remotes under $T.
set -u
export HOME=$(mktemp -d "${TMPDIR:-/tmp}/rwhome.XXXXXX")
export GIT_CONFIG_NOSYSTEM=1
RW=$(cd "$(dirname "$0")/.." && pwd)
G="$RW/hooks/guard_push.py"
T=$(mktemp -d "${TMPDIR:-/tmp}/rwtest5.XXXXXX")
# Test a private copy of the plugin, so the results never depend on this checkout's state.
mkdir -p "$T/plugin" && cp -R "$RW/scripts" "$RW/hooks" "$T/plugin/"
RW="$T/plugin"
G="$RW/hooks/guard_push.py"
unset RAVENWATCH_DISABLE RAVENWATCH_CHECKS_RUNNING XDG_CONFIG_HOME GIT_DIR GIT_WORK_TREE
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
mkdir -p "$T/nohook" && git init -q "$T/nohook"

pass=0; failn=0
ok() { pass=$((pass+1)); }
bad() { failn=$((failn+1)); echo "FAIL: $*"; }
bash_gate() { # expect cwd command
  out=$(python3 -c 'import json,sys; print(json.dumps({"tool_name":"Bash","cwd":sys.argv[1],"tool_input":{"command":sys.argv[2]}}))' "$2" "$3" | python3 "$G")
  [ -n "$out" ] && got=deny || got=allow
  [ "$got" = "$1" ] && ok || bad "bash expected $1 got $got: $3 $out"
}
write_gate() { # expect cwd path content
  out=$(python3 -c 'import json,sys; print(json.dumps({"tool_name":"Write","cwd":sys.argv[1],"tool_input":{"file_path":sys.argv[2],"content":sys.argv[3]}}))' "$2" "$3" "$4" | python3 "$G")
  [ -n "$out" ] && got=deny || got=allow
  [ "$got" = "$1" ] && ok || bad "write expected $1 got $got: $3 $out"
}
rw() { python3 "$RW/scripts/ravenwatch.py" "$@" >/dev/null; }
push_ok()   { git $P -q "$@" 2>"$T/err" && ok || { bad "push should succeed: $*"; cat "$T/err"; }; }
push_fail() {
  if git $P -q "$@" 2>"$T/err"; then bad "push should be blocked: $*"
  elif grep -q "ravenwatch:" "$T/err"; then ok
  else bad "push failed but not because of ravenwatch: $*"; cat "$T/err"; fi
}

# --- SEC-1 / LOOP-1: verdict state reached through other paths
bash_gate  deny  "$R" "mv $D dotgit"
bash_gate  deny  "$R" "git init --separate-git-dir=/tmp/g"
bash_gate  deny  "$R" "cp -r $D /tmp/copy"
git init -q --separate-git-dir="$T/sep.git" "$T/sepwt"
write_gate deny  "$T/sepwt" "$T/sep.git/ravenwatch/status" "verdict=pass"
write_gate deny  "$T/sepwt" "$T/sep.git/hooks/pre-$P.local" "exit 0"
mkdir -p "$R/$D/modules/sub/ravenwatch"
write_gate deny  "$R" "$R/$D/modules/sub/ravenwatch/status" "verdict=pass"
write_gate deny  "$R" "$R/$D/modules/sub/config" "x"
write_gate allow "$R" "$R/$D/ravenwatch/reports/r.md" "report"
write_gate allow "$R" "$R/notes.md" "see [Remote setup](docs/remote.md)"
write_gate allow "$R" "$R/airflow.cfg" "$(printf '[core]\ndags_folder = x')"

# --- SEC-2: pushes hidden from the directory check
bash_gate deny "$R" "echo \`cd $T/nohook && git $P origin main\`"
bash_gate deny "$R" "find $T/nohook -maxdepth 0 -execdir git $P origin main \\;"
bash_gate deny "$R" "git submodule foreach git $P"
bash_gate deny "$R" "echo main | xargs git $P origin"
bash_gate deny "$R" "bash -c 'git $P'"

# --- LOOP-2 / SEC-3: abbreviations
bash_gate deny "$R" "git $P --recu=on-demand origin main"
bash_gate deny "$R" "git $P --e=x origin main"
bash_gate deny "$R" "git -c alias.x=$P x"
echo b > b; git add b; git commit -qm b                  # unreviewed
push_fail --e="git receive-pack $T/remote.git #" . main:newb
push_fail --recurse-sub=check origin main

# --- false denials that must be gone
bash_gate allow "$R" "git switch -c feat && git $P -u origin feat"
mkdir -p "$T/My Projects"; git clone -q "$T/remote.git" "$T/My Projects/app"
(cd "$T/My Projects/app" && python3 "$RW/scripts/ravenwatch.py" install-hook >/dev/null)
bash_gate allow "$R" "cd \"$T/My Projects/app\" && git $P"
bash_gate allow "$R" "pushd $R >/dev/null && git $P"
bash_gate allow "$R" "git $P origin main && cd .."
bash_gate allow "$R" "git $P origin main 2>&1 | tail -5"
bash_gate allow "$R" "$(printf 'git commit -m "$(cat <<%sEOF%s\nGate git %s behind review\nEOF\n)"' "'" "'" "$P")"
bash_gate allow "$R" "rg -n \"git $P\" README.md"
bash_gate allow "$R" "git stash $P -m wip"
bash_gate allow "$R" "git log --grep=$P --oneline"
H="$T/home"; mkdir "$H"; printf '[alias]\n\tundo = !git reset HEAD~1\n\tsub = submodule update --init --recurse-submodules\n' > "$H/.gitconfig"
HOME="$H" bash_gate allow "$R" "git commit -m \"undo the button change\""
HOME="$H" bash_gate allow "$R" "git log -- sub/file"

# --- BUG-2: reviewed push from a linked worktree to a local-path remote
git worktree add -q -b wtb "$T/wt"
(cd "$T/wt" && echo w > w && git add w && git commit -qm w &&
  python3 "$RW/scripts/ravenwatch.py" prepare >/dev/null && python3 "$RW/scripts/ravenwatch.py" mark --verdict pass >/dev/null &&
  git $P -q origin wtb 2>"$T/err") && ok || { bad "worktree push refused"; cat "$T/err"; }

# --- BUG-3: add/revert on a merged side branch is not "nothing to review"
git checkout -q -b side; echo evil > ci.yml; git add ci.yml; git commit -qm add; git rm -q ci.yml; git commit -qm rm
git checkout -q main; git merge -q --no-ff side -m merge
rw prepare --base HEAD~1
python3 "$RW/scripts/ravenwatch.py" prepare --base "$(git rev-parse HEAD^1)" | grep -q "NOTHING TO REVIEW" && bad "merged add/revert reported as nothing to review" || ok

echo "gate_guard: passed=$pass failed=$failn"
rm -rf "$T" "$HOME"
[ "$failn" -eq 0 ]
