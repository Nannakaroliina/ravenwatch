#!/bin/sh
# ravenwatch gate_history: round-4 regression tests. Pushes only to throwaway bare remotes under $T.
set -u
export HOME=$(mktemp -d "${TMPDIR:-/tmp}/rwhome.XXXXXX")
export GIT_CONFIG_NOSYSTEM=1
RW=$(cd "$(dirname "$0")/.." && pwd)
G="$RW/hooks/guard_push.py"
T=$(mktemp -d "${TMPDIR:-/tmp}/rwtest4.XXXXXX")
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
push_ok()   { git $P -q "$@" 2>"$T/err" && ok || { bad "push should succeed: $*"; cat "$T/err"; }; }
push_fail() {
  if git $P -q "$@" 2>"$T/err"; then bad "push should be blocked: $*"
  elif grep -q "ravenwatch:" "$T/err"; then ok
  else bad "push failed but not because of ravenwatch: $*"; cat "$T/err"; fi
}

# --- SEC-1: working inside .git, links into .git
bash_gate deny  "$R/$D" "printf x > ravenwatch/status"
bash_gate allow "$R/$D" "cd .."
bash_gate deny  "$R" "ln -s $D g"
bash_gate allow "$R" "ln -s src lib"

# --- SEC-2: abbreviated receive-pack / exec
echo b > b; git add b; git commit -qm b                 # unreviewed
push_fail --rece="git receive-pack $T/remote.git #" . main:newb
push_fail --ex="git receive-pack $T/remote.git #" . main:newb
bash_gate deny "$R" "git $P --ex=x origin main"
bash_gate deny "$R" "git $P --rec''eive-pack=x origin main"
[ -z "$(git ls-remote "$T/remote.git" refs/heads/newb)" ] && ok || bad "newb reached the remote"

# --- LOOP-3: uploadpack redirect
git config remote.origin.uploadpack "git-upload-pack . #"
push_fail origin HEAD:refs/heads/fresh
git config --unset remote.origin.uploadpack

# --- LOOP-2: a reverted intermediate commit can't be pushed as a tip
echo evil > ci.yml; git add ci.yml; git commit -qm add-ci; A=$(git rev-parse HEAD)
git rm -q ci.yml; git commit -qm revert-ci
ctx=$(python3 "$RW/scripts/ravenwatch.py" prepare)
echo "$ctx" | grep -q "NOTHING TO REVIEW" && bad "NOTHING TO REVIEW for add+revert" || ok
echo "$ctx" | grep -q "per-commit patches:" && ok || bad "no per-commit patches"
rw mark --verdict pass
push_fail origin "$A:refs/heads/ci-test"
push_ok origin main

# --- RES-1: teammate pushed main; we haven't fetched -> refusal says to fetch
git clone -q "$T/remote.git" "$T/mate"
(cd "$T/mate" && git config user.email m@x && git config user.name m && echo m > m && git add m && git commit -qm mate && git $P -q origin main)
git checkout -q -b feat; echo f > f; git add f; git commit -qm f
rw prepare; rw mark --verdict pass
git $P -q origin feat 2>"$T/err" && bad "push with unfetched remote should be refused" || {
  grep -q "git fetch" "$T/err" && ok || { bad "refusal does not suggest git fetch"; cat "$T/err"; }; }
git fetch -q origin
rw prepare; rw mark --verdict pass
push_ok origin feat

# --- BUG-3: upstream deleted on the remote (squash-merged), not pruned
git $P -q -u origin feat
(cd "$T/mate" && git $P -q origin :feat)
echo g > g; git add g; git commit -qm g
python3 "$RW/scripts/ravenwatch.py" prepare | grep -q "upstream branch no longer exists" && ok || bad "stale upstream not detected"
rw mark --verdict pass
push_ok origin feat
git checkout -q main

# --- LOOP-1: config files and aliases
write_gate deny  "$HOME/.gitconfig" "x"
write_gate allow "$R/x.cfg" "$(printf '[alias]\n\tp = %s --no-verify' "$P")"   # harmless unless included
write_gate allow "$R/y.cfg" "$(printf '[remote "origin"]\n\tuploadpack = x')"
write_gate allow "$R/notes.md" "use git $P to publish"
bash_gate deny  "$R" "git config include.path ../x.cfg"
bash_gate deny  "$R" "git config alias.p $P"
H="$T/home"; mkdir "$H"
printf '[alias]\n\tp = %s --no-verify\n\tq = !cd ../other && git %s\n\tr = %s\n' "$P" "$P" "$P" > "$H/.gitconfig"
HOME="$H" bash_gate deny  "$R" "git p origin main"
HOME="$H" bash_gate deny  "$R" "git q"
HOME="$H" bash_gate allow "$R" "git r origin main"
HOME="$H" bash_gate allow "$R" "git status"

# --- LOOP-4 / LOOP-5: zsh cd, CDPATH, -c on push
mkdir -p "$T/nohook" && git init -q "$T/nohook"
bash_gate deny "$R" "cd $R $T/nohook && git $P"
bash_gate deny "$R" "CDPATH=$T cd nohook && git $P"
bash_gate deny "$R" "git -c submodule.recurse=true $P origin main"
bash_gate deny "$R" "git -c user.name=x $P origin main"
bash_gate allow "$R" "git -c color.ui=never log --oneline"

# --- BUG-1: Husky v9 layout
git init -q "$T/h9"; mkdir -p "$T/h9/.husky/_"
printf '#!/usr/bin/env sh\n. "${0%%/*}/h"\n' > "$T/h9/.husky/_/pre-$P"; printf 'echo h\n' > "$T/h9/.husky/_/h"
(cd "$T/h9" && git config core.hooksPath .husky/_ &&
  python3 "$RW/scripts/ravenwatch.py" install-hook --hooks-path-ok >/dev/null 2>&1) && bad "installed over husky v9" || ok
[ -e "$T/h9/.husky/_/pre-$P.local" ] && bad "husky v9 stub was renamed" || ok

# --- BUG-4: SHA-256 repository
git init -q --bare --object-format=sha256 "$T/r256.git"
git init -q -b main --object-format=sha256 "$T/s" && cd "$T/s"
git config user.email t@example.com; git config user.name t
echo a > a; git add a; git commit -qm a
git remote add origin "$T/r256.git"
python3 "$RW/scripts/ravenwatch.py" install-hook >/dev/null
rw prepare && ok || bad "prepare failed in sha256 repo"
rw mark --verdict pass
push_ok origin main
push_ok origin main:other
push_ok origin :other

echo "gate_history: passed=$pass failed=$failn"
rm -rf "$T" "$HOME"
[ "$failn" -eq 0 ]
