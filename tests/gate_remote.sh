#!/bin/sh
# ravenwatch gate_remote: round-3 regression tests. Pushes only to throwaway bare remotes under $T.
set -u
export HOME=$(mktemp -d "${TMPDIR:-/tmp}/rwhome.XXXXXX")
export GIT_CONFIG_NOSYSTEM=1
RW=$(cd "$(dirname "$0")/.." && pwd)
G="$RW/hooks/guard_push.py"
T=$(mktemp -d "${TMPDIR:-/tmp}/rwtest3.XXXXXX")
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

pass=0; failn=0
ok() { pass=$((pass+1)); }
bad() { failn=$((failn+1)); echo "FAIL: $*"; }
bash_gate() { # expect cwd command
  out=$(python3 -c 'import json,sys; print(json.dumps({"tool_name":"Bash","cwd":sys.argv[1],"tool_input":{"command":sys.argv[2]}}))' "$2" "$3" | python3 "$G")
  [ -n "$out" ] && got=deny || got=allow
  [ "$got" = "$1" ] && ok || bad "bash expected $1 got $got: $3 $out"
}
write_gate() { # expect path
  out=$(python3 -c 'import json,sys; print(json.dumps({"tool_name":"Write","cwd":sys.argv[1],"tool_input":{"file_path":sys.argv[2],"content":"x"}}))' "$R" "$2" | python3 "$G")
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

# --- BUG-1: remote has a branch commit we never fetched -> reviewed push still works
git clone -q "$T/remote.git" "$T/other"
(cd "$T/other" && git config user.email o@x && git config user.name o &&
  echo th > th && git add th && git commit -qm theirs && git $P -q origin HEAD:refs/heads/theirs)
echo b > b; git add b; git commit -qm b
rw prepare; rw mark --verdict pass
push_ok origin main

# --- LOOP-2: fast-forward to an outsider's PR commit; refs/pull doesn't count as published
(cd "$T/other" && git fetch -q origin main && git reset -q --hard origin/main &&
  echo pr > pr && git add pr && git commit -qm pr && git $P -q origin HEAD:refs/pull/1/head)
git fetch -q origin refs/pull/1/head && git merge -q --ff-only FETCH_HEAD
push_fail origin main
rw prepare; rw mark --verdict pass
push_ok origin main

# --- SEC-1: trees and blobs can't be pushed unreviewed
tree=$(git write-tree)
push_fail origin "$tree:refs/tags/tr"

# --- LOOP-1: the listed remote must be the push target
echo c > c; git add c; git commit -qm c              # unreviewed
push_fail --receive-pack="git receive-pack $T/remote.git #" . main:newb
git clone -q --mirror "$T/r" "$T/fullclone.git"      # has every commit
git config "url.$T/remote.git.pushInsteadOf" "$T/remote.git"
git config "url.$T/fullclone.git.insteadOf" "$T/remote.git"
push_fail origin main
git config --unset "url.$T/remote.git.pushInsteadOf"; git config --unset "url.$T/fullclone.git.insteadOf"
git config remote.origin.receivepack "git receive-pack $T/remote.git #"
push_fail origin main
git config --unset remote.origin.receivepack
[ "$(git ls-remote "$T/remote.git" refs/heads/newb)" = "" ] && ok || bad "newb reached the remote"

# --- normal new-branch push with a reviewed range based on origin/main
git checkout -q -b feat; echo d > d; git add d; git commit -qm d
rw prepare; rw mark --verdict pass
push_ok origin feat
git checkout -q main

# --- guard: case, git-dir helpers, cd forms, new repos, submodules, aliases, rewrites
bash_gate deny  "$R" "printf x > .GIT/RAVENWATCH/status"
bash_gate deny  "$R" "printf x > $D/Hooks/pre-$P"
bash_gate deny  "$R" 'printf x > "$(git rev-parse --absolute-git-dir)/hooks/pre-push"'
bash_gate deny  "$R" 'rm "$(git rev-parse --git-common-dir)/ravenwatch/status"'
write_gate deny ".GIT/RAVENWATCH/status"
write_gate deny "$D/HOOKS/pre-$P"
mkdir -p "$T/nohook" && git init -q "$T/nohook"
bash_gate deny  "$R" "cd -P $T/nohook && git $P"
bash_gate deny  "$R" "sh -c \"cd $T/nohook && git $P\""
bash_gate deny  "$R" "git clone -q $T/remote.git $T/newc && cd $T/newc && git $P"
bash_gate deny  "$T" "git init -q && git remote add o x && git $P o main"
bash_gate deny  "$R" "git $P --recurse-submodules=on-demand"
bash_gate allow "$R" "git clone --recurse-submodules $T/remote.git $T/sub2"
bash_gate allow "$R" "git rebase --exec true HEAD~1"
bash_gate deny  "$R" "git config url.$T/x.insteadOf $T/remote.git"
bash_gate deny  "$R" "git $P --exec=/bin/true origin main"
bash_gate allow "$R" "git $P origin main"
H="$T/home"; mkdir "$H"; printf '[alias]\n\tp = %s\n' "$P" > "$H/.gitconfig"
HOME="$H" bash_gate allow "$T/nohook" "git status"
HOME="$H" bash_gate allow "$T/nohook" "git rev-parse --show-toplevel"
HOME="$H" bash_gate deny  "$T/nohook" "git p origin main"

# --- ravenwatch.py: --base injection, secret added then removed, --full history, Husky
if python3 "$RW/scripts/ravenwatch.py" prepare --base "$(printf 'HEAD^{/!-x\nbase=4b825dc642cb6eb9a060e54bf8d69288fbee4904\nx=}')" >/dev/null 2>&1; then
  bad "prepare accepted a --base with newlines"; else ok; fi
fake=Zx81kq0PLm; fake="${fake}33aa9QwerTy"; printf 'api_key = "%s"\n' "$fake" > s.py; git add s.py; git commit -qm add
git rm -q s.py; git commit -qm remove
out=$(python3 "$RW/scripts/ravenwatch.py" prepare)
echo "$out" | grep -q "SECRET?" && ok || bad "history scan missed removed secret"
echo "$out" | grep -q "NOTHING TO REVIEW" && bad "NOTHING TO REVIEW despite scan hit" || ok
python3 "$RW/scripts/ravenwatch.py" prepare --full | grep -q "SECRET?" && ok || bad "--full missed history secret"

git init -q "$T/husky"; mkdir -p "$T/husky/$D/hooks"
printf '#!/usr/bin/env sh\n. "$(dirname "$0")/_/husky.sh"\n' > "$T/husky/$D/hooks/pre-$P"
(cd "$T/husky" && python3 "$RW/scripts/ravenwatch.py" install-hook >/dev/null 2>&1) && bad "installed over husky" || ok
grep -q husky "$T/husky/$D/hooks/pre-$P" && ok || bad "husky hook was touched"

echo "gate_remote: passed=$pass failed=$failn"
rm -rf "$T" "$HOME"
[ "$failn" -eq 0 ]
