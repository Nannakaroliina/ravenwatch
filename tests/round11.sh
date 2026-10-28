#!/bin/sh
# Regression tests for the full-audit findings (0.4.1): the helper shortcut with a second line, variables
# that build names or paths, heredocs inside heredocs or quotes, git output options into .git, comments
# after escaped spaces, unknown git options and alias chains; the CDPATH, submodule-config and modified-hook
# gaps in the tests; the file classifier, .gitattributes that hide content, quoted non-ASCII paths,
# skip-worktree files and the history scan's time budget.
# Pushes only to throwaway bare remotes under $T.
set -u
RW=$(cd "$(dirname "$0")/.." && pwd)
T=$(mktemp -d "${TMPDIR:-/tmp}/rwtest11.XXXXXX")
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
    # Since 0.5.0 a command that isn't plain gets one refusal for every reason: it counts for any of them.
    echo "$out" | grep -q -e "$4" -e "must be plain" && ok || bad "reason for '$3' lacks '$4': $out"
  fi
}
commit() { echo "$1" > "$1"; git add "$1"; git commit -qm "$1"; }

# --- BUG-1: the helper shortcut only covers a single line
bash_gate deny  "$R" "python3 $RV
git -C $N $P" "not installed"
bash_gate allow "$R" "python3 $RV status"

# --- SEC-1: names built from variables
bash_gate deny  "$R" 'export RAVENWATCH_DISAB${U}LE=1 && git '$P' origin main' "RAVENWATCH_DISABLE"
bash_gate deny  "$R" 'export RAVENWATCH_DIS"$U"ABLE=1' "RAVENWATCH_DISABLE"
bash_gate deny  "$R" 'export GIT_CONF${U}IG_COUNT=1' "GIT_CONFIG"
bash_gate deny  "$R" 'X=ABLE; export RAVENWATCH_DIS$X=1' "builds a variable name"
bash_gate deny  "$R" 'B=main; git '$P' origin $B' "uses shell variables"
bash_gate deny  "$R" 'git config ali${U}as.x '$P "aliases"

# --- SEC-2 / BUG-3: paths through variables
bash_gate deny  "$R" 'd=.git; mkdir -p $d/ravenwatch && printf x > $d/ravenwatch/status' "inside a git directory"
bash_gate deny  "$R" 'G=.git; cp /tmp/forged $G/ravenwatch/status' "inside a git directory"
bash_gate deny  "$R" 'd=$(echo x); cp /tmp/f $d/thing' "can't tell where"
bash_gate deny  "$R" 'read d; printf x > $d' "can't tell where"
# Since 0.5.0 reading through a variable is fine, wherever it points: reads can't forge or skip anything.
bash_gate allow "$R" 'cat $UNSET_DIR/ravenwatch/status'
# Since 0.5.0, writes through variables are refused outright: the command isn't plain.
bash_gate deny  "$R" 'for f in a b; do cp $f /tmp/; done' "must be plain"
bash_gate deny  "$R" 'x=$(mktemp); echo hi > $x' "must be plain"
bash_gate deny  "$R" 'cp a $TMPDIR/b' "must be plain"
bash_gate deny  "$R" 'echo "costs $5" > /tmp/out.txt' "must be plain"

# --- BUG-2: a `cat` heredoc only counts as data where `cat` really is a command
bash_gate deny  "$R" "python3 - <<X
cat <<EOF
X
git -C $N $P
EOF" "not installed"
bash_gate deny  "$R" "echo 'x
cat <<EOF'
git -C $N $P
EOF" "not installed"
bash_gate allow "$R" 'git commit -m "$(cat <<'"'"'EOF'"'"'
Fix the '$P' gate
EOF
)"'

# --- BUG-4: git options that write files are path-checked; naming a repository is fine
bash_gate deny  "$R" "git checkout-index -f --prefix=.git/ ravenwatch/status" "inside a git directory"
bash_gate deny  "$R" "git format-patch -o .git/x HEAD~1" "inside a git directory"
bash_gate allow "$R" "git clone -q $T/remote.git $T/c2"

# --- BUG-5: `a\ #` is one word, not a comment
bash_gate deny  "$R" "echo a\\ #; git -C $N $P" "not installed"
bash_gate deny  "$R" "echo a # note
git -C $N $P" "not installed"

# --- BUG-6: an option the guard doesn't know may swallow a word before the subcommand
bash_gate deny  "$R" "git -C $N --attr-source HEAD $P origin main" "not installed"
bash_gate deny  "$R" "git --frobnicate HEAD $P origin main" "can't tell whether it pushes"
bash_gate allow "$R" "git stash $P -m wip"

# --- BUG-7: aliases of aliases, and aliases that add git options to a push
(cd "$N" && git config alias.bb $P && git config alias.aa bb)
git config alias.pf "-c push.recurseSubmodules=on-demand $P"
git config alias.bb $P; git config alias.aa bb
bash_gate deny  "$R" "git -C $N aa" "not installed"
bash_gate deny  "$R" "git pf" "a push with git options"
bash_gate allow "$R" "git aa origin main"
git config --unset alias.pf

# --- TEST-1 (full audit): CDPATH is what sends `cd nohook` elsewhere ($R/nohook exists too)
mkdir -p "$R/nohook"
bash_gate deny  "$R" "CDPATH=$T cd nohook && git $P" "change the shell"
rmdir "$R/nohook"

# --- TEST-2 (round 4: LOOP-1/3): push recursion switched on in git config is refused whenever it is on,
# submodules or not, by the guard and by the terminal hook. Values git may read as on (2, 1k) count.
commit sub1
for setting in "push.recurseSubmodules on-demand" "push.recurseSubmodules only" "submodule.recurse true" \
               "submodule.recurse 2" "submodule.recurse 1k"; do
  git config $setting
  bash_gate deny "$R" "git $P origin main" "recursion into submodules is on"
  git $P -q origin main 2>"$T/err" && bad "hook let '$setting' through" || ok
  grep -q "recurseSubmodules" "$T/err" && ok || bad "hook refusal for '$setting' not about submodules: $(cat "$T/err")"
  git config --unset ${setting%% *}
done
for setting in "push.recurseSubmodules check" "push.recurseSubmodules no" "submodule.recurse false"; do
  git config $setting
  bash_gate allow "$R" "git $P origin main"
  git $P -q origin main 2>"$T/err"
  grep -q "recurseSubmodules" "$T/err" && bad "hook refused '$setting' as recursion: $(cat "$T/err")" || ok
  git config --unset ${setting%% *}
done

# --- TEST-3: a modified or non-executable hook makes the guard refuse
HOOK="$(git rev-parse --git-path hooks)/pre-push"
printf 'exit 0\n' >> "$HOOK"
bash_gate deny  "$R" "git $P origin main" "out of date"
python3 "$RV" install-hook --uninstall >/dev/null 2>&1; python3 "$RV" install-hook >/dev/null
chmod -x "$HOOK"
bash_gate deny  "$R" "git $P origin main" "out of date"
chmod +x "$HOOK"
bash_gate allow "$R" "git $P origin main"

# --- LOOP-1: code in doc-, credential- or infra-named paths is code
mkdir -p src/documents src/auth src/infra
for f in src/documents/upload.ts src/auth/credentials.ts src/infra/repository.ts src/docker_client.go; do
  echo "export const x = 1" > "$f"
done
git add src; git commit -qm paths
ctx=$(python3 "$RV" prepare)
echo "$ctx" | grep "^- code (4)" | grep -q "src/documents/upload.ts" && ok || bad "classifier: $(echo "$ctx" | grep '^- [a-z-]* (')"
echo "$ctx" | grep -q "^- docs" && bad "code classified as docs" || ok

# --- LOOP-2: .gitattributes can't hide a file from the secret scan
k=AKIA; printf 'KEY = "%s"\n' "${k}Q7RTYU2X9ZPLM4KD" > keys.py
echo "keys.py -diff" > .gitattributes
git add keys.py .gitattributes; git commit -qm keys
python3 "$RV" prepare | grep -q "AWS access key ID at keys.py" && ok || bad "-diff attribute hid a key from the scan"
git rm -q keys.py .gitattributes; git commit -qm unkeys

# --- BUG-9: non-ASCII file names are not quoted into misclassification
echo "print(1)" > "työkalut.py"; git add "työkalut.py"; git commit -qm uml
python3 "$RV" prepare | grep "^- code" | grep -q "työkalut.py" && ok || bad "non-ASCII code file misclassified"

# --- LOOP-3 / IMP-2 (round 4-5, scoped in round 6 by UX-1): a skip-worktree file that is present but
# DIFFERS from the commit, or is MISSING, is refused when it is among the reviewed files, or in a full
# audit; outside the range it is a local override the context points out. `a` is committed and not
# changed on the branch (out of range); U is added on the branch (in range).
U=src/documents/upload.ts
git update-index --skip-worktree "$U"
python3 "$RV" prepare >/dev/null 2>"$T/err" && ok || bad "an unchanged skip-worktree file blocked prepare: $(cat "$T/err")"
echo changed >> "$U"
python3 "$RV" prepare >/dev/null 2>"$T/err" && bad "prepare ignored a changed, reviewed skip-worktree file" || ok
grep -q "differ on disk" "$T/err" && ok || bad "changed skip-worktree refusal unclear: $(cat "$T/err")"
git update-index --no-skip-worktree "$U"; git checkout -q -- "$U"
# A changed file OUTSIDE the reviewed range (a local override kept out of commits) doesn't block a diff
# review: the context tells reviewers it isn't the commit. A full audit still refuses it.
git update-index --skip-worktree a; echo override >> a
ctx=$(python3 "$RV" prepare 2>"$T/err") && ok || bad "a local override outside the range blocked a diff review: $(cat "$T/err")"
echo "$ctx" | grep "local overrides, NOT what is pushed" | grep -q ": a$" && ok || bad "override not noted: $ctx"
python3 "$RV" prepare --full >/dev/null 2>"$T/err" && bad "full audit ignored a changed skip-worktree file" || ok
grep -q "differ on disk" "$T/err" && ok || bad "full-audit changed refusal unclear: $(cat "$T/err")"
grep -q "git stash" "$T/err" && ok || bad "changed refusal doesn't give the stash round trip: $(cat "$T/err")"
grep -q "and commit or stash" "$T/err" && bad "changed refusal still advises committing a local override" || ok
git update-index --no-skip-worktree a; git checkout -q -- a
# A MISSING file outside the reviewed range is allowed in a diff review (sparse checkout), refused in --full.
git update-index --skip-worktree a; rm a
python3 "$RV" prepare >/dev/null 2>"$T/err" && ok || bad "a missing file outside the range blocked a diff review: $(cat "$T/err")"
python3 "$RV" prepare --full >/dev/null 2>"$T/err" && bad "full audit ignored a missing skip-worktree file" || ok
grep -q "missing from disk" "$T/err" && ok || bad "missing-file refusal unclear: $(cat "$T/err")"
git update-index --no-skip-worktree a; git checkout -q -- a
echo changed >> a
python3 "$RV" prepare --full >/dev/null 2>"$T/err" && bad "full audit ran over uncommitted tracked changes" || ok
grep -q "uncommitted changes" "$T/err" && ok || bad "dirty full-audit refusal unclear: $(cat "$T/err")"
git checkout -q -- a

# --- TEST-2: mark refuses pass/warn over a changed skip-worktree file or a full audit changed on disk
python3 "$RV" prepare >/dev/null
git update-index --skip-worktree "$U"; echo changed >> "$U"
python3 "$RV" mark --verdict pass --secrets-cleared >/dev/null 2>"$T/err" && bad "mark passed over a hidden change" || ok
grep -q "differ on disk" "$T/err" && ok || bad "mark's skip-worktree refusal unclear: $(cat "$T/err")"
python3 "$RV" mark --verdict block >/dev/null 2>&1 && ok || bad "mark refused block over a hidden change"
git update-index --no-skip-worktree "$U"; git checkout -q -- "$U"
python3 "$RV" prepare --full >/dev/null
echo changed >> a
python3 "$RV" mark --verdict pass --secrets-cleared >/dev/null 2>"$T/err" && bad "mark passed a full audit changed on disk" || ok
grep -q "changed on disk" "$T/err" && ok || bad "mark's dirty full-audit refusal unclear: $(cat "$T/err")"
git checkout -q -- a

# --- round 2 (SEC-1): line continuations and $'…' quoting can't hide a hook-skipping flag
bash_gate deny  "$R" "git $P --no-\\
verify origin main" "no-verify"
bash_gate deny  "$R" "git $P \$'--no-\\x76erify' origin main"

# --- round 2 (SEC-2): an empty-body cat heredoc ends at the next delimiter line
bash_gate deny  "$R" "cat <<EOF
EOF
git -C $N $P
EOF" "not installed"
bash_gate allow "$R" "cat <<EOF > /tmp/rw-notes.txt
EOF"

# --- round 2 (BUG-2): $PWD after a cd, and assignments that may not apply
mkdir -p sub
bash_gate deny  "$R" 'cd sub && cp a $PWD/../.gi?/hooks/pre-'$P "can't tell where"
bash_gate deny  "$R" 'PWD=/tmp cp a $PWD/.gi?/hooks/pre-'$P "inside a git directory"
rmdir sub

# --- round 2 (UX-1/2/3, sed, reads): ordinary commands with variables
# Since 0.5.1 a command that isn't plain may only run read-only programs.
bash_gate deny  "$R" 'docker '$P' "$IMAGE"' "known read-only"
bash_gate allow "$R" 'grep -rn '$P' src | awk -F: '"'"'{print $1}'"'"
bash_gate deny  "$R" 'git stash '$P' -m "wip $B"' "must be plain"
bash_gate deny  "$R" 'git '$P' origin "$B"' "uses shell variables"
bash_gate deny  "$R" 'D="$(mktemp -d)"; cp a "$D/x"' "must be plain"
bash_gate deny  "$R" 'mkdir -p "${TMPDIR:-/tmp}/build"' "must be plain"
bash_gate deny  "$R" 'for f in *.md; do cp "$f" "${f%.md}.txt"; done' "must be plain"
bash_gate deny  "$R" 'd=$(mktemp -d .git/x.XXXX); cp a $d/y' "inside a git directory"
bash_gate deny  "$R" 'd=$(mktemp -d "$X/y.XXXX"); cp a $d/y' "can't tell where"
bash_gate allow "$R" 'curl -s -H "Authorization: Bearer $TOKEN" https://example.com/api'
bash_gate deny  "$R" 'curl -s -o "$(echo .)/x" https://example.com' "can't tell where"
bash_gate deny  "$R" 'sed -n "$(echo 1)p" a' "can't tell where"
bash_gate deny  "$R" 'sed -i "" $UNKNOWN_DIR/x' "can't tell where"
bash_gate deny  "$R" 'cat "$(git rev-parse --show-toplevel)/config/x.yml"' "must be plain"

# --- round 3 (UX-1): `$` inside a single-quoted sed or perl script is text
bash_gate allow "$R" "sed -i '' '\$d' a"
bash_gate allow "$R" "sed -i 's/\\\${VERSION}/1.2.0/' a"
bash_gate allow "$R" "perl -pi -e 's/v(\\d+)/v\$1/' a"
bash_gate deny  "$R" 'read F; sed "s/a/b/w $F" a' "can't tell where"

# --- round 3 (SEC-1): $'…' escapes the shells read differently, and $'…' in git commands
bash_gate deny  "$R" "git \$'pu\\x73h\\c@' origin main" "escapes the shells read differently"
bash_gate deny  "$R" "git \$'pu\\x73h' origin main" "mentions git"
bash_gate allow "$R" "grep -nE 'git $P\$' README.md"
bash_gate allow "$R" "printf \$'\\e[1mbold\\e[0m\\n'"

# --- round 3 (BUG-1): ${X#…} and ${X%…} are trimmed like the shell does
bash_gate deny  "$R" 'X=x.git; cp /tmp/f ${X#x}/ravenwatch/status' "inside a git directory"
bash_gate deny  "$R" 'X=.gitx; cp /tmp/f ${X%x}/hooks/pre-'$P "inside a git directory"
bash_gate deny  "$R" 'X=notes.md; cp a "${X%.md}.txt"' "must be plain"

# --- round 3 (BUG-2): a command name or git subcommand from a variable
bash_gate deny  "$R" 'G=git; $G '$P' origin main' "uses shell variables"
bash_gate deny  "$R" 'read G; $G '$P' origin main' "takes its name from a variable"
bash_gate deny  "$R" 'read S; git $S origin main' "subcommand comes from a variable"

# --- round 3 (BUG-3): output options in clusters and attached values
bash_gate deny  "$R" 'read F; curl -sSo "$F" https://example.com' "can't tell where"
bash_gate deny  "$R" 'read F; curl -o"$F" https://example.com' "can't tell where"
bash_gate deny  "$R" 'read F; wget -qO "$F" https://example.com' "can't tell where"
bash_gate deny  "$R" 'read F; tar -xf"$F"' "can't tell where"
bash_gate deny  "$R" 'read F; curl --output="$F" https://example.com' "can't tell where"

# --- round 3 (BUG-5): $PWD is the shell's directory, not the guard's
bash_gate deny  "$R" 'cp /tmp/f $PWD/.gi?/ravenwatch/status' "inside a git directory"

# --- round 3 (SEC-2 r2): an unquoted heredoc delimiter with a command substitution in the body
bash_gate deny  "$R" "cat <<EOF
\$(git -C $N $P)
EOF" "command substitution"

# --- round 5 (BUG-2): a quote after the delimiter opens a string that swallows the body — keep the body
bash_gate deny  "$R" "cat <<'EOF' \"
\$(git -C $N $P)
EOF
\"" "command substitution"

# --- round 5 (BUG-3): cat redefined in the same command runs the body, so it is not dropped
bash_gate deny  "$R" "cat() { sh; }; cat <<'EOF'
git -C $N $P origin main
EOF" "not installed"
bash_gate deny  "$R" "alias cat=sh; cat <<'EOF'
git -C $N $P origin main
EOF" "changes how"

# --- round 5 (DES-1): a # after an escaped space is not a comment, so a later $'…' is still seen
bash_gate deny  "$R" "echo a\\ #x; git \$'pu\\x73h' origin main" "mentions git"

# --- round 2-4 (BUG-3 / LOOP-1 / IMP-1): of the two settings, the one git reads last wins …
git config push.recurseSubmodules check; git config submodule.recurse true
bash_gate deny  "$R" "git $P origin main" "recursion into submodules is on"
git $P -q origin main 2>"$T/err" && bad "hook let submodule.recurse=true (read last) through" || ok
grep -q "recurseSubmodules" "$T/err" && ok || bad "hook refusal not about submodules: $(cat "$T/err")"
# … an opt-out on the command line can't be told apart from an option's value, so it doesn't count …
bash_gate deny  "$R" "git $P -o --no-recurse-submodules origin main" "recursion into submodules is on"
bash_gate deny  "$R" "git $P --no-recurse-submodules origin main" "recursion into submodules is on"
# … and push.recurseSubmodules=check read last (the repository's own setting) wins over submodule.recurse.
git config --unset submodule.recurse; git config --unset push.recurseSubmodules
git config submodule.recurse true; git config push.recurseSubmodules check
bash_gate allow "$R" "git $P origin main"
git $P -q origin main 2>"$T/err"
grep -q "recurseSubmodules" "$T/err" && bad "hook refused check-read-last as recursion: $(cat "$T/err")" || ok
git config --unset submodule.recurse; git config --unset push.recurseSubmodules

# --- round 4 (TEST-2): $PWD comes from the session's directory, even when the guard's own differs
out=$(python3 -c 'import json,sys; print(json.dumps({"tool_name":"Bash","cwd":sys.argv[1],"tool_input":{"command":sys.argv[2]}}))' \
  "$R" 'cp /tmp/f $PWD/.gi?/ravenwatch/status' | PWD="$T" python3 "$G")
echo "$out" | grep -q -e "inside a git directory" -e "must be plain" && ok \
  || bad "\$PWD taken from the guard's environment: $out"
out=$(python3 -c 'import json,sys; print(json.dumps({"tool_name":"Bash","cwd":sys.argv[1],"tool_input":{"command":sys.argv[2]}}))' \
  "$T" 'cp a $PWD/.gi?/notes.txt' | PWD="$R" python3 "$G")
# Since 0.5.0 a variable in a copy's target is refused whatever its value.
echo "$out" | grep -q "must be plain" && ok || bad "a variable in a copy's target was let through: $out"

# --- round 4 (VER-1, UX-1): $'…' is found inside "$(…)" too; undecodable bodies are refused; heredoc data
# and harmless $'\0' are fine
bash_gate deny  "$R" "echo \"\$(git \$'pu\\x73h' origin main)\"" "can't be checked"
bash_gate deny  "$R" "echo \"\$(git \$'pu\\x7' origin main)\"" "escapes the shells read differently"
bash_gate deny  "$R" "printf %s \$'\\N{LATIN SMALL LETTER P}'" "escapes the shells read differently"
bash_gate deny  "$R" "find . -print0 | while IFS= read -r -d \$'\\0' f; do echo \"\$f\"; done" "must be plain"
bash_gate deny  "$R" "cat > /tmp/x <<'EOF' && git -C $N $P
EOF" "not installed"
bash_gate deny  "$R" "cat > .git/hooks/x <<'EOF'
EOF" "git hooks"
# A `\$` inside double quotes isn't plain (since 0.5.1 refused when the command splits oddly); single quotes are.
bash_gate deny  "$R" 'grep -n "a\$\|b" a' "known read-only"
bash_gate allow "$R" "grep -n 'a\$\|b' a"
bash_gate allow "$R" "cat > /tmp/rw-x.sh <<'EOF'
IFS=\$'\\n'
for f in \$(git diff --name-only); do echo \"\$f\"; done
EOF"

# --- round 4 (RES-1): a long value isn't trimmed (that could run out the guard's time), and when time runs
# out anyway, writes and variables are refused
bash_gate deny  "$R" "X=\$(printf '%5000s' x); rm \${X%zz}/f" "can't tell where"
python3 - "$RW/hooks" <<'EOF' && ok || bad "out of time, rm with variables was let through"
import io, json, sys, contextlib; sys.path.insert(0, sys.argv[1]); import guard_push as g
g._CURRENT.update(command="rm ${A}${B}", target="")
buf = io.StringIO()
real_exit = g.os._exit
g.os._exit = lambda code: (_ for _ in ()).throw(SystemExit(code))
try:
    with contextlib.redirect_stdout(buf):
        g._too_slow(14, None)
except SystemExit:
    pass
sys.exit(0 if '"deny"' in buf.getvalue() else 1)
EOF

# --- round 2 (BUG-1 / IMP-1): sensitive files whatever category wins; infrastructure code is signalled
mkdir -p terraform tests infra
k=pass; printf 'db_%sword = "x"\n' "$k" > terraform/prod.tfvars
echo "X=1" > tests/.env
echo "export const app = 1" > infra/app.ts
echo "module.exports = {}" > next.config.js
git add -f terraform tests/.env infra next.config.js; git commit -qm infra
ctx=$(python3 "$RV" prepare)
echo "$ctx" | grep -q "SENSITIVE FILE in push: terraform/prod.tfvars" && ok || bad ".tfvars not reported as sensitive"
echo "$ctx" | grep -q "SENSITIVE FILE in push: tests/.env" && ok || bad "tests/.env not reported as sensitive"
echo "$ctx" | grep "infrastructure as code" | grep -q "infra/app.ts" && ok || bad "infra code not signalled"
echo "$ctx" | grep "infrastructure as code" | grep -q "next.config.js" && ok || bad "framework config not signalled"
git rm -rq terraform tests/.env infra next.config.js; git commit -qm noinfra

# --- round 2/3 (RES-1, LOOP-3): over-long lines come out in bounded, overlapping pieces, so a key far
# into a minified line is still found, and the lines after it still arrive
k=AKIA; python3 -c 'import sys; print("x" * 5000 + "KEY=\"" + sys.argv[1] + "\""); print("tail")' "${k}Q7RTYU2X9ZPLM4KD" > long.txt
git add long.txt; git commit -qm long
python3 - "$RW/scripts" <<'EOF' && ok || bad "long lines not scanned in bounded pieces"
import sys; sys.path.insert(0, sys.argv[1]); import ravenwatch as r
lines = list(r.git_lines("show", "--format=", "HEAD", max_line=1000))
hits = r.scan_added_lines(lines)
cap = 1000 + 512 + len(r.CONTINUATION)
sys.exit(0 if "+tail" in lines and max(map(len, lines)) <= cap
         and any(h[2] == "AWS access key ID" for h in hits) else print(len(lines), hits) or 1)
EOF
git rm -q long.txt; git commit -qm nolong

# --- round 5 (LOOP-1): a long `++` line in a combined (merge) diff is scanned in full, so a `-` placed at a
# piece boundary can't make a continuation look like a deletion and skip a key after the first MiB.
python3 - "$RW/scripts" <<'EOF' && ok || bad "a long ++ merge line hid a key from the scan"
import sys; sys.path.insert(0, sys.argv[1]); import ravenwatch as r
k = "AKIA" + "Q7RTYU2X9ZPLM4KD"
# Build the combined-diff lines git_lines would yield for a 2-column `++` line over the cap: a first piece
# whose tail is `-` (so a naive 2-col marker would read `+-`), then the key in a continuation.
first = "++" + "y" * 1500 + "-"
cont = r.CONTINUATION + "-x KEY=" + k
lines = ["diff --cc x.js", "--- a/x.js", "+++ b/x.js", "@@@ -1,1 -1,1 +1,2 @@@", first, cont, "++ok"]
hits = r.scan_added_lines(lines)
sys.exit(0 if any(h[2] == "AWS access key ID" and h[0] == "x.js" for h in hits) else print(hits) or 1)
EOF

# --- round 4 (LOOP-2): a piece that starts with `++` (or an added line that does) is still scanned
python3 - "$RW/scripts" <<'EOF' && ok || bad "a ++ line or piece hid a key from the scan"
import sys; sys.path.insert(0, sys.argv[1]); import ravenwatch as r
k = "AKIA" + "Q7RTYU2X9ZPLM4KD"
lines = ["diff --git a/x.js b/x.js", "--- a/x.js", "+++ b/x.js", "@@ -0,0 +1,3 @@",
         "+++n; const t = '" + k + "'", "+++ b/elsewhere " + k, "+ok"]
hits = r.scan_added_lines(lines)
sys.exit(0 if len([h for h in hits if h[2] == "AWS access key ID"]) == 2 and all(h[0] == "x.js" for h in hits)
         else print(hits) or 1)
EOF

# --- round 3/4 (LOOP-1 / IMP-1): a flagged file missing from disk blocks a full audit and the checks (they
# read the whole tree), and a diff review only when it is a reviewed file — so sparse checkouts still work
git update-index --skip-worktree a; rm a
python3 "$RV" prepare >/dev/null 2>"$T/err" && ok || bad "a missing file outside the reviewed ones blocked prepare: $(cat "$T/err")"
python3 "$RV" prepare --full >/dev/null 2>"$T/err" && bad "full audit ignored a deleted skip-worktree file" || ok
grep -q "missing from disk" "$T/err" && ok || bad "deleted skip-worktree refusal unclear: $(cat "$T/err")"
git update-index --no-skip-worktree a; git checkout -q -- a
printf -- '---\nchecks:\n  - name: ok\n    run: "true"\n---\n# P\n' > .ravenwatch.md
sha=$(python3 "$RV" trust-brief --private 2>&1 | sed -n 's/^sha256: //p')
python3 "$RV" trust-brief --private --approve "$sha" >/dev/null 2>&1 || bad "approve failed"
python3 "$RV" prepare >/dev/null
git update-index --skip-worktree a; rm a
python3 "$RV" checks >/dev/null 2>"$T/err" && bad "checks ran with a deleted skip-worktree file" || ok
grep -q "missing from disk" "$T/err" && ok || bad "checks skip-worktree refusal unclear: $(cat "$T/err")"
git update-index --no-skip-worktree a; git checkout -q -- a
U=src/documents/upload.ts
git update-index --skip-worktree "$U"; rm "$U"
python3 "$RV" prepare >/dev/null 2>"$T/err" && bad "prepare ignored a reviewed file missing from disk" || ok
git update-index --no-skip-worktree "$U"; git checkout -q -- "$U"

# --- RES-1: the history scan stops at its time budget and says so
python3 - "$RW/scripts" <<'EOF' && ok || bad "scan budget"
import sys, time; sys.path.insert(0, sys.argv[1]); import ravenwatch as r
def slow():
    for i in range(10):
        yield f"commit {'0' * 40}"
        time.sleep(0.05)
state = {"commits": 0, "cut": False}
lines = list(r.budgeted(slow(), 0.12, state))
sys.exit(0 if state["cut"] and 0 < state["commits"] < 10 else print(state) or 1)
EOF

echo "round11: passed=$pass failed=$failn"
[ "$failn" -eq 0 ]
