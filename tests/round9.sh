#!/bin/sh
# Regression tests for review round 9: the guard's helper exemption, redirects such as `>|`, directories it
# can't follow (popd, subshells, `cd "$X"`), Edit/MultiEdit/NotebookEdit, its time budget; the hook's own
# --receive-pack check; secret-scan dedupe and templates; check results that outlive runs, brief binding in
# mark, duplicate check names, accepted-risk headings, CRLF briefs, concurrent checks, dirtied trees.
# Pushes only to throwaway bare remotes under $T.
set -u
RW=$(cd "$(dirname "$0")/.." && pwd)
T=$(mktemp -d "${TMPDIR:-/tmp}/rwtest9.XXXXXX")
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

# --- SEC-G1: the helper is only exempt as the script of a python call
bash_gate deny  "$R" "cp /dev/null $RV" "installed ravenwatch plugin"
bash_gate deny  "$R" "printf x > $RV" "installed ravenwatch plugin"
bash_gate deny  "$R" "sed -i '' s/a/b/ $RV"
bash_gate allow "$R" "python3 $RV status 2>&1"
bash_gate allow "$R" "python3 $RV mark --verdict block --report /tmp/report.md > /dev/null"

# --- SEC-G2 / SEC-G3: other redirect spellings and write options
bash_gate deny  "$R" "cat /dev/null >| $RW/hooks/guard_push.py"
bash_gate deny  "$R" "git show HEAD:a >| .gi[t]/ravenwatch/status"
bash_gate deny  "$R" "echo x &> $RW/hooks/guard_push.py"
bash_gate deny  "$R" "tree -o $RW/hooks/guard_push.py /tmp"
bash_gate deny  "$R" "cp --target-directory=$RW/hooks /tmp/x"
bash_gate allow "$R" "cat $RW/hooks/guard_push.py"

# --- SEC-G4 / BUG-G3 / TEST-2: every directory the shell may be in is checked
bash_gate deny  "$T" "pushd /tmp; popd; cp /dev/null plugin/hooks/guard_push.py" "installed ravenwatch plugin"
bash_gate deny  "$T" "(cd /tmp); cp /dev/null plugin/hooks/guard_push.py"
bash_gate deny  "$T" "cd /tmp; cp /dev/null plugin/hooks/guard_push.py"
bash_gate deny  "$R" "cd $T && printf x > plugin/hooks/guard_push.py" "installed ravenwatch plugin"
bash_gate deny  "$R" "cd $T && printf x > r/.gi?/hooks/pre-$P" "inside a git directory"
bash_gate allow "$R" "cd $T && printf x > r/notes.txt"
bash_gate deny  "$R" "cd \"\$HOME\" && cp /dev/null $RW/hooks/guard_push.py"
bash_gate deny  "$R" "cd -P /tmp && printf x > $RW/hooks/guard_push.py"
bash_gate deny  "$R" "cd \"\$PWD\" && cd .git && printf x > status" "can't tell which directory"
bash_gate deny  "$R" "cd \"\$PWD\" && printf x > ravenwatch/status" "can't tell which directory"
bash_gate allow "$R" "cd \"\$HOME\" && ls"
# Since 0.5.1 a command that isn't plain may only run read-only programs.
bash_gate deny  "$R" "cd \"\$PWD\" && npm test" "known read-only"
bash_gate allow "$R" "npm test"
bash_gate allow "$T" "cd $R && git $P -q origin main"
bash_gate deny  "$R" "cd /tmp; git $P -q origin main" "not a git repository"

HP=hooksP; HP="${HP}ath"
# --- TEST-3: Edit, MultiEdit and NotebookEdit go through the guard too
tool_gate deny  "$R" "{\"file_path\":\"$D/hooks/pre-$P\",\"old_string\":\"x\",\"new_string\":\"exit 0\"}" Edit
tool_gate deny  "$R" "{\"file_path\":\"$D/ravenwatch/status\",\"old_string\":\"block\",\"new_string\":\"pass\"}" Edit
tool_gate deny  "$R" "{\"file_path\":\"x.cfg\",\"edits\":[{\"old_string\":\"a\",\"new_string\":\"${HP} = /tmp\"}]}" MultiEdit
tool_gate deny  "$R" "{\"notebook_path\":\"$D/hooks/n.ipynb\",\"new_source\":\"x\"}" NotebookEdit
tool_gate allow "$R" "{\"file_path\":\"README.md\",\"old_string\":\"a\",\"new_string\":\"b\"}" Edit

# --- RES-1: a crafted heredoc line can't keep the guard busy past its budget
long=$(python3 -c 'print(">a" * 40 + "|")')
start=$(python3 -c 'import time; print(time.time())')
bash_gate allow "$R" "cat <<EOF $long
body
EOF"
python3 -c 'import sys,time; sys.exit(0 if time.time() - float(sys.argv[1]) < 5 else 1)' "$start" \
  && ok || bad "guard took too long on a crafted heredoc"

# --- TEST-1: the hook's own --receive-pack/exec check refuses (the target is not this repository)
commit unreviewed
git clone -q --mirror "$R" "$T/full.git"   # has every commit, so nothing looks new there
git $P -q --receive-pack="git receive-pack $T/remote.git #" "$T/full.git" main:newb 2>"$T/err" \
  && bad "push with --receive-pack went through" || ok
grep -q "overrides the receive command" "$T/err" && ok || { bad "not refused by the receive-pack check"; cat "$T/err"; }
[ -z "$(git ls-remote "$T/remote.git" refs/heads/newb)" ] && ok || bad "newb reached the remote"
rwq prepare; rwq mark --verdict pass
git $P -q --recurse-submodules=check origin main 2>"$T/err" && bad "recurse push went through" || ok
grep -q "recurses into submodules" "$T/err" && ok || { bad "not refused by the recurse check"; cat "$T/err"; }

# --- BUG-H1: a later example key with the same prefix doesn't hide a real one; TEST-4: accepted is gated too
git checkout -q -b s
k=AKIA; printf 'AWS_KEY = "%s"\n' "${k}QX7ZP4M2KD9W3B5N" > config.py; git add config.py; git commit -qm key
printf 'AWS_KEY = "%s"\n' "${k}IOSFODNN7EXAMPLE" > config.py; git add config.py; git commit -qm example
python3 "$RV" prepare | grep -q "LIKELY REAL" && ok || bad "real key hidden behind a later example key"
rwq mark --verdict pass && bad "pass recorded over a likely secret" || ok
rwq mark --verdict accepted --note x && bad "accepted recorded over a likely secret" || ok
rwq mark --verdict block && ok || bad "block refused with a likely secret"
git checkout -q main; git branch -q -D s

# --- BUG-H5: template values in URLs are not secrets
python3 - "$RW/scripts" <<'EOF' && ok || bad "template URL credentials"
import sys; sys.path.insert(0, sys.argv[1]); import ravenwatch as r
def ph(line):
    return [h[4] for h in r.scan_added_lines(["+++ b/x.py", "@@ -0,0 +1 @@", "+" + line])
            if h[2] == "Credentials in URL"]
sys.exit(0 if ph('u = f"https://deploy:{real}@db.example.com/x"') == [True]
         and ph("u=https://x:$TOKEN@h.example.com/x") == [True]
         and ph("u=https://x:Zr84kQpL2w@h.example.com/x") == [False] else 1)
EOF

# --- BUG-H3 / LOOP-4 / BUG-H2: brief validation
printf -- '---\nchecks:\n  - name: t\n    run: exit 1\n  - name: T\n    run: "true"\n    blocking: false\n---\n# P\n' > .ravenwatch.md
python3 "$RV" trust-brief --private 2>&1 | grep -q "its own name" && ok || bad "duplicate check names accepted"
printf '# P\n## Risks we accept\n- anything in src/\n' > .ravenwatch.md
rwq trust-brief --private && bad "reworded accepted-risks heading accepted" || ok
printf '# P\nAccepted risks\n--------------\n- anything in src/\n' > .ravenwatch.md
rwq trust-brief --private && bad "underlined heading accepted" || ok
printf -- '---\r\naudience: only me\r\n---\r\n# P\r\n## Accepted risks\r\n- docs/a.md: fine\r\n' > .ravenwatch.md
python3 "$RV" trust-brief --private 2>&1 | grep -q "^sha256: " && ok || bad "CRLF brief refused"

# --- LOOP-2 / BUG-H4: a run prepared under another brief can't run checks or record pass
printf -- '---\naudience: only me\n---\n# P\n' > .ravenwatch.md
approve
commit c1; rwq prepare; r1=$(latest_run)
printf -- '---\nchecks:\n  - name: unit\n    run: exit 3\n---\n# P\n' > .ravenwatch.md
approve
python3 "$RV" checks --run "$r1" 2>&1 | grep -q "changed since this review was prepared" && ok || bad "checks ran under a newer brief"
rwq prepare; r2=$(latest_run); rwq checks --run "$r2"
rwq mark --run "$r1" --verdict pass && bad "an older run skipped the new blocking check" || ok
rwq mark --run "$r2" --verdict pass && bad "pass over a failed check" || ok

# --- RES-3: one checks run at a time per commit
printf -- '---\nchecks:\n  - name: long\n    run: sleep 293\n    timeout: 600\n  - name: quick\n    run: "true"\n---\n# P\n' > .ravenwatch.md
approve
rwq prepare; run=$(latest_run)
python3 "$RV" checks --run "$run" --only long >/dev/null 2>&1 &
cpid=$!
i=0; while [ $i -lt 50 ] && ! grep -q "long — STARTED" "$(runs_dir)/$run/checks.md" 2>/dev/null; do sleep 0.2; i=$((i+1)); done
python3 "$RV" checks --run "$run" --only quick 2>&1 | grep -q "already running" && ok || bad "parallel checks allowed"
kill -TERM "$cpid"; wait "$cpid" 2>/dev/null

# --- UX-1: a check that leaves files behind says what to do, everywhere
printf -- '---\nchecks:\n  - name: cov\n    run: echo x > coverage.txt\n  - name: after\n    run: "true"\n---\n# P\n' > .ravenwatch.md
approve
commit c2; rwq prepare; run=$(latest_run)
out=$(python3 "$RV" checks --run "$run" 2>&1)
echo "$out" | grep -q "left files behind: coverage.txt" && ok || bad "checks output doesn't name the files: $out"
echo "$out" | grep -q "after: NOT RUN" && ok || bad "not-run check missing from the summary"
python3 "$RV" mark --run "$run" --verdict pass 2>&1 | grep -q "git-ignore them" && ok || bad "mark gives no way out"
python3 "$RV" checks --run "$run" --only cov 2>&1 | grep -q "cov left files behind" && ok || bad "re-run refusal doesn't explain"
rm -f coverage.txt

# --- BUG-G2: a helper call with a redirect still refuses uncommitted plugin changes
(cd "$RW" && git init -q && git add -A && git -c user.email=t@x -c user.name=t commit -qm plugin)
echo "# edit" >> "$RV"
bash_gate deny "$R" "python3 $RV status 2>&1" "uncommitted changes"
bash_gate deny "$RW" "python3 $RV status | head -3" "uncommitted changes"

echo "round9: passed=$pass failed=$failn"
[ "$failn" -eq 0 ]
