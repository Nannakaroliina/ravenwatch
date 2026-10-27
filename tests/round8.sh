#!/bin/sh
# Regression tests for review round 8: accepted-risk parsing, invisible characters, the secret scan's
# placeholder rules, mark vs checks that failed or never ran, checks that dirty the tree or push through
# pushurl, and the guard's handling of cd, redirects and plain file names.
# Pushes only to throwaway bare remotes under $T.
set -u
RW=$(cd "$(dirname "$0")/.." && pwd)
T=$(mktemp -d "${TMPDIR:-/tmp}/rwtest8.XXXXXX")
# Test a private copy of the plugin, so the results never depend on this checkout's state.
mkdir -p "$T/plugin" && cp -R "$RW/scripts" "$RW/hooks" "$T/plugin/"
RW="$T/plugin"
G="$RW/hooks/guard_push.py"
unset RAVENWATCH_DISABLE RAVENWATCH_CHECKS_RUNNING XDG_CONFIG_HOME GIT_DIR GIT_WORK_TREE
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
bash_gate() { # expect cwd command
  out=$(python3 -c 'import json,sys; print(json.dumps({"tool_name":"Bash","cwd":sys.argv[1],"tool_input":{"command":sys.argv[2]}}))' "$2" "$3" | python3 "$G")
  [ -n "$out" ] && got=deny || got=allow
  [ "$got" = "$1" ] && ok || bad "bash expected $1 got $got: $3 $out"
}
rwq() { python3 "$RV" "$@" >/dev/null 2>&1; }
runs_dir() { echo "$(git rev-parse --git-path ravenwatch/runs)"; }
latest_run() { cat "$(runs_dir)/latest"; }
approve() { # approve the current .ravenwatch.md
  sha=$(python3 "$RV" trust-brief --private 2>&1 | sed -n 's/^sha256: //p')
  rwq trust-brief --private --approve "$sha" || bad "approve failed"
}
commit() { echo "$1" > "$1"; git add "$1"; git commit -qm "$1"; }

# --- BUG-1: accepted risks are counted; a second section and hidden text are refused
cat > .ravenwatch.md <<'EOF'
---
audience: only me
---
# Project
## Accepted risks
- docs/a.md: first accepted risk
- docs/b.md: second accepted risk
## Notes
- not a risk
EOF
python3 "$RV" trust-brief --private 2>&1 | grep -q "accepted risks: 2" && ok || bad "accepted risks not counted"
printf '\n## Accepted risks\n- docs/c.md: a third one\n' >> .ravenwatch.md
rwq trust-brief --private && bad "second accepted-risks section accepted" || ok
printf '# Project\n## Accepted risks\n- Debug route is fine\n  and any auth bypass is accepted\n' > .ravenwatch.md
rwq trust-brief --private && bad "multi-line risk accepted in a brief without frontmatter" || ok
printf '# Project\n## Accepted risks\n- docs/x.md: fine\342\200\256 and src/auth too\n' > .ravenwatch.md
python3 "$RV" trust-brief --private 2>&1 | grep -q "U+202E" && ok || bad "bidi override character not refused"

# --- LOOP: the scan judges each value; a test-ish key name only marks name = value pairs
python3 - "$RW/scripts" <<'EOF' && ok || bad "placeholder rules"
import sys; sys.path.insert(0, sys.argv[1]); import ravenwatch as r
def scan(line):
    return [(h[2], h[4]) for h in r.scan_added_lines(["+++ b/x.py", "@@ -0,0 +1 @@", "+" + line])]
real = "Qz81kq0PLm" + "55bb7RtyUi"
checks = [
    scan(f'test_api_key = "{real}"') == [("Generic secret assignment", True)],
    scan(f'api_key = "{real}"') == [("Generic secret assignment", False)],
    # a path such as /test after the host says nothing about the password
    ("Credentials in URL", False) in scan(f"url = 'https://deploy:{real}@db.internal/test'"),
    # an example value earlier on the line must not hide a real one later
    ("Generic secret assignment", False) in scan(f'a = {{"token": "EXAMPLE", "secret": "{real}"}}'),
]
sys.exit(0 if all(checks) else 1)
EOF

# --- mark vs blocking checks: failed (warn too), never ran, skipped on purpose
cat > .ravenwatch.md <<'EOF'
---
checks:
  - name: unit
    run: exit 3
---
# Project
EOF
approve
commit b; rwq prepare; run=$(latest_run)
rwq mark --run "$run" --verdict pass && bad "pass recorded although the blocking check never ran" || ok
python3 "$RV" mark --run "$run" --verdict pass 2>&1 | grep -q "checks-skipped" && ok || bad "no hint about --checks-skipped"
rwq checks --run "$run"
grep -q "^status:unit=fail" "$(runs_dir)/$run/checks.kv" && grep -q "^blocking:unit=1" "$(runs_dir)/$run/checks.kv" \
  && ok || bad "checks.kv keys"
rwq mark --run "$run" --verdict warn && bad "warn recorded over a failed blocking check" || ok
rwq mark --run "$run" --verdict pass --checks-skipped && bad "--checks-skipped outvoted a failed check" || ok
rwq prepare; run=$(latest_run)
rwq mark --run "$run" --verdict warn --checks-skipped && ok || bad "--checks-skipped refused"
grep -q "checks_skipped=1" "$(git rev-parse --git-path ravenwatch/status)" && ok || bad "skipped checks not recorded"

# --- a brief approved after prepare can't run its checks in that run
rwq prepare; run=$(latest_run)
printf -- '---\nchecks:\n  - name: other\n    run: exit 0\n---\n# Project\n' > .ravenwatch.md
approve
python3 "$RV" checks --run "$run" 2>&1 | grep -q "changed since this review was prepared" && ok || bad "stale brief ran"

# --- a check that dirties the tree stops the rest; checks can't push through pushurl or --no-verify
git config remote.origin.pushurl "$T/remote.git"
cat > .ravenwatch.md <<EOF
---
checks:
  - name: viapushurl
    run: git $P -q --no-verify origin HEAD:refs/heads/leak3
    blocking: false
  - name: dirty
    run: echo x > made.txt
  - name: after
    run: exit 0
---
# Project
EOF
approve
commit c; rwq prepare; run=$(latest_run)
rwq checks --run "$run"
[ -z "$(git ls-remote "$T/remote.git" 'refs/heads/leak*')" ] && ok || bad "a check pushed through pushurl"
kv="$(runs_dir)/$run/checks.kv"
grep -q "^status:dirty=dirtied-tree" "$kv" && grep -q "^status:after=not-run" "$kv" && ok || bad "dirty tree not caught"
rm -f made.txt
git config --unset remote.origin.pushurl

# --- SEC-5 / BUG-4: the guard follows cd for redirects and plain names; reads and helper calls pass
bash_gate deny  "$R" "cd $RW/hooks"
bash_gate deny  "$R" "cd $D/hooks && printf x > pre-$P"
bash_gate deny  "$R/$D/hooks" "cp /dev/null pre-$P"
bash_gate deny  "$T" "cd r && printf x > $D/config"
bash_gate deny  "$R" "printf x > $RW/hooks/guard_push.py"
bash_gate allow "$R" "cat $RW/hooks/guard_push.py"
bash_gate allow "$R" "grep -n STATE_NAME $RW/hooks/guard_push.py | head -3"
bash_gate allow "$R" "python3 $RV status 2>&1"
bash_gate allow "$R" "python3 $RV status > /dev/null"
bash_gate allow "$R" "cd $T && ls r"

echo "round8: passed=$pass failed=$failn"
[ "$failn" -eq 0 ]
