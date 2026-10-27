#!/bin/sh
# Tests for the whole-repository audit (`prepare --full`): review groups, files left out of them, high-risk
# ordering, the history-wide secret scan, triage signals without vendored code, and the push gate after a
# full audit. Pushes only to a throwaway bare remote under $T.
set -u
RW=$(cd "$(dirname "$0")/.." && pwd)
T=$(mktemp -d "${TMPDIR:-/tmp}/rwtestfull.XXXXXX")
# Test a private copy of the plugin, so the results never depend on this checkout's state.
mkdir -p "$T/plugin" && cp -R "$RW/scripts" "$RW/hooks" "$T/plugin/"
RW="$T/plugin"
RV="$RW/scripts/ravenwatch.py"
unset RAVENWATCH_DISABLE RAVENWATCH_CHECKS_RUNNING XDG_CONFIG_HOME GIT_DIR GIT_WORK_TREE CDPATH
export GIT_CONFIG_NOSYSTEM=1
trap 'rm -rf "$T"' EXIT
export HOME="$T/home"; mkdir -p "$HOME"
P=push
cd "$T"
git init -q --bare -b main remote.git
git init -q -b main r && cd r
git config user.email t@example.com; git config user.name t
git remote add origin "$T/remote.git"

pass=0; failn=0
ok() { pass=$((pass+1)); }
bad() { failn=$((failn+1)); echo "FAIL: $*"; }
run_dir() { echo ".git/ravenwatch/runs/$(cat .git/ravenwatch/runs/latest)"; }

mkdir -p src/lib src/routes src/big node_modules/pkg dist gen bin tests docs
for i in $(seq 1 25); do seq 1 100 | sed 's/^/export const v = /' > "src/lib/m$i.ts"; done
seq 1 3000 | sed 's/^/x = /' > src/big/huge.py
printf 'export function login(req) { return req.body.email }\n' > src/routes/auth.ts
printf 'module.exports = { api: 1, email: 1 }\n' > node_modules/pkg/index.js
seq 1 10 > dist/app.min.js
printf 'export const generated = 1\n' > gen/client.ts
echo 'gen/** linguist-generated' > .gitattributes
printf '#!/bin/sh\necho deploy\n' > bin/deploy
printf '\000\001\002\003' > logo.png
echo '{}' > package-lock.json; echo '{"name":"t"}' > package.json
echo 'it("works", () => {})' > tests/a.test.ts
echo '# Docs' > docs/guide.md
k=sk_live_; k="${k}abcdefghijklmnopqrstuvwx1234"   # split so the test file itself holds no key
echo "const KEY = \"$k\";" > src/keys.ts
git add -A; git commit -qm one
git rm -q src/keys.ts; git commit -qm "remove key"

out=$(python3 "$RV" prepare --full)
D=$(run_dir)
grep -q "^mode=full$" "$D/prepared" && ok || bad "mode not full"
[ -f "$D/groups.txt" ] && ok || bad "no groups file"
[ ! -e "$D/diff.patch" ] && ok || bad "full audit wrote a whole-repo diff"
[ ! -e "$D/commits.patch" ] && ok || bad "full audit wrote per-commit patches"
echo "$out" | grep -q "^## Full audit" && ok || bad "no full audit section"

# Files left out of the groups, each with its reason.
for f in node_modules/pkg/index.js dist/app.min.js gen/client.ts; do
  grep -q "	$f	not grouped: vendored/generated$" "$D/files.txt" && ok || bad "$f not excluded as vendored/generated"
done
grep -q "	package-lock.json	not grouped: lockfile$" "$D/files.txt" && ok || bad "lockfile grouped"
grep -q "	logo.png	not grouped: binary$" "$D/files.txt" && ok || bad "binary grouped"
grep -q "	tests/a.test.ts	not grouped: test$" "$D/files.txt" && ok || bad "test file grouped"
grep -q "	package.json	not grouped: manifest$" "$D/files.txt" && ok || bad "manifest grouped"
grep -q "	bin/deploy	G[0-9]*$" "$D/files.txt" && ok || bad "extension-less script not grouped"
grep -Eq "^(node_modules|dist|gen)/" "$D/groups.txt" && bad "vendored file in a group" || ok

# Every code file lands in exactly one group, and no group is over the limits (a huge file stands alone).
grouped=$(grep -c "	G[0-9]*$" "$D/files.txt")
[ "$grouped" -eq 28 ] && ok || bad "expected 28 grouped files, got $grouped"
python3 - "$D/groups.txt" <<'EOF' && ok || bad "group limits"
import re, sys
groups, cur = [], None
for line in open(sys.argv[1], encoding="utf-8"):
    if line.startswith("## G"):
        cur = []; groups.append(cur)
    elif cur is not None and line.strip() and not line.startswith("#"):
        p, n = line.rstrip("\n").split("\t")[:2]
        cur.append((p, int(n)))
for g in groups:
    assert len(g) <= 20, g
    assert len(g) == 1 or sum(n for _, n in g) <= 2500, g
assert any(g == [("src/big/huge.py", 3000)] for g in groups), "huge file not alone"
EOF

# High-risk paths are listed first, and vendored code does not drive triage.
gid=$(grep "	src/routes/auth.ts	" "$D/files.txt" | cut -f5)
first=$(echo "$out" | sed -n '/^## Full audit/,/^## /p' | grep -m1 '^- G')
echo "$first" | grep -q "^- $gid \[high\]" && ok || bad "auth route group $gid not first: $first"
grep -q "^## $gid \[high\]" "$D/groups.txt" && ok || bad "auth route group not high priority"
grep -q "^src/routes/auth.ts	[0-9]*	high-risk path$" "$D/groups.txt" && ok || bad "auth route not marked high-risk"
echo "$out" | grep "api / routes" | grep -q node_modules && bad "vendored file in api signal" || ok
echo "$out" | grep "personal data" | grep -q "src/routes/auth.ts" && ok || bad "personal data signal missed"
echo "$out" | grep "personal data" | grep -q node_modules && bad "vendored file in personal data signal" || ok

echo "$out" | grep -q "vendored/generated, by top-level path: dist/ (1), gen/ (1), node_modules/ (1)" && ok \
  || bad "vendored directories not all listed"

# An extension-less file replaced by a FIFO in the working tree must not hang prepare.
echo plain > bin/tool; git add bin/tool; git commit -qm tool
rm bin/tool; mkfifo bin/tool
if timeout 30 python3 "$RV" prepare --full >/dev/null 2>&1; then ok; else bad "prepare --full hung or failed on a FIFO"; fi
rm bin/tool; git checkout -q -- bin/tool

# The secret scan still covers the whole history, including a file deleted since.
echo "$out" | grep -q "SECRET? \[LIKELY REAL\].*src/keys.ts" && ok || bad "history secret missed"

# A normal review still gets its diff.
echo more >> docs/guide.md; git commit -qam more
python3 "$RV" prepare >/dev/null
[ -f "$(run_dir)/diff.patch" ] && ok || bad "normal review lost its diff"

# After a full audit, its verdict unlocks a first push of the whole history.
python3 "$RV" install-hook >/dev/null
python3 "$RV" prepare --full >/dev/null
python3 "$RV" mark --verdict pass >/dev/null 2>&1 && bad "pass recorded over a likely secret" || ok
python3 "$RV" mark --verdict pass --secrets-cleared --note "partial audit: 3 of 4 groups reviewed" >/dev/null \
  && ok || bad "mark after full audit failed"
grep -q "^mode=full$" .git/ravenwatch/status && ok || bad "status lacks full mode"
git $P -q -u origin main 2>"$T/err" && ok || { bad "push after full audit refused"; cat "$T/err"; }

echo "full: passed=$pass failed=$failn"
[ "$failn" -eq 0 ]
