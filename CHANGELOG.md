# Changelog

## 0.5.1 — 2026-10-28

Fixes from the review of 0.5.0.

**Upgrade:** re-run /ravenwatch:install-git-hook in each gated repository. If push recursion into submodules is on anywhere (for example `submodule.recurse=true` in your global config), set `push.recurseSubmodules=check` in each gated repository's own config: since 0.4.1 the hook (and Claude's guard) refuse every push while recursion is on, with or without submodules.

- Guard:
  - A command that isn't plain may only run read-only programs (a short allowlist: echo, cat, grep, ls, head, wc, sort/uniq without an output file, curl without output options …), and must not write to a file. 0.5.0 instead looked for risky words, which globbed program names (`/bin/c?`), globbed paths (`.gi?`) and writers it didn't list (`uniq`, `sort -o`) got past. More commands are refused as a result (`docker push "$IMAGE"`, `cd "$DIR" && npm test`); the refusal says that anything in single quotes is plain.
  - In plain commands, a program name with glob characters (`/usr/bin/gi[t] push`) is refused, and a globbed word counts as possibly any program in `xargs`, `find -exec`, `sh -c` and pushes run through wrappers.
  - The `-m "$(cat <<'EOF' … EOF)"` commit message ends where the shell ends it: at the first line that is exactly the delimiter. Anything other than `)` after that line makes the command not plain (0.5.0 could run on to a later delimiter line and miss the commands in between).
  - A partly quoted heredoc delimiter (`<<"E"OF`, `<<EOF'X'`) is no longer mistaken for a shorter one; such a heredoc isn't plain.
  - A `~name` word is plain only for a user that exists (zsh reads `~X` as the directory in `$X`).
  - One rule decides which programs write or run code (writers, output-option programs, shells, interpreters, wrappers, git, globbed names); more writers are known (`ed`, `sponge`, `shred`, `uniq`, `sort`, `base64`, `scp` …), so `ed ~/.gitconfig` and `xargs sponge` are refused.
  - Quote state is no longer read from inside an earlier heredoc body (a `don't` there made a second heredoc look unquoted).
- `prepare`'s refusal for skip-worktree or sparse files no longer suggests recording `accepted`: there is no run to record it on yet.
- Tests: new `tests/round15.sh`.

## 0.5.0 — 2026-10-28

The Claude guard no longer tries to work out what shell variables, substitutions and comments do. Four review rounds in a row found a new way around that guesswork, and some of the fixes opened the next one. It now parses only **plain** commands, and refuses anything else that could matter.

**Upgrade:** re-run /ravenwatch:install-git-hook in each gated repository. **Behaviour change:** some commands Claude could run before are now refused (see the README "Limits" section): writes or git commands that use variables, `$(…)`, backticks, subshells or braces. Claude is told to write the values out, split the command or use the Write/Edit tools.

- Guard:
  - Plain commands (literal words, quoted strings without `$`/backticks/backslashes in double quotes, operators, plain-word comments, heredocs with plain bodies, and Claude Code's `-m "$(cat <<'EOF' … EOF)"` commit messages) get every check as before, on an exact parse.
  - Any other command is let through only when its text can't touch git, write a file, run other code or change the environment; otherwise it gets one refusal saying how to rewrite it. Reads through variables (`echo $HOME`, `cat "$F"`) keep working.
  - Gone: the variable tracking (`shell_vars`, `expand_vars`, `${X%…}` trimming, the `$(mktemp)` rules) and the comment and quote special cases in the old scanner. This closes the round-7 findings (a `#` after a backtick or `<(…)` hiding the rest of the line) and every earlier variant of them.
  - The plugin's own helper gets no shortcut any more: its arguments are checked like any other command's, so zsh glob qualifiers (`*(e:…:)`) or `=(…)` can't run code through it.
  - A push can't come with `export`/`NAME=` changes in the same command (`HOME=/tmp/x git push` reads another gitconfig), or from text fed to a shell or interpreter (`cat <<EOF | sh`, `printf 'git push' | sh`).
  - `xargs`/`parallel` with a program that writes or runs code, and `find` with `-exec` of one or with `-delete`/`-fprint`, are refused: their paths come from input the guard can't see.
  - The timeout and crash fallbacks share one rule for what to refuse.
- `mark` takes no abbreviated options and no repeated ones (`--sc`, `--verdict block … --verdict pass`): the permission prompt must show exactly what is recorded.
- Infrastructure folders (`infra/`, `terraform/`, `cdk/` …) bring in infra-config-auditor at any depth, not only at the top of the repository.
- Tests: new `tests/round14.sh`; older suites updated where 0.5.0 deliberately refuses what they allowed.

## 0.4.3 — 2026-10-28

Fixes from the review of 0.4.2.

**Upgrade:** re-run /ravenwatch:install-git-hook in each gated repository.

- Guard, bypasses closed:
  - A `#` right after `(`, a subshell's `)`, `$(` or an opening backtick starts a comment, as in bash. 0.4.2's single quote scanner had lost this, so a command could hide a push or a write behind `(#'…`.
  - Variables now fail closed. Any variable the command sets in a way the guard doesn't follow counts as unknown, and writes through it are refused: `X+=…`, `X[i]=…`, `X=(…)`, `${X:=…}`, `printf -v X`, `declare -n`, `let`, `((…))`, `unset` and `select`. So does a value that reads another variable the same command sets (`HOME=.g; V=${HOME}it/…`). `$(mktemp)` counts as a temp path only when the command doesn't set TMPDIR and gives no `-p` directory or template path.
  - Alias chains: options and arguments from every level count, so `aa = bb --recurse-submodules=…` with `bb = push` is refused like a one-level alias. An alias that hides a builtin of the same name (`status = status -sb`, which git ignores) no longer makes the guard refuse the builtin.
- Secret scan out of time: the review skill always reports SCAN-1, and asks the owner before `--scan-incomplete-accepted`. A clean gitleaks run is supporting evidence only, since the repository can configure gitleaks. `prepare` no longer says "nothing to review" after a cut scan.
- Tests: new `tests/round13.sh`.

## 0.4.2 — 2026-10-28

Fixes from the review of 0.4.1.

**Upgrade:** re-run /ravenwatch:install-git-hook in each gated repository (the guard refuses Claude's pushes while the installed hook is out of date).

- Guard, bypasses closed:
  - A variable whose value goes on after a quote or `$(…)` (`X='/repo'/.git`, `X="$HOME"/….git`, `X=$(mktemp -d)/../…`), or whose bare value has quotes or backslashes inside, used to be read only up to that point, so a write through `"$X/hooks/pre-push"` or into the verdict state got through. Such a value now counts as unknown, and writes through it are refused.
  - An alias chain the guard can't follow to its end (more than five levels, or a loop) is refused instead of allowed.
  - Bash writes to git config files outside a git directory (`~/.gitconfig`, `~/.config/git/config`) are refused, as Write/Edit already were: they could add aliases or a hooks path.
  - `segments()` now reads quotes, comments and line continuations through `quoting()`, so the guard has one quote scanner instead of two that disagreed (`$'…'`, quotes inside `"$(…)"`).
- Secret scan:
  - A lone CR no longer ends a line: text after it (CR-only files, binary blobs) used to go unscanned, and a CR followed by `diff ` hid the rest of the hunk.
  - When the scan runs out of time, `mark` refuses pass and warn unless the owner confirms the range is clean with `--scan-incomplete-accepted` (ideally after gitleaks over the full history). The verdict records it. The review skill reports both scan-incomplete warnings as SCAN-1.
- A skip-worktree or assume-unchanged file that differs from the commit blocks a review only when it is among the reviewed files, or in checks and full audits. A local override elsewhere is listed in the context for the reviewers instead, so `accepted` is reachable again. The refusal no longer suggests committing the file; it gives the stash round trip.
- Tests: new `tests/round12.sh` covers all of the above, including NUL-byte and `binary`-attribute files in the scan, the HEAD fallback after a history scan out of time, and git killed at its deadline.

## 0.4.1 — 2026-10-28

Fixes from the first full-repository audit and four review rounds of those fixes.

**Upgrade:** re-run /ravenwatch:install-git-hook in each gated repository. The guard refuses Claude's pushes while the installed hook is out of date. If push recursion into submodules is on anywhere (for example `submodule.recurse=true` in your global config), set `push.recurseSubmodules=check` in the repository's own config.

- Guard, bypasses closed:
  - The helper shortcut only covers a single-line command; a second line used to skip every check.
  - Every hook-skipping check runs over the same views of each command (as written, line continuations joined, `$'…'` decoded, quotes and variables removed), for the whole command, each part of it, and alias values. Names built from variables (`RAVENWATCH_DIS${X}ABLE`) are caught.
  - `$'…'` with escapes the shells read differently (`\c`, `\0`, `\N`, a `\x`/`\u`/`\U` without all its digits), or that can't be decoded, is refused anywhere, and any `$'…'`/`$"…"` is refused in a command that mentions git. One quote scanner decides what is quoted, including inside `"$(…)"` and backticks.
  - Paths through variables are followed: literal assignments, `for` loops, `$(mktemp)`, the environment, `$PWD` (the session's directory), `${X:-default}`, `${X%…}`/`${X#…}`. A write to a path that can't be worked out is refused, and so is a command name or git subcommand that comes from an unknown variable. A git push may not use shell variables.
  - A `cat` heredoc body counts as data only where `cat` really is a command (one quote scanner, which opens a fresh context at `$(`, backticks and a plain `(` subshell or case pattern, so a `)` can't close a substitution early); the first line's remainder must be redirections only with no quote that could swallow the body; the body ends at the shell's real delimiter (also when empty); an unquoted delimiter with command substitutions keeps it; and a command that redefines `cat` (a function, alias, or `PATH=`) keeps every body. `cat > file <<'EOF'` works like `cat <<'EOF' > file`.
  - git options that write files (`--prefix=`, `-o`, `--output`) and the output options of curl, wget, tar and unzip are path-checked, in clusters and attached forms too (`-sSo f`, `-of`). sed and perl count as writers; `$` inside single quotes is text.
  - A `#` after an escaped space isn't a comment; `--attr-source` takes a value, and `push` after an unknown git option is refused; aliases of aliases are followed, and an alias that adds `-c`/`-C` to a push is refused.
  - A glob with too many wildcard path components is refused rather than risking a crash; when a check crashes or runs out of time, any command with a push, a writer, an output option, a variable or a pattern is refused.
- Hook and guard, submodules: a push is refused whenever push recursion is on (`push.recurseSubmodules` other than check/no, or `submodule.recurse` other than false — the setting git reads last wins, and values such as `2` count as on), with or without submodules found. `--no-recurse-submodules` doesn't count as a way out, because the hook can't tell it from the value of `-o`.
- Classifier: code is recognised by its extension before the docs, secret-file, infra and config rules (`src/documents/upload.ts`, `src/auth/credentials.ts` are code); the docs rule matches whole names only; more code extensions are known; extension-less scripts count as code in every mode. `.tfvars` and secret files under test directories are still reported as sensitive. Infrastructure written as code (CDK, SST, Pulumi, `*-stack.ts`) and framework config (`*.config.ts`) bring in infra-config-auditor through a new signal.
- Secret scan:
  - The repository's `.gitattributes` (`-diff`, `binary`, textconv) can't hide a file from the scan, the diff or the per-commit patches, and a NUL byte can't hide one from the scan.
  - Over-long lines are scanned in overlapping 1 MB pieces that carry the line's own marker, and `+++` counts as a file header only outside a hunk, so content — including a merge diff's `++` lines — can't pass itself off as a header or a deletion to go unscanned.
  - Non-ASCII paths are no longer quoted into misclassification.
  - The scan has a 4-minute budget (3 for the history, the rest for the files at HEAD if the history runs out), git is stopped at the deadline, and an incomplete scan is reported. Binary files in a diff and code-like files left out of a full audit's groups are listed by path.
- Files on disk that differ from the commit: a skip-worktree, assume-unchanged or sparse-checkout file that is **changed** on disk blocks a review in every mode (it could show the reviewers code that isn't committed); one that is only **missing** blocks a diff review when it is among the reviewed files, and always blocks checks and full audits (those read the whole tree) — so an ordinary sparse checkout still reviews normally, but with blocking checks it can only be `accepted` or reviewed from a full checkout. A full audit also refuses uncommitted tracked changes (untracked content inside submodules doesn't count). `mark` re-checks before pass/warn; `accepted` is never blocked by it. (Narrowed in 0.4.2: see above.)
- Checks: `tests/run.sh` drops the checks runner's push shim for its own throwaway remotes, so ravenwatch's suite can run as an approved check.
- Review skill: `prepare` gets a 10-minute Bash timeout; an incomplete history scan is reported as finding SCAN-1.
- Tests: new round-11 suite; the FIFO test no longer needs `timeout`, which macOS doesn't have.

## 0.4.0 — 2026-10-27

- Whole-repository review: `/ravenwatch:review --full` is now a real audit of everything at HEAD. `prepare --full` splits the code into review groups (at most 20 files and 2,500 lines each, related paths together, high-risk paths first) written to `groups.txt`, and leaves lockfiles, vendored, generated, minified and binary files out of the groups (they are still secret-scanned across the whole history). It no longer writes a diff of the whole repository or per-commit patches, and vendored code no longer drives reviewer triage.
- The review skill runs one bug-hunter and one security-auditor per group and the other specialists once for the repository, in waves of at most 12 agents, asks the owner before auditing more than 10 groups, and reports coverage per group. Reviewers and the verifier keep pre-existing findings at any severity in a full audit.
- Tests: new full-audit suite.

## 0.3.5 — 2026-10-27

- Guard: `grep --exclude-dir=.git`, `tar --exclude=.git` and other pattern options are no longer refused; `cd` behind `builtin`, `command`, `if`, `time` or `!` is followed, and `eval cd` makes the directory unknown; globs matching more than 2000 paths are refused as uncheckable; when its 10 s budget runs out the guard decides at once (refusing pushes, writes and patterns) instead of raising an exception that file-system code could swallow; git timeouts inside the guard count as timeouts.
- Secret scan: `$NAME` and `{name}` count as placeholders only when they look like a variable or template field, and `test…`/`…mock` only in values without digits, so `$uperSecret2024` or `Testarossa2024` are flagged; different keys with the same prefix in one file are listed separately.
- Checks: untracked files count even when `status.showUntrackedFiles` hides them, and a failing `git status` stops the checks instead of passing as a clean tree.
- Tests: new round-10 suite, including popd and subshell cases that only that tracking can catch.

## 0.3.4 — 2026-10-27

- Guard: the helper is exempt only as the script of a `python3` call (round 8 let any command overwrite it), and that call refuses uncommitted plugin changes even with `2>&1` or a pipe; `>|` and `&>` count as redirects; `tree`, pagers and `rg` no longer count as read-only; `--opt=PATH` values are checked; every directory a command may be in is checked (`cd x;`, `popd`, subshells), absolute paths are checked after a `cd` it can't follow, and relative paths that could reach hooks or state are refused then; globs naming files that don't exist yet are checked against their directory; pushes are gated in every directory they may run in; the heredoc regex can no longer backtrack exponentially, and the guard decides within 10 s.
- Secret scan: an example key no longer hides a real key with the same first characters; template values (`{password}`, `$TOKEN`, `%s`) in URLs are placeholders.
- Checks: results are kept per commit and approved brief, so preparing a new run doesn't forget a failure; `mark` and `checks` refuse a run prepared under a different brief; only one checks run per commit at a time; duplicate check names are refused; a check that leaves files behind says which files and what to do, in `checks`, `mark` and the re-run refusal, and checks that didn't run are listed.
- Brief: the accepted-risks heading must be written exactly `## Accepted risks` (reworded and underlined headings are refused, and the verifier ignores any other section); CRLF briefs are accepted.
- Agents: every reviewer treats repository text as data and ignores claims addressed to it; supply-chain-auditor runs only `osv-scanner` on lockfiles; `--secrets-cleared` needs the owner's own answer for each hit. The review skill treats any non-pass blocking check result as HIGH and explains each status.
- `mark` writes the per-commit verdict before `status`. README lists all stored state.
- Tests: new round-9 suite; the round-8 `--checks-skipped` test now expects a fresh run to remember a failure.

## 0.3.3 — 2026-10-27

- Brief: accepted risks are counted correctly on the approval screen; a second `## Accepted risks` section, wrapped lines in briefs without frontmatter and invisible or bidi control characters are refused; briefs are capped at 16 KB.
- Secret scan: every match on a line is judged (an example value no longer hides a real one); `Credentials in URL` judges the password, not the path; a test-ish key name (`test_api_key = …`) marks a `name = value` pair as a placeholder.
- `mark` refuses pass/warn while a blocking check of the approved brief never ran in this run, unless the owner skipped the checks (`--checks-skipped`, recorded); warn is refused over a failed blocking check like pass.
- Checks: refuse to run when the approved brief changed since `prepare`; a check that changes the working tree is recorded as `dirtied-tree` and stops the rest; `pushurl` is redirected as well as `url`; result keys can't collide; timeouts use a monotonic clock.
- Guard: follows `cd` for redirect targets and plain file names, refuses `cd` into the installed plugin, lets reads of the plugin's files and helper calls with redirects through, protects more run files, and its refusals say what to do instead.
- Docs: the push redirect during checks is best-effort, checks run unreviewed code at HEAD, and committed changes to ravenwatch's own code are trusted when developing it.
- Author name is Nanna Karoliina throughout.
- Tests: new round-8 suite.

## 0.3.2 — 2026-10-27

- Secret gate: the placeholder heuristic now looks at the matched value only, so `process.env.KEY ?? "sk_live_…"` and keys on lines mentioning "latest"/"test" count as likely real; merge-commit resolutions are scanned too.
- Brief approval shows the whole file first and refuses accepted risks that aren't one-line `- ` bullets in a single section, so nothing reaches the reviewers that the owner didn't see.
- Checks: pushes to the repository's remotes are redirected through git's own config (covering absolute git paths and aliases) and refused by the pre-push hook while checks run; results are also written machine-readably, and `mark` refuses pass/warn while a blocking check failed or didn't finish; output is capped at 50 MB; checks stay in the caller's session; the untracked-files refusal lists the files and suggests `git stash -u`.
- Guard: refuses edits to the installed plugin; when developing ravenwatch itself, the helper refuses to run with uncommitted changes to its own code; fewer false denials when a path merely contains "ravenwatch".
- `status` reports the current commit's own verdict; `install-hook` prints the installed hook's hash; Husky repos get a way-out message; redaction covers Authorization headers, cookies and quoted values with spaces.
- Tests: suites run against a private copy of the plugin and clear gate-related environment; new round-7 suite (HEAD moved, `--since-last` after BLOCK, keeping a foreign hook, interrupted checks, plugin self-protection).

## 0.3.1 — 2026-10-27

- Push gate: each reviewed commit keeps its own verdict (reviewing another branch no longer cancels one); refusals name the actual next step (fetch, fix the setting, re-review) instead of always "review again"; a BLOCK refusal mentions accepting the risk.
- `mark` won't unlock a push while the secret scan has likely-real hits, unless the owner passes `--secrets-cleared`; the review profile (`quick`/`standard`) is recorded.
- Brief approval is two steps bound to a content hash (`trust-brief`, then `trust-brief --approve <sha256>`), and shows every accepted risk and the audience in full. Inline `# comments` in the brief are allowed.
- Checks: refuse to run with uncommitted changes, run with `git push` disabled, save each result as it finishes (an unfinished check counts as failed), kill the whole process group, cap output, and `--only` appends instead of erasing earlier results; generic `key = value` secrets are redacted.
- Claude guard: honours shell comments and line continuations, follows `cd` targets and globs, refuses writes inside any git directory (also not-yet-created and bare/separate ones) and to ravenwatch state names anywhere, and no longer refuses all edits on an internal error.
- Report drafts live in a private per-run temp directory and are read without following symlinks.
- Tests: `tests/run.sh` runs end-to-end suites for the gate, guard, brief and checks.

- Project brief (`.ravenwatch.md`) and `/ravenwatch:init-brief`: describe the project, its audience, data, conventions and accepted risks; every reviewer reads it. Only an owner-approved snapshot (`trust-brief`, stored in `.git/ravenwatch/`) is acted on; the review flags when the file differs from it. `--private` keeps the brief out of the repository.
- Checks: the brief can list your own commands (tests, type checks, linters). `ravenwatch.py checks` runs them from the approved snapshot with `CI=1`, timeouts and redacted output, after your confirmation. A failing blocking check is a HIGH finding.
- `privacy-reviewer`: personal data in logs, URLs, client storage or outside services, tracking before consent, special categories, retention and deletion, new processors. Can block (max HIGH).
- security-auditor and loophole-hunter now cover AI/LLM features: prompt injection, model output reaching sinks, keys in prompts, over-permissioned tools, unmetered paid AI endpoints, rules enforced only by the prompt.
- resilience-reviewer now covers cloud and API cost blowups.
- supply-chain-auditor now checks licences of new dependencies and added fonts/media (max MEDIUM).
- finding-verifier: `ACCEPTED` verdict for findings matching the brief's accepted risks (never CRITICAL or leaked credentials); checks for PRIV- and CHK- findings.
- `prepare` adds a personal-data/tracking signal and a project-brief section; `status` shows the brief's state.

## 0.2.0 — 2026-10-27

- Four new reviewers, run when relevant and skipped with `--quick`:
  - `impact-analyzer`: blast radius of a change — dependents of changed exports, routes and schemas, breaking API changes, migration safety, new env vars, deploy order and rollback. Can block.
  - `ux-reviewer`: user flows, loading/error/empty states, accessibility (WCAG 2.2 AA), mobile layouts, copy and visual consistency. Can block only when a user can't complete a core task.
  - `test-reviewer`: risky changed behaviour without tests, tests that can't fail, weakened or skipped tests, flaky patterns. Warns, never blocks.
  - `design-reviewer`: architecture fit, duplication, coupling, data modelling and over-engineering. Warns, never blocks.
- `prepare` now reports triage signals (UI, schema/migration, API/entry points, deploy config, deleted files, code changed without tests).
- `--quick` runs only the core reviewers.
- finding-verifier has type-specific checks for the new reviewers; chat summaries tag each finding with its area.

## 0.1.0 — 2026-10-27

First release.

- `/ravenwatch:review`: multi-agent pre-push review (bug-hunter, security-auditor, loophole-hunter, resilience-reviewer, supply-chain-auditor, infra-config-auditor) with a finding-verifier pass and a BLOCK/WARN/PASS verdict.
- Deterministic pre-scan for secrets across every commit in the push range, sensitive files, large files and `.gitignore` gaps.
- Git `pre-push` hook (`/ravenwatch:install-git-hook`) as the authoritative gate: it checks the exact objects git is pushing, asks the remote which branches and tags it already has (verified against git's own view of the push target), and requires every new commit to be covered by a passing or owner-accepted review, with only the reviewed commit allowed as a new tip. Works in SHA-256 repositories.
- Claude guard hook that refuses Claude's pushes where the git hook isn't installed, refuses ways to skip or redirect it (`--no-verify`, hooks-path overrides, `GIT_CONFIG_*`, `-c`, aliases, includes, `send-pack`, receive-pack overrides), and refuses edits to `.git/hooks`, git config files and the verdict state.
- Reviewers get per-commit patches as well as the net diff, so changes made and later undone inside a push are reviewed too.
- Verdicts are tied to the reviewed range: `mark` refuses if HEAD moved since `prepare` or the run never finished, `--worktree` reviews never unlock a push, and `--since-last` only builds on a passing review. Recording a verdict always needs the owner's permission.
