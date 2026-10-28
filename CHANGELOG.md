# Changelog

## 0.4.1 — 2026-10-28

Fixes from the first full-repository audit.

- Guard: the helper shortcut only covers a single-line command (a second line used to skip every check); variable names built from other variables (`RAVENWATCH_DIS${X}ABLE`, `GIT_CONF${X}IG_*`, `git config ali${X}as.…`) are caught, and a pushing command may not use shell variables at all; paths through variables are followed (literal assignments, `for` loops, `$(mktemp)`, the environment) and a write to a path that can't be worked out is refused; a `cat` heredoc only counts as data where `cat` really is a command (not inside quotes or another heredoc); git options that write files (`--prefix=`, `-o`, `--output`) are path-checked; a `#` after an escaped space is not a comment; `--attr-source` takes a value, and `push` after an unknown git option is refused; aliases of aliases are followed, and an alias that adds `-c`/`-C` to a push is refused.
- Hook: `push.recurseSubmodules=on-demand|only` and `submodule.recurse=true` are refused in repositories with submodules (found from the pushed commits, HEAD, the index, a `.gitmodules` file or `.git/modules`), as the README already said; of the two settings, the one git reads last wins, as in git itself. **Re-run /ravenwatch:install-git-hook in each gated repository after updating**: the guard refuses Claude's pushes while the installed hook is out of date. If you set `submodule.recurse=true` globally, set `push.recurseSubmodules=check` in repositories with submodules.
- Classifier: code is recognised by its extension before the docs, secret-file, infra and config rules (`src/documents/upload.ts`, `src/auth/credentials.ts` and `src/infra/repository.ts` are code), the docs rule matches whole names only, more code extensions are known, and extension-less scripts count as code in every mode.
- Scan: the repository's `.gitattributes` (`-diff`, `binary`, textconv) can no longer hide a file from the secret scan, the diff or the per-commit patches, and a NUL byte no longer hides one from the scan; binary files in a diff and code-like files left out of a full audit's groups are listed by path; non-ASCII paths are no longer quoted into misclassification; the history scan has a 4-minute budget, then scans the files at HEAD and says the history scan was incomplete.
- Full audits and checks: `prepare`, `checks` and `mark` refuse while tracked files are marked skip-worktree or assume-unchanged, and a full audit refuses (and `mark` refuses its pass/warn) while tracked files have uncommitted changes, since the reviewers read the files on disk.
- Review skill: `prepare` gets a 10-minute Bash timeout; an incomplete history scan is reported as a finding; infrastructure written as code (CDK, SST, Pulumi, `*-stack.ts`) and framework config (`*.config.ts`) bring in infra-config-auditor through a new signal.
- Guard, after the first review of these fixes: line continuations and `$'…'` quoting can't hide a hook-skipping flag; an empty-body `cat` heredoc no longer hides the commands after it; `$PWD` after a `cd` counts as unknown, and environment values stay possible next to assignments; the shell-variable rule applies to git pushes only (`docker push "$IMAGE"` is fine); quoted `$(mktemp …)`, `${X:-default}` and `${X%suffix}` are followed; curl, wget, tar and unzip are only checked where an option names an output file; reads through a variable are refused only when the path names `.git` or `ravenwatch`.
- Helper, after the same review: `.tfvars` and secret files under test directories are reported as sensitive files again; skip-worktree/assume-unchanged files only block when their content differs from the commit, and never block `accepted`; untracked content inside submodules doesn't count as a dirty tree; the history scan and its fallback share one budget.
- Checks: `tests/run.sh` drops the checks runner's push shim for its own throwaway remotes, so ravenwatch's suite can run as an approved check.
- Guard, after the second review: all bypass-flag checks go through one function over the same shell views (as written, continuations joined, `$'…'` decoded, quotes and variables removed), per command; `$'…'` with escapes the shells read differently (`\c`, `\0`, short `\x`/`\u`/`\U`) is refused, and `$'…'` is refused in any command that mentions git (a `$` at the end of a quoted pattern no longer counts); `${X#…}`/`${X%…}` are trimmed like the shell does; a command name or git subcommand from a variable is followed when known and refused when not; output options are found in clusters and attached values (`-sSo f`, `-of`); `$PWD` is the session's directory; `$` inside single quotes is text, and sed and perl always count as writers; a `cat` heredoc with an unquoted delimiter keeps its body when it has command substitutions; the submodule check reads the two settings in git's order, looks for submodules only when recursion is on, and no longer accepts `--no-recurse-submodules`.
- Helper, after the second review: skip-worktree/assume-unchanged/sparse files missing from disk block like changed ones, and no paths go on the command line; over-long lines are scanned in overlapping 1 MB pieces instead of being cut; git is stopped at the scan deadline even when it produces no output, and the worktree scan has a budget too; the history gets 180 s of the 240 s.
- Tests: new round-11 suite (including the CDPATH, submodule-config and modified-hook gaps the audit found); the FIFO test no longer needs `timeout`, which macOS doesn't have.

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
