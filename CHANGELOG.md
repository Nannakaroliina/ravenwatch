# Changelog

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
