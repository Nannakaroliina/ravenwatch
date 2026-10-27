# Changelog

## 0.3.0 — 2026-10-27

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
