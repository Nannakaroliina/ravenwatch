# ravenwatch

A code reviewer for people who work alone. Before anything reaches GitHub, a team of specialist agents reviews your unpushed commits with an emphasis on **bugs, loopholes and security** — and also checks the blast radius, privacy, user experience, tests and design, and runs your own tests if you want — a skeptical verifier throws out false alarms, and a push gate stops `git push` until the review passes.

## How it works

```
/ravenwatch:review
   │
   ├─ 1. prepare      what's about to be pushed (unpushed commits, or full history on a first push)
   │                  + fast deterministic scan: secret patterns, sensitive files, large files, .gitignore gaps
   │                  (scans every commit in the range, so a secret added then deleted is still caught)
   │
   │                  + reads your approved project brief (.ravenwatch.md) and runs its checks (tests, types, lint)
   │
   ├─ 2. triage       picks specialists from what changed
   │
   ├─ 3. specialists  run in parallel ───────────────────────────────────────────────┐
   │    core (can block)                                                              │
   │      bug-hunter            logic errors, edge cases, broken caller contracts     │
   │      security-auditor      untrusted input → dangerous sinks, authn/authz, crypto│
   │      loophole-hunter       business-logic abuse: client trust, races, replays,   │
   │                            limit bypass, workflow skipping, captcha bypass       │
   │      resilience-reviewer   failure paths, partial writes, timeouts, leaks, DoS   │
   │      supply-chain-auditor  new deps, typosquats, install scripts, CVEs, CI pins  │
   │      infra-config-auditor  secrets, wrangler/AWS/IaC, GitHub Actions, Docker     │
   │    broader (skipped with --quick)                                                │
   │      impact-analyzer       blast radius: dependents, breaking API/schema changes,│
   │                            migrations, env vars, deploy order, rollback  (blocks)│
   │      privacy-reviewer      personal data in logs/URLs/3rd parties, consent,      │
   │                            retention, special categories (GDPR-minded) (≤ HIGH)  │
   │      ux-reviewer           flows, states, accessibility, mobile, copy  (≤ HIGH)  │
   │      test-reviewer         risky code without tests, tests that can't fail,      │
   │                            weakened/skipped tests, flakiness         (≤ MEDIUM)  │
   │      design-reviewer       architecture fit, duplication, coupling, data model,  │
   │                            over-engineering                          (≤ MEDIUM)  │
   │                                                                                  │
   ├─ 4. finding-verifier  tries to disprove every MEDIUM+ finding, and sets aside ◄─┘
   │                       ones matching your brief's accepted risks
   │
   ├─ 5. verdict      BLOCK (critical/high) · WARN (medium) · PASS
   │
   └─ 6. report       short summary in chat, full report saved in .git/ravenwatch/reports/
                      verdict recorded for the push gate
```

## Components

| Component | What it does |
|---|---|
| `/ravenwatch:review` | Runs the review. Arguments: none (unpushed commits), `--since-last` (only commits since the last passing review), `--base <ref>`, `--worktree` (uncommitted changes; never unlocks a push), `--full` (whole repo, e.g. before making it public). Add `--quick` to any of these to run only the core reviewers. |
| `/ravenwatch:init-brief` | Drafts the project brief from your repo (stack, commands, routes, data), asks you a few questions, and asks you to approve it. `--update` edits an existing brief, e.g. to accept a risk permanently. |
| `/ravenwatch:install-git-hook` | Installs the git `pre-push` hook in the current repo. This hook is the real gate: git hands it the exact commits being pushed, it asks the remote what it already has, and it requires every new commit to be covered by a PASS, WARN or owner-accepted review. Works for pushes from Claude, the terminal or any app. `--uninstall` removes it. |
| 12 agents | The eleven specialists above plus `finding-verifier`. All are read-only and never run your code; only the checks you approve in the brief are run. |
| Claude guard hook | Keeps Claude from getting around the git hook: refuses Claude's pushes in repos where the hook isn't installed, refuses `--no-verify`, hooks-path overrides, `send-pack` and similar, and refuses edits to `.git/hooks`, `.git/config` and the verdict state. |

## What blocks a push

| Reviewer | Highest severity | Effect |
|---|---|---|
| bug, security, loophole, resilience, deps, config, impact | CRITICAL | can BLOCK |
| ux-reviewer | HIGH, only when a user can't complete a core task (including accessibility blockers) | can BLOCK |
| privacy-reviewer | HIGH (personal data leaking by design, special categories, real personal data committed) | can BLOCK |
| your checks (from the brief) | a failing `blocking: true` check is HIGH; a failing non-blocking check is MEDIUM | can BLOCK |
| licence findings | MEDIUM | can WARN, never BLOCK |
| test-reviewer, design-reviewer | MEDIUM | can WARN, never BLOCK |

The broader reviewers only run when they're relevant (privacy-reviewer when the change touches personal data, forms, logging, cookies, analytics or outside services): impact-analyzer for schema, API, route, env or deleted-file changes; ux-reviewer for UI files and user-facing text; test-reviewer for code changes of 20+ lines; design-reviewer for larger changes or new modules, schemas or endpoints.

## Project brief

`.ravenwatch.md` tells the reviewers what your project is, so they raise fewer false alarms and stop repeating things you've decided to accept. Create it with `/ravenwatch:init-brief`.

```markdown
---
audience: public, EU
distribution: closed-source commercial
checks:
  - name: tests
    run: npm test
    blocking: true
  - name: lint
    run: npm run lint
    blocking: false
skip: []            # optional: impact-analyzer, ux-reviewer, test-reviewer, design-reviewer, privacy-reviewer
---
# Cabin booking
## About
## Public and private parts
## Data
## Conventions
## Accepted risks
- WINTER discount code is public on purpose (marketing), public/book.js — 2026-10-27
```

**Only a version you approve counts.** Approving (`trust-brief`, which Claude asks you to confirm) stores a snapshot inside `.git/ravenwatch/`. Checks always run from that snapshot, so nobody — including Claude — can add a command, skip a reviewer or accept a risk by editing the file; the review tells you when the file differs from what you approved. Checks run with `CI=1`, a timeout and redacted output, and each run asks for your confirmation first. Accepted risks only cover the specific issue and place they name, never CRITICAL findings or leaked credentials.

For public repos, keep the brief private (`init-brief` offers this): a committed brief tells everyone which risks you've accepted. Private means git-ignored in this clone only.

## Setup

Requirements: `git` and `python3` (on macOS both come with the Xcode Command Line Tools).

This repository is both the plugin and its own marketplace. In Claude Code:

```
/plugin marketplace add Nannakaroliina/ravenwatch
/plugin install ravenwatch@ravenwatch
```

Then restart Claude Code (or run `/reload-plugins`). To work on the plugin itself, add your local clone instead: `/plugin marketplace add ~/path/to/ravenwatch`.

Then run `/ravenwatch:install-git-hook` once in each repository you want gated. Claude can't push in a repository until the hook is installed there.

Optional: if [gitleaks](https://github.com/gitleaks/gitleaks), `osv-scanner`, `pip-audit` or similar tools are installed, the review uses them automatically.

## Day-to-day

1. Commit as usual.
2. Run `/ravenwatch:review`.
3. BLOCK → ask Claude to fix the findings, commit, then `/ravenwatch:review` again.
4. Push.

If you deliberately want to push despite a BLOCK, tell Claude you accept the risk; it records your reason. Confirmed leaked credentials can't be accepted this way — rotate them first.

## Escape hatches

| Situation | Do this |
|---|---|
| Turn every gate off for a session | start Claude Code with `RAVENWATCH_DISABLE=1` |
| Bypass the git hook once (terminal only; Claude is refused) | `git push --no-verify` |
| See the last verdict | `python3 <plugin>/scripts/ravenwatch.py status` |

## Where things are stored

Everything lives inside the repository's `.git/ravenwatch/` folder, so nothing is ever committed: `status` (latest verdict and the commit range it covers), `history.log`, `reports/`, and `runs/` (diff and context of the last 20 runs).

## Limits

- The reviewers are AI models: they reduce risk, they don't certify code as safe. Keep tests, dependency updates and secret scanning in CI too.
- The gate checks that the commit you push was reviewed; it does not stop you editing history afterwards.
- Everything here runs on your machine. The git hook can't be fooled about *what* is pushed, but a determined agent with shell access could still disable it in a way the Claude guard doesn't recognise (for example a script that rewrites the hook). For a guarantee, also protect the branch on GitHub (required reviews or status checks).
- The Claude guard matches command text broadly, so it occasionally refuses a harmless command (for example one that mentions `.git/hooks`). Reword it, or read files with the Read tool.
- Recording a verdict always asks for your permission, so a review can't unlock the gate on its own.
- The git hook asks the remote which branches and tags it already has (`git ls-remote`), so pushing needs the remote to be reachable — as it does anyway. Commits that exist only in other refs (such as GitHub `refs/pull/*`) still need a review before you push them to a branch.
- The git hook refuses pushes it can't verify: tags pointing at trees or blobs, `--receive-pack`/`remote.<name>.receivepack` overrides, and URL rewriting that sends its check somewhere other than the push.
- Repositories whose `pre-push` hook is managed by Husky, lefthook or pre-commit aren't supported yet; `install-hook` refuses rather than silently disabling your existing checks.
- Recursive submodule pushes (`--recurse-submodules`, `push.recurseSubmodules=on-demand`) are refused from Claude, because each submodule has its own hooks.
- Only the reviewed commit itself can be pushed as a new branch or tag tip. Earlier commits in the reviewed range go out as history, not as tips (the reviewers see each commit's own changes, but a tip is what CI runs).
- If the remote has commits you haven't fetched, the hook may not be able to tell your already-published history apart from new commits; it then tells you to `git fetch` first.
- Publishing through a hosting API (for example `gh api` writing file contents) doesn't involve `git push`, so no local gate sees it. Server-side branch protection covers that too.
- If `python3` is missing, the Claude push gate fails open (allows the push) rather than blocking all shell commands.

## Repository layout

```
.claude-plugin/   plugin.json (the plugin) + marketplace.json (lets this repo be added as a marketplace)
agents/           the twelve reviewer agents
skills/           /ravenwatch:review, /ravenwatch:init-brief and /ravenwatch:install-git-hook
hooks/            the Claude Code push gate
scripts/          ravenwatch.py (range, scan, verdicts) and the git pre-push hook
```

## License

MIT © 2026 Nanna Karoliina
