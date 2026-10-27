---
name: init-brief
description: >
  Creates or updates the project brief (.ravenwatch.md) that tells the ravenwatch reviewers what the project
  is, who uses it, what data it handles, which checks to run (tests, type checks, linters) and which risks the
  owner has accepted — then asks the owner to approve it. Use when the user types /ravenwatch:init-brief, or asks
  to "set up the project brief", "add checks to the review", "accept this risk permanently" or "update the brief".
argument-hint: "[--update]"
allowed-tools: Read, Grep, Glob, Bash(git rev-parse:*), Bash(git ls-files:*), Bash(git status:*), Bash(python3 ${CLAUDE_PLUGIN_ROOT}/scripts/ravenwatch.py status)
---

# Project brief

The brief is a short Markdown file, `.ravenwatch.md`, at the repository root. Every reviewer reads it, so it cuts false alarms and repeated findings. Its frontmatter can list **checks** — the owner's own commands (tests, type checks, linters) that the review runs and treats as hard evidence.

Only a version the owner explicitly **approved** is acted on. The approved copy is stored inside `.git/ravenwatch/`, and checks run from that copy, never from the working file. Editing the file (by anyone, including Claude) changes nothing until the owner approves again. Never approve on the owner's behalf or present approval as a formality.

Arguments received: `$ARGUMENTS`

## 1. Look before asking

1. Find the repository root (`git rev-parse --show-toplevel`). If `.ravenwatch.md` exists, read it; this is an update, so keep everything the owner wrote unless they ask to change it.
2. Work out the stack and the commands that already exist. Read `package.json` scripts, `pyproject.toml`/`setup.cfg`/`tox.ini`/`noxfile.py`, `Makefile`, `Cargo.toml`, `go.mod`, `deno.json`, CI workflows, and config files for test runners, type checkers and linters (vitest/jest/mocha/playwright, pytest, tsc/`tsconfig.json`, eslint/biome, ruff/mypy, cargo test/clippy, go test/vet).
3. Draft check commands that already work in this repo and finish on their own:
   - Prefer the project's own scripts (`npm test`, `npm run lint`, `make test`) over raw tool calls.
   - They must not wait for input or watch files. The review sets `CI=1`, which stops vitest and jest watch mode; for other tools add the non-watch flag (`--run`, `--watch=false`).
   - They must not deploy, publish, migrate a real database, push, send email, or call paid services. Leave out anything that touches production. Say why if you leave a script out.
   - Mark a check `blocking: true` only if its failure means the code is broken (tests, type check). Lint and formatting are usually `blocking: false`.
   - Never invent a command the project doesn't have; if there are no tests, say so.
4. Look for what the app does and who uses it: README, routes, page titles, `wrangler.toml`/IaC (what is deployed and where), forms and fields (what personal data it collects), outside services it calls (email, payments, analytics, AI APIs).

## 2. Ask the owner (one round, AskUserQuestion)

Ask only what you can't tell from the code, at most four questions. Usually:

- **Audience** — who uses it and where (e.g. "public, EU", "only me", "internal team"). This sets how strict the privacy review is.
- **Distribution** — open source (which licence), closed-source commercial, or private/personal. This drives the licence checks.
- **Checks** — show the drafted commands and ask which to include (multi-select), noting which would block.
- **Keep the brief private?** — if the repository is or will be public, recommend private: a committed brief tells everyone what you've accepted as risk. Private means it is git-ignored for this clone only (it won't follow you to another machine).

## 3. Write the brief

Write `.ravenwatch.md` with this structure (omit empty sections; keep it under ~80 lines):

```markdown
---
audience: <who uses it, where>
distribution: <open source (MIT) | closed-source commercial | private>
checks:
  - name: tests
    run: npm test
    timeout: 600
    blocking: true
  - name: types
    run: npx tsc --noEmit
    blocking: true
  - name: lint
    run: npm run lint
    blocking: false
skip: []          # optional; only impact-analyzer, ux-reviewer, test-reviewer, design-reviewer, privacy-reviewer
---
# <Project name>

## About
<2–4 sentences: what it does, main user flows, how it is deployed.>

## Public and private parts
<Which routes/pages are public, which need login, which are admin-only, and how admin access works.>

## Data
<Personal data collected, where it is stored, how long, which outside services receive it.>

## Conventions
<Anything reviewers should respect: e.g. "money is integer cents", "all DB access goes through src/lib/db.js".>

## Accepted risks
- <What is accepted, where (file or area), why, and the date. Be specific so it can't hide new issues.>
```

Rules for **Accepted risks**: add an entry only when the owner explicitly says to accept something, in their words. Each entry must name the specific issue and place. Never write broad entries ("XSS is fine", "ignore tests"). Confirmed leaked credentials can never be accepted.

## 4. Ask for approval

Approval is two steps, so the owner approves exactly the content they saw. First show what would take effect (this stores nothing):

```bash
python3 ${CLAUDE_PLUGIN_ROOT}/scripts/ravenwatch.py trust-brief
```

Relay its output to the owner **in full** — every check command, the skip list, the audience, and the full text of every accepted risk — and point out anything that came from someone other than the owner (for example entries already in a pulled `.ravenwatch.md`). Then, if they approve, run the command it printed:

```bash
python3 ${CLAUDE_PLUGIN_ROOT}/scripts/ravenwatch.py trust-brief --approve <sha256 it printed>
```

Add `--private` if they chose to keep it private. This command is deliberately not pre-approved: the owner's confirmation of it, with the hash of the content they were shown, is the approval. It refuses if the file changed after it was shown. If they decline, leave the file as a draft and say that reviews will ignore it until it is approved. Don't edit `.ravenwatch.md` between the two steps.

Finish with one line: the brief's status, how many checks it has, and that `/ravenwatch:review` will now use it. If the brief is not private, remind them to commit it.
