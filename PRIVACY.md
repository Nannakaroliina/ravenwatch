# Privacy Policy

Last updated: 29 October 2026

ravenwatch is a free, open-source plugin for Claude Code, made by Nanna Karoliina ("I", "me"). This policy explains what happens to your data when you use it.

**Short version: ravenwatch collects nothing. It has no server, no account, no analytics and no telemetry. It runs on your machine, inside Claude Code. The code it reviews is read by Claude, so it goes to Anthropic like any code you ask Claude to read. What ravenwatch stores stays on your machine: mostly in your repository's `.git` folder, plus report drafts in your system's temporary folder.**

## What ravenwatch does with your data

ravenwatch reviews code in a git repository you choose. To do that it:

- reads your repository's files, commits and git configuration on your machine, and gives diffs, file contents and commit subjects to Claude to review;
- keeps its working state in `.git/ravenwatch/` in that repository: review verdicts, reports, the approved project brief and its hash, check results, a history log and the diffs of recent runs (see the README for the full list). Nothing under `.git/` is committed or pushed by git;
- writes each report draft to a private `ravenwatch-*` folder in your system's temporary folder (`$TMPDIR` on macOS, usually `/tmp` on Linux). The draft is removed when the verdict is recorded, or once 20 newer reviews have run in that repository;
- runs the check commands (tests, type checks, linters) that you approve in your project brief, on your machine. While they run, a small helper folder in the temporary folder blocks pushes; it is removed afterwards;
- runs `gitleaks` and `osv-scanner` only if you already have them installed.

Outside `.git/ravenwatch/` and the temporary folder, ravenwatch only writes where you ask it to:

- `/ravenwatch:install-git-hook` installs a `pre-push` hook in your hooks folder (`.git/hooks`, or the folder `core.hooksPath` points to), and keeps any `pre-push` hook you already had as `pre-push.local`;
- `/ravenwatch:init-brief` writes the project brief, `.ravenwatch.md`, in your repository's root folder. It is committed like any other file unless you mark it private, which adds it to `.git/info/exclude`.

I never receive any of this. ravenwatch contains no code that sends data to me or to any server I run.

## Where your data does go

ravenwatch works through other software, and that software has its own terms:

- **Claude Code and Anthropic.** The review is carried out by Claude through Claude Code. The code, diffs, commit subjects and reports Claude reads are sent to Anthropic (or to the cloud provider you have configured for Claude Code) as part of your normal Claude Code session, exactly like any other code you ask Claude to read. That is governed by your agreement with Anthropic and [Anthropic's Privacy Policy](https://www.anthropic.com/legal/privacy), not by ravenwatch.
- **Your git remote.** `/ravenwatch:review` and the pre-push hook run `git ls-remote` against your remote (for example GitHub) to see which branches it already has, using the credentials git already has. They send nothing beyond what git itself sends.
- **osv-scanner.** If it is installed, a review may run it on your lockfiles. It sends the package names and versions listed there to the public OSV vulnerability database. It is a separate program with its own privacy policy. `gitleaks` works offline.
- **Your own checks.** Commands you approve in the project brief run as you; what they send anywhere is up to them.

## Personal data

ravenwatch does not ask for, collect or store personal data about you, and it never sends anything to me.

Your repository may contain personal data, for example names or emails in code, test fixtures or commit messages. A review reads it like any other content. Whatever Claude reads is sent to Anthropic, as described above, so check that this is allowed before you review a repository that holds other people's personal data. Copies of diffs and reports are kept in `.git/ravenwatch/` until you delete them, and report drafts in the temporary folder as described above.

## Deleting your data

- Delete the `.git/ravenwatch/` folder in a repository to remove its reviews, reports and history.
- Delete any `ravenwatch-*` folders in your system's temporary folder to remove report drafts that were never filed.
- Run `/ravenwatch:install-git-hook --uninstall` to remove the hook. It also puts back any hook ravenwatch had kept as `pre-push.local`.
- Delete `.ravenwatch.md` if you no longer want the project brief, and remove its line from `.git/info/exclude` if you had marked it private.
- Uninstalling the plugin from Claude Code removes the plugin itself.

## Children

ravenwatch is a developer tool and is not directed at children.

## Changes

If this policy changes, the new version will be published in this file in the repository, with a new date at the top. The repository's history keeps every earlier version.

## Contact

Questions about this policy: open an issue at <https://github.com/Nannakaroliina/ravenwatch/issues>.
