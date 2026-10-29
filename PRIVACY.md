# Privacy Policy

Last updated: 29 October 2026

ravenwatch is a free, open-source plugin for Claude Code, made by Nanna Karoliina ("I", "me"). This policy explains what happens to your data when you use it.

**Short version: ravenwatch collects nothing. It has no server, no account, no analytics and no telemetry. It runs on your machine, inside Claude Code, and everything it writes stays in your repository's `.git` folder.**

## What ravenwatch does with your data

ravenwatch reviews code in a git repository you choose. To do that it:

- reads your repository's files, commits and git configuration on your machine;
- writes its working state only to `.git/ravenwatch/` in that repository: review verdicts, reports, the approved project brief and its hash, check results, a history log and the diffs of recent runs (see the README for the full list). Report drafts are briefly written to a private temporary folder first. Nothing under `.git/` is committed or pushed by git;
- runs the check commands (tests, type checks, linters) that you approve in your project brief, on your machine;
- runs scanners such as `gitleaks`, `osv-scanner` or `pip-audit` only if you already have them installed.

I never receive any of this. ravenwatch contains no code that sends data to me or to any server I run.

## Where your data does go

ravenwatch works through other software, and that software has its own terms:

- **Claude Code and Anthropic.** The review is carried out by Claude through Claude Code. The code, diffs and reports Claude reads are sent to Anthropic (or to the cloud provider you have configured for Claude Code) as part of your normal Claude Code session, exactly like any other code you ask Claude to read. That is governed by your agreement with Anthropic and [Anthropic's Privacy Policy](https://www.anthropic.com/legal/privacy), not by ravenwatch.
- **Your git remote.** Before a push, the pre-push hook runs `git ls-remote` against the remote you are pushing to (for example GitHub), using the credentials git already has. It sends nothing beyond what git itself sends.
- **Scanners you have installed.** Tools such as `osv-scanner` or `pip-audit` may look up package versions in public vulnerability databases. They are separate programs with their own privacy policies, and ravenwatch only runs them if they are already on your machine.
- **Your own checks.** Commands you approve in the project brief run as you; what they send anywhere is up to them.

## Personal data

ravenwatch does not ask for, collect or store personal data about you. Your repository may of course contain personal data (commit author names and emails, for example); ravenwatch reads it locally only as part of the review and does not copy it anywhere outside `.git/ravenwatch/`.

## Deleting your data

Delete the `.git/ravenwatch/` folder in a repository to remove everything ravenwatch stored there. Run `/ravenwatch:install-git-hook` and choose remove (or delete `.git/hooks/pre-push`) to remove the hook. Uninstalling the plugin from Claude Code removes the plugin itself.

## Children

ravenwatch is a developer tool and is not directed at children.

## Changes

If this policy changes, the new version will be published in this file in the repository, with a new date at the top. The repository's history keeps every earlier version.

## Contact

Questions about this policy: open an issue at <https://github.com/Nannakaroliina/ravenwatch/issues>.
