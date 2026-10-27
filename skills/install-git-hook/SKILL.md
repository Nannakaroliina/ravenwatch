---
name: install-git-hook
description: >
  Installs (or removes) the ravenwatch git pre-push hook in the current repository. The hook is what actually
  enforces review verdicts: it blocks pushes from Claude, the terminal or any app until /ravenwatch:review has
  passed for the commits being pushed, and Claude's pushes are refused in repositories without it. It guards
  against accidental pushes on this machine; branch protection on GitHub is the real enforcement. Use when the
  user types /ravenwatch:install-git-hook or asks to "install the pre-push hook", "gate my pushes", or "remove
  the pre-push hook".
argument-hint: "[--uninstall]"
allowed-tools: Bash(git rev-parse:*), Bash(git config --get core.hooksPath), Read
---

# Install the git pre-push gate

The git `pre-push` hook is ravenwatch's authoritative check: git hands it the exact commits being pushed, and it asks the remote what it already has. Claude's own push gate refuses pushes in repositories where this hook is missing or out of date. The hook only reads the verdict recorded by `/ravenwatch:review`; it never runs a review itself.

Arguments received: `$ARGUMENTS`

## Install

1. Confirm this is a git repository: `git rev-parse --show-toplevel`. If not, say so and stop.
2. Check `git config --get core.hooksPath`. If it is set, explain that hooks live in that folder and the ravenwatch hook will be placed there, with any existing plain `pre-push` script kept as `pre-push.local` and run first. Hook managers (Husky, lefthook, pre-commit) are not supported yet: the helper refuses rather than silently disabling their checks, so say so instead of retrying. Proceed only on a clear yes, and then add `--hooks-path-ok` below.
3. Run (this is deliberately not pre-approved, so the owner confirms it):

   ```bash
   python3 ${CLAUDE_PLUGIN_ROOT}/scripts/ravenwatch.py install-hook
   ```

   It keeps an existing non-ravenwatch `pre-push` as `pre-push.local` (run first, so existing behaviour is preserved), updates an outdated ravenwatch hook, and refuses if both `pre-push` and `pre-push.local` already exist. Report what it printed.
4. Confirm in two or three lines: pushes from anywhere in this repository now require a passing review; bypass once from a terminal with `git push --no-verify` (Claude is not allowed to); turn off temporarily with `RAVENWATCH_DISABLE=1`. Mention that git hooks are per-repository, so the user runs this once in each repository they want gated.

Never write, copy or move files in the hooks folder yourself; the push gate refuses that. Use the helper.

## Uninstall (`--uninstall`)

Run `python3 ${CLAUDE_PLUGIN_ROOT}/scripts/ravenwatch.py install-hook --uninstall`. It removes only a ravenwatch hook and restores `pre-push.local` if present. Tell the user that Claude will no longer be able to push in this repository while the plugin is enabled.
