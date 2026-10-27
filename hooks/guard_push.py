#!/usr/bin/env python3
"""PreToolUse hook: keep Claude from getting around the ravenwatch git pre-push hook.

The git pre-push hook (scripts/git-pre-push.sh, installed per repository) is the
authoritative check: git hands it the exact commits being pushed. This hook does
not try to work out what a shell command pushes. It only makes sure that:

  * a command that may push runs in a repository where the ravenwatch git hook
    is installed and unmodified (and does not recurse into submodules without it);
  * Claude does not skip, disable or redirect git hooks (--no-verify, core.hooksPath,
    GIT_CONFIG_*, send-pack, receive-pack overrides, URL rewriting, RAVENWATCH_DISABLE ...);
  * Claude does not write to the git hooks, git config or the ravenwatch verdict
    state, or put a hooks path setting into any file.

Matching is deliberately broad and case-insensitive: a false denial costs a reworded
command, a miss costs an unreviewed push. Set RAVENWATCH_DISABLE=1 in Claude Code's
environment to turn the gate off.
"""

import json
import os
import re
import subprocess
import sys

SCRIPTS = os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "scripts"))
HOOK_SOURCE = os.path.join(SCRIPTS, "git-pre-push.sh")
# A single plain call of the plugin's own helper (it writes verdicts and installs hooks itself;
# those calls are not pre-approved, so the owner confirms each one).
OWN_HELPER = re.compile(r"^\s*python3\s+" + re.escape(os.path.join(SCRIPTS, "ravenwatch.py")) + r"\s[^;&|<>`$\n\\]*$")

# Ways to make git skip, replace or redirect hooks, or to push without running pre-push.
BYPASS = [
    (re.compile(r"--no-v(?!erbose\b)[a-z]*"), "`--no-verify` skips the review hook"),
    # Setting the hooks path: `-c core.hooks…=x`, `git config [--global] core.hooks… x` (reads with --get are fine).
    (re.compile(r"hooks[p]ath\s*=|config\b(?![^\n;&|]*--get)[^\n;&|]*hooks[p]ath", re.I),
     "changing the git hooks path would bypass the review hook"),
    (re.compile(r"GIT_CONFIG", re.I), "GIT_CONFIG_* variables can override git settings such as core.hooksPath"),
    (re.compile(r"--config-env", re.I), "--config-env can override git settings such as core.hooksPath"),
    (re.compile(r"send-pack|http-push", re.I), "low-level push commands do not run the review hook"),
    (re.compile(r"receive-?pack|upload-?pack|insteadof", re.I),
     "overriding how git reaches the remote can make the review hook check a different repository"),
    (re.compile(r"RAVENWATCH_DISABLE", re.I), "RAVENWATCH_DISABLE is for the owner to set, not for a command"),
    (re.compile(r"--git-dir|GIT_DIR|GIT_COMMON_DIR|--work-tree|GIT_WORK_TREE", re.I),
     "--git-dir / GIT_DIR point git at another repository, whose hooks the gate cannot check"),
    (re.compile(r"include\.path|includeif", re.I), "git config includes can pull in aliases or settings that skip the hook"),
    (re.compile(r"config\b(?![^\n;&|]*--get)[^\n;&|]*\balias\.", re.I),
     "defining git aliases can hide a push that skips the hook"),
    (re.compile(r"\bln\b[^\n;&|]*\.git\b", re.I), "a link into .git would let commands reach the hooks or verdict state"),
]
# Only a problem on a push (clone --recurse-submodules and rebase --exec are fine). git accepts
# abbreviated long options, so match prefixes.
PUSH_BYPASS = [
    (re.compile(r"--exe?c?(?:[=\s]|$)|--rece", re.I),
     "`--exec` / `--receive-pack` replace the receive command, so the push may go elsewhere"),
    (re.compile(r"recurse-?submodules|submodule\.recurse", re.I),
     "pushing submodules recursively goes through their own hooks, which the gate cannot check"),
    (re.compile(r"(?:^|\s)-c\s"), "per-command git settings (-c) on a push can change where it goes or skip the hook"),
    (re.compile(r"CDPATH"), "CDPATH changes where `cd` goes, so the gate cannot tell which repository pushes"),
]
# Text that reaches the hooks, git config or verdict state (case-insensitive: macOS paths are).
PROTECTED_TEXT = re.compile(
    r"\.git\b.*\b(hooks|ravenwatch)\b|\.git/config\b|--git-path|--absolute-git-dir|--git-common-dir", re.S | re.I)
PROTECTED_PATH = re.compile(
    r"/\.git/(?:worktrees/[^/]+/)?(?:hooks(?:/|$)|ravenwatch/(?!reports/)|config(?:\.worktree)?$)"
    r"|(?:^|/)\.?gitconfig$|/git/config$", re.I)
# A hooks path assignment inside a file (gitconfig style).
HOOKS_PATH_SETTING = re.compile(r"hooks[p]ath\s*=", re.I)
# Git config sections that can define aliases, includes, URL rewrites, remotes or hook settings.
GITCONFIG_SECTION = re.compile(r"^\s*\[\s*(?:alias|include|includeif|url|remote|core|protocol|submodule|push)\b",
                               re.I | re.M)
GIT_DIR_PATH = re.compile(r"/\.git(?:/|$)", re.I)
PLAIN_CD = re.compile(r"^\s*(?:cd|pushd|popd)\b[^;&|<>`$\n]*$")
# `push` as its own word (git push, git-push), but not inside identifiers like guard_push or the
# hook's name pre-push (writes to the hook itself are caught by PROTECTED_TEXT / PROTECTED_PATH).
PUSH_WORD = re.compile(r"(?<![A-Za-z0-9_.])(?<!pre-)push(?![A-Za-z0-9_])")
GIT_WORD = re.compile(r"(?<![\w-])git(?![\w-])")
# Wrappers that run a command string or elsewhere, so the directory or the push cannot be seen.
WRAPPED = re.compile(r"\b(?:sh|bash|zsh|dash|ksh)\s+-\w*c\b|\beval\b|\bxargs\b|--chdir|\benv\b[^\n;&|]*\s-C\b")
# cd/pushd with all of its arguments (zsh's two-argument `cd old new` must not be misread), or git -C.
DIR_TARGET = re.compile(r"(?:^|[\s;&|(){}\"'])(?:cd|pushd)((?:[ \t]+[^\s;&|(){}]+)*)|(?:^|\s)-C\s+([^\s;&|(){}]+)")


def may_push(text):
    """True if `push` appears as a word, after removing quotes and backslashes (so `pu''sh` counts)."""
    return bool(PUSH_WORD.search(re.sub(r"[\"'\\]", "", text)))


def allow():
    sys.exit(0)


def deny(reason):
    print(json.dumps({
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": "deny",
            "permissionDecisionReason": "ravenwatch push gate: " + reason,
        }
    }))
    sys.exit(0)


def git(repo, *args):
    res = subprocess.run(["git", "-C", repo, *args], capture_output=True, text=True, timeout=5)
    return res.returncode, res.stdout.strip()


def hook_installed(repo):
    """None if repo is not a git work tree, else whether the ravenwatch hook is installed unmodified."""
    if git(repo, "rev-parse", "--is-inside-work-tree")[0] != 0:
        return None
    code, hooks = git(repo, "rev-parse", "--path-format=absolute", "--git-path", "hooks")
    if code != 0:
        return False
    path = os.path.join(hooks, "pre-push")
    try:
        with open(path, "rb") as fh, open(HOOK_SOURCE, "rb") as src:
            return os.access(path, os.X_OK) and fh.read() == src.read()
    except OSError:
        return False


def recurses_into_submodules(repo):
    """True if a plain push here also pushes submodules (through their own, unchecked hooks)."""
    code, top = git(repo, "rev-parse", "--show-toplevel")
    if code != 0 or not os.path.exists(os.path.join(top, ".gitmodules")):
        return False
    mode = git(repo, "config", "--get", "push.recurseSubmodules")[1].lower()
    if not mode:
        mode = "on-demand" if git(repo, "config", "--type=bool", "--get", "submodule.recurse")[1] == "true" else ""
    return mode in ("on-demand", "only")


def target_dirs(command, cwd):
    """cd/pushd/-C targets in order (cwd excluded), or None if one cannot be resolved."""
    dirs, here = [], cwd
    for m in DIR_TARGET.finditer(command):
        if m.group(2) is not None:
            args = [m.group(2)]
        else:
            args = m.group(1).split() or ["~"]
        if len(args) != 1:
            return None
        raw = args[0].strip("'\"")
        if any(ch in raw for ch in "$`*?") or raw.startswith("-"):
            return None
        target = os.path.expanduser(raw)
        here = target if os.path.isabs(target) else os.path.normpath(os.path.join(here, target))
        dirs.append(here)
    return dirs


def matching(rules, *texts):
    for rx, why in rules:
        if any(rx.search(t) for t in texts):
            return f"{why}. Run the command without it."
    return None


def inside_git_dir(cwd):
    real = os.path.realpath(cwd)
    if GIT_DIR_PATH.search(real):
        return True
    return os.path.isdir(real) and git(real, "rev-parse", "--is-inside-git-dir")[1] == "true"


def used_aliases(repo, command):
    """{name: definition} of git aliases this command calls in repo."""
    code, out = git(repo, "config", "--get-regexp", r"^alias\.")
    if code != 0:
        return {}
    cleaned = re.sub(r"[\"'\\]", "", command)
    used = {}
    for line in out.splitlines():
        key, _, value = line.partition(" ")
        name = key.split(".", 1)[1]
        if re.search(r"(?<![\w.-])" + re.escape(name) + r"(?![\w.-])", cleaned):
            used[name] = value
    return used


def check_bash(command, cwd):
    if OWN_HELPER.match(command):
        return None
    if inside_git_dir(cwd) and not PLAIN_CD.match(command):
        return ("the shell's working directory is inside a .git directory, where commands can reach the hooks and "
                "verdict state. `cd` back to the work tree first.")
    stripped = re.sub(r"[\"'\\]", "", command)
    reason = matching(BYPASS, command, stripped)
    if reason:
        return reason
    if PROTECTED_TEXT.search(command) or PROTECTED_TEXT.search(stripped):
        return ("this command touches the git hooks, git config or ravenwatch state inside .git/. "
                "Read files there with the Read tool; install or remove the hook with /ravenwatch:install-git-hook.")
    pushing = may_push(command) and "git" in command.lower()
    if not (pushing or GIT_WORD.search(command)):
        return None
    reason = matching(PUSH_BYPASS, command, stripped) if pushing else None
    if reason:
        return reason
    if pushing and WRAPPED.search(command):
        return "this command runs a push through another command, so the gate cannot check it. Run the push directly."
    targets = target_dirs(command, cwd)
    if targets is None:
        if pushing:
            return ("the command changes directory in a way the gate cannot follow (shell variables, cd options). "
                    "Run the push from inside the repository instead.")
        return None
    for d in [cwd] + targets:
        installed = hook_installed(d) if os.path.isdir(d) else None
        if installed is not None:
            # Aliases are checked in every repository: a shell alias (`!…`) can run anything, and an
            # alias can carry --no-verify or a receive-pack override.
            for name, value in used_aliases(d, command).items():
                if value.startswith("!"):
                    return f"`git {name}` is a shell alias, which the gate cannot check. Run the commands directly."
                reason = matching(BYPASS + PUSH_BYPASS, value)
                if reason:
                    return f"`git {name}` expands to `{value}`: {reason}"
                if may_push(value):
                    pushing = True
        if installed is None:
            # Not a repository (yet). A push from here can only target a repository created in this same
            # command, which has no review hook.
            if pushing and (d != cwd or not targets):
                return (f"{d} is not a git repository with the ravenwatch hook yet. Create or clone it first, run "
                        "/ravenwatch:install-git-hook there, then push in a separate command.")
            continue
        if installed:
            if pushing and recurses_into_submodules(d):
                return ("this repository is configured to push submodules too (push.recurseSubmodules / "
                        "submodule.recurse), and their hooks cannot be checked. Push submodules yourself, or set "
                        "push.recurseSubmodules to check.")
            continue
        if pushing:
            return (f"the ravenwatch git pre-push hook is not installed (or is out of date) in {d}, so this "
                    "push could not be checked. Run /ravenwatch:install-git-hook in that repository first.")
    return None


def check_write(path, texts, cwd):
    if any(HOOKS_PATH_SETTING.search(t or "") for t in texts):
        return "setting the git hooks path would bypass the review hook."
    if any(GITCONFIG_SECTION.search(t or "") for t in texts):
        return ("this content defines git config sections (aliases, includes, URL rewrites, remotes) that could "
                "skip or redirect the review hook. Ask the owner to make that change.")
    if not path:
        return None
    full = os.path.realpath(os.path.join(cwd, os.path.expanduser(path)))
    if PROTECTED_PATH.search(full):
        return ("this file is part of the git hooks, git config or ravenwatch verdict state. Verdicts are "
                "recorded only by the review skill; hooks are managed with /ravenwatch:install-git-hook.")
    return None


def main():
    if os.environ.get("RAVENWATCH_DISABLE") == "1":
        allow()
    try:
        payload = json.load(sys.stdin)
    except Exception:
        allow()
    if not isinstance(payload, dict):
        allow()
    tool = payload.get("tool_name")
    inp = payload.get("tool_input") or {}
    cwd = payload.get("cwd") or os.environ.get("CLAUDE_PROJECT_DIR") or os.getcwd()
    try:
        if tool == "Bash":
            reason = check_bash(inp.get("command") or "", cwd)
        elif tool in ("Write", "Edit", "MultiEdit", "NotebookEdit"):
            texts = [inp.get("content"), inp.get("new_string"), inp.get("new_source")]
            texts += [e.get("new_string") for e in inp.get("edits") or [] if isinstance(e, dict)]
            reason = check_write(inp.get("file_path") or inp.get("notebook_path"), texts, cwd)
        else:
            reason = None
    except Exception as exc:
        # Fail closed only for commands that may push; never brick unrelated tools.
        reason = None
        if tool == "Bash" and may_push(inp.get("command") or ""):
            reason = (f"internal error while checking this command ({type(exc).__name__}: {exc}). "
                      "Start Claude Code with RAVENWATCH_DISABLE=1 to bypass the gate if this persists.")
    if reason:
        deny(reason)
    allow()


if __name__ == "__main__":
    main()
