#!/usr/bin/env python3
"""PreToolUse hook: keep Claude from getting around the ravenwatch git pre-push hook.

The git pre-push hook (scripts/git-pre-push.sh, installed per repository) is the
authoritative check: git hands it the exact commits being pushed. This hook does
not try to work out what a push sends. It only makes sure that:

  * a push is a plain `git [-C dir] push …` command of its own (not hidden in
    backticks, `find -exec`, `submodule foreach`, `sh -c`, aliases to shell
    commands …), run in a repository where the ravenwatch git hook is installed
    and unmodified, and not recursing into submodules;
  * Claude does not skip, disable or redirect git hooks (--no-verify, core.hooksPath,
    GIT_CONFIG_*, send-pack, receive-pack overrides, URL rewriting, RAVENWATCH_DISABLE ...);
  * Claude does not write inside any git directory (hooks, config, verdict state —
    only ravenwatch review reports), move a git directory, or edit git config files.

Matching errs on the side of denying a push: a false denial costs a reworded
command, a miss costs an unreviewed push. Set RAVENWATCH_DISABLE=1 in Claude
Code's environment to turn the gate off.
"""

import glob
import json
import os
import re
import shlex
import signal
import subprocess
import sys

SCRIPTS = os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "scripts"))
PLUGIN_ROOT = os.path.realpath(os.path.dirname(SCRIPTS))
HELPER = os.path.realpath(os.path.join(SCRIPTS, "ravenwatch.py"))
# Commands that only read their arguments: reading the plugin's own files is fine.
# (No pagers, tree or rg: they can write files or run commands through options.)
READERS = {"cat", "head", "tail", "ls", "grep", "egrep", "fgrep", "wc", "file", "stat", "cmp", "md5", "md5sum",
           "shasum", "sha256sum"}
PYTHONS = re.compile(r"^python3?(?:\.\d+)?$")
# File names that matter when the directory a command runs in is unknown.
SENSITIVE_NAMES = {"status", "latest", "prepared", "checks.kv", "brief-approved.md", "brief-trust", "config",
                   "pre-push", "pre-push.local", "head", "guard_push.py", "ravenwatch.py", "git-pre-push.sh",
                   "hooks.json"}
HOOK_SOURCE = os.path.join(SCRIPTS, "git-pre-push.sh")
# A single plain call of the plugin's own helper (it writes verdicts and installs hooks itself;
# those calls are not pre-approved, so the owner confirms each one).
OWN_HELPER = re.compile(r"^\s*python3\s+" + re.escape(os.path.join(SCRIPTS, "ravenwatch.py")) + r"\s[^;&|<>`$\n\\]*$")

# Ways to make git skip, replace or redirect hooks, reach another git directory, or push without pre-push.
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
    (re.compile(r"(?i:-{1,2}(?:separate-)?git-dir|--work-tree|absorbgitdirs|worktree\s+move)"
                r"|\bGIT_(?:DIR|COMMON_DIR|WORK_TREE)\b"),
     "pointing git at, or moving, a git directory puts its hooks and verdict state out of the gate's sight"),
    (re.compile(r"include\.path|includeif", re.I), "git config includes can pull in aliases or settings that skip the hook"),
    (re.compile(r"config\b(?![^\n;&|]*--get)[^\n;&|]*\balias\.|(?:^|\s)-c\s*alias\.", re.I),
     "defining git aliases can hide a push that skips the hook"),
    (re.compile(r"\b(?:ln|mv|cp|rsync|ditto|rename)\b[^\n;&|]*(?:^|[\s/\"'=])\.git(?:[\s/\"']|$)", re.I),
     "linking, moving or copying a .git directory would let commands reach its hooks or verdict state"),
]
# Text that reaches the hooks, git config or verdict state (case-insensitive: macOS paths are).
PROTECTED_TEXT = re.compile(
    r"\.git/(?:[^\s;&|<>\"']*/)?(?:hooks|ravenwatch)\b|\.git/config\b|--git-path|--absolute-git-dir|--git-common-dir",
    re.I)
# Git config files outside a git directory (inside one, any write is refused).
GITCONFIG_FILE = re.compile(r"(?:^|/)\.?gitconfig$|/git/config$", re.I)
# A hooks path assignment inside a file (gitconfig style).
HOOKS_PATH_SETTING = re.compile(r"hooks[p]ath\s*=", re.I)
GIT_DIR_PATH = re.compile(r"/\.git(?:/|$)", re.I)
PLAIN_CD = re.compile(r"^\s*(?:cd|pushd|popd)\b[^;&|<>`$\n]*$")
# `push` as its own word (git push, git-push), but not inside identifiers like guard_push or the
# hook's name pre-push (writes to the hook itself are refused as writes inside a git directory).
PUSH_WORD = re.compile(r"(?<![A-Za-z0-9_.])(?<!pre-)push(?![A-Za-z0-9_])")
GIT_WORD = re.compile(r"(?<![\w-])git(?![\w-])")
# Push options that send the push elsewhere or recurse into submodules. git accepts unique
# abbreviations of long options, so match prefixes (--e[xec], --rec[eive-pack|urse-submodules]).
PUSH_OPTION = re.compile(r"^--(?:e[a-z]*|rec[a-z-]*)(?:=|$)", re.I)
SEPARATORS = {";", "&&", "||", "|", "&", "|&", ";;", "(", ")", "{", "}"}
# Shell operators, longest first (for splitting runs of operator characters).
OPERATORS = sorted({";", "&&", "||", "|", "&", "|&", ";;", "(", ")", "<", ">", ">>", "<<", "<<-", "<<<", ">|",
                    "&>", "&>>", "<&", ">&", "<>"}, key=len, reverse=True)
REDIRECT = re.compile(r"^(?=.*[<>])[<>&|]+$")
# Programs that run a command given to them as a string or argument list.
EXECUTORS = {"sh", "bash", "zsh", "dash", "ksh", "fish", "env", "xargs", "eval", "exec", "command", "nohup", "time",
             "timeout", "watch", "find", "parallel", "sudo", "doas", "nice", "stdbuf", "script", "builtin"}
# A `cat` heredoc. Its body is only dropped when the rest of its first line is just redirections:
# `cat <<EOF | sh` or `cat <<EOF && git push` keep the body, which is then checked as commands.
CAT_HEREDOC = re.compile(r"\bcat\s+<<-?\s*(['\"]?)(\w+)\1([^\n]*)\n.*?\n[ \t]*\2[ \t]*(?=\n|\)|$)", re.S)
HARMLESS_REST = re.compile(r"[\s\"')]*(?:(?:(?<=\s)\d+)?>>?\s*[^\s;&|()<>\"']+[\s\"')]*)*")
REPORTS_PATH = re.compile(r"/ravenwatch/reports(?:/|$)")
# ravenwatch state file names, wherever they are written (a directory may become a git dir later).
STATE_NAME = re.compile(r"/ravenwatch/(?:status|latest|brief-approved\.md|brief-trust|verdicts/|checks/"
                        r"|runs/[^/]+/(?:prepared|checks\.kv|checks\.md|brief\.md|context\.md)$)")
# git subcommands that can run arbitrary commands (and so a push the gate can't see).
RUNS_COMMANDS = {"submodule", "bisect", "rebase", "filter-branch", "filter-repo", "for-each-repo", "difftool",
                 "mergetool", "worktree"}
# git global options that take a separate value.
GIT_VALUE_OPTS = {"-C", "-c", "--namespace", "--exec-path", "--git-dir", "--work-tree", "--config-env"}


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


def git_dir_of(path):
    """The git directory that path is (or would be) inside of, else None. Filesystem only, no git calls:
    a `.git` path component (even if it doesn't exist yet), or an existing ancestor that has a git
    directory's layout (HEAD, objects/, refs/) — which also covers bare, moved and separate git dirs."""
    full = os.path.realpath(path)
    m = GIT_DIR_PATH.search(full)
    if m:
        return full[:m.start() + 5]
    d = full
    while True:
        if os.path.isfile(os.path.join(d, "HEAD")) and os.path.isdir(os.path.join(d, "objects")) \
                and os.path.isdir(os.path.join(d, "refs")):
            return d
        parent = os.path.dirname(d)
        if parent == d:
            return None
        d = parent


def segments(command):
    """Split a command into simple commands, each (tokens, redirect targets, the separator after it),
    honouring quotes, comments and line continuations like the shell does. None if it can't be parsed."""
    out, quote, escaped, i, n = [], None, False, 0, len(command)
    while i < n:
        ch = command[i]
        if escaped:
            escaped = False
        elif ch == "\\" and quote != "'":
            if command[i + 1:i + 2] == "\n":  # line continuation: the shell joins the lines
                i += 2
                continue
            escaped = True
        elif quote:
            quote = None if ch == quote else quote
        elif ch in "'\"":
            quote = ch
        elif ch == "#" and (not out or out[-1] in " \t;&|()"):
            i = command.find("\n", i)  # a comment runs to the end of its line only
            if i < 0:
                break
            continue
        elif ch == "\n":
            ch = ";"  # unquoted newlines separate commands
        out.append(ch)
        i += 1
    lexer = shlex.shlex("".join(out), posix=True, punctuation_chars=True)
    lexer.whitespace_split = True
    lexer.commenters = ""
    try:
        raw = list(lexer)
    except ValueError:
        return None
    tokens = []
    for tok in raw:
        if tok and all(ch in "();<>|&" for ch in tok):
            while tok:
                op = next(o for o in OPERATORS if tok.startswith(o))
                tokens.append(op)
                tok = tok[len(op):]
        else:
            tokens.append(tok)
    segs, cur, redirects, skip = [], [], [], False
    for tok in tokens:
        if skip:
            skip = False
            if not tok.isdigit():
                redirects.append(tok)
            continue
        if tok in SEPARATORS:
            segs.append((cur, redirects, tok))
            cur, redirects = [], []
        elif REDIRECT.match(tok):
            if cur and cur[-1].isdigit():
                cur.pop()  # the file descriptor of `2>`
            skip = True  # the redirect target (`2>&1` leaves `1`, which is skipped too)
        else:
            cur.append(tok)
    if cur or redirects:
        segs.append((cur, redirects, None))
    return segs


def parse_git(seg):
    """For `git [global options] sub …` return (dir_option, globals, sub, args); else None."""
    if not seg or os.path.basename(seg[0]) != "git":
        return None
    i, cdir, globs = 1, None, []
    while i < len(seg) and seg[i].startswith("-"):
        tok = seg[i]
        globs.append(tok)
        if tok in GIT_VALUE_OPTS:
            if tok == "-C" and i + 1 < len(seg):
                cdir = seg[i + 1] if cdir is None else os.path.join(cdir, seg[i + 1])
            globs.append(seg[i + 1] if i + 1 < len(seg) else "")
            i += 2
            continue
        i += 1
    sub = seg[i] if i < len(seg) else ""
    return cdir, globs, sub, seg[i + 1:]


def expand(base, target):
    """All paths a shell word could refer to, relative to base (globs expanded). None if unknowable."""
    if any(ch in target for ch in "$`") or target.startswith("-"):
        return None
    target = os.path.expanduser(target)
    if not os.path.isabs(target) and base is None:
        return None
    full = target if os.path.isabs(target) else os.path.join(base, target)
    if any(ch in target for ch in "*?["):
        # Like the shell: a pattern that matches nothing is passed on literally — but it is checked
        # against every existing directory its leading part matches, since the file may be created there.
        return [os.path.normpath(p) for p in glob_existing(full)] or [os.path.normpath(full)]
    return [os.path.normpath(full)]


def glob_existing(pattern):
    """Matches of a pattern; if none, the pattern's leading directories that do match, with the rest
    appended literally (the path that would be created there)."""
    found = glob.glob(pattern)
    parent, name = os.path.split(pattern)
    if found or parent == pattern or not any(ch in parent for ch in "*?["):
        return found
    return [os.path.join(d, name) for d in glob_existing(parent)]


def resolve(base, target):
    """The single directory a `cd` target refers to, or None if it is unknowable or ambiguous."""
    paths = expand(base, target)
    return paths[0] if paths is not None and len(paths) == 1 else None


def risky_when_lost(word):
    """A relative word that could reach hooks, verdict state or the plugin from a directory we can't know."""
    w = word.rstrip("/")
    return "/" in w or os.path.basename(w).lower() in SENSITIVE_NAMES or w.lower() in (".git", "..")


def touches_git_dir(bases, words, protect_plugin=False):
    """(word, "git" | "plugin" | "lost") for the first word (argument or redirect target) that refers to
    something inside a git directory or, when protect_plugin is set, to ravenwatch's own installed code,
    from any directory the command may be in (None = unknown); else None."""
    for w in words:
        if w.startswith("-"):
            if "=" not in w:
                continue
            w = w.split("=", 1)[1]  # --output=FILE, --target-directory=DIR
            if not w:
                continue
        for base in bases:
            if base is None and not w.startswith(("/", "~", "$")) and risky_when_lost(w):
                return w, "lost"
            for p in expand(base, w) or []:
                if git_dir_of(p) and not REPORTS_PATH.search(p):
                    return w, "git"
                if protect_plugin and under_plugin(p):
                    return w, "plugin"
    return None


def path_refusal(word, kind):
    if kind == "lost":
        return (f"the guard can't tell which directory `{word}` is in, because an earlier `cd` uses a variable, an "
                "option or `-`. Use absolute paths, or `cd` to a plain absolute path first.")
    if kind == "plugin":
        return (f"`{word}` is part of the installed ravenwatch plugin, which Claude can't change (it is the push "
                "gate itself). If the plugin needs a change, the owner makes it in the ravenwatch repository and "
                "updates the plugin. To run the helper, use one plain command: `python3 <plugin>/scripts/"
                "ravenwatch.py <args>`.")
    return (f"`{word}` is inside a git directory (hooks, config or ravenwatch verdict state). Read files there with "
            "the Read tool; install or remove the hook with /ravenwatch:install-git-hook. If the path only appears "
            "in text (for example a commit message), write the text to a file outside .git and use `git commit -F`.")


def alias_of(repo, sub):
    if not sub or repo is None or not os.path.isdir(repo):
        return None
    code, value = git(repo, "config", "--get", f"alias.{sub}")
    return value if code == 0 and value else None


def developing_plugin(cwd):
    """True when this session works inside ravenwatch's own source tree (the plugin is loaded from it)."""
    real = os.path.realpath(cwd)
    return real == PLUGIN_ROOT or real.startswith(PLUGIN_ROOT + os.sep)


def under_plugin(path):
    real = os.path.realpath(path)
    return real == PLUGIN_ROOT or real.startswith(PLUGIN_ROOT + os.sep)


def plugin_modified():
    """Uncommitted changes to the plugin's own code (only possible when it runs from a git checkout)."""
    if not os.path.exists(os.path.join(PLUGIN_ROOT, ".git")):
        return False
    code, out = git(PLUGIN_ROOT, "status", "--porcelain", "--", "scripts", "hooks")
    return code != 0 or bool(out)


def check_bash(command, cwd):
    if OWN_HELPER.match(re.sub(r"/{2,}", "/", command)):
        # The helper records verdicts and installs the hook, so it must be the code that was reviewed.
        if plugin_modified():
            return ("ravenwatch's own scripts or hooks have uncommitted changes, so the helper can't be trusted to "
                    "record verdicts or install hooks. Commit them first (the review will see them).")
        return None
    stripped = re.sub(r"[\"'\\]", "", command)
    for rx, why in BYPASS:
        if rx.search(command) or rx.search(stripped):
            return f"{why}. Run the command without it."
    if PROTECTED_TEXT.search(command) or PROTECTED_TEXT.search(stripped):
        return ("this command touches the git hooks, git config or ravenwatch state inside .git/. Read files there "
                "with the Read tool; install or remove the hook with /ravenwatch:install-git-hook. If the path only "
                "appears in text (for example a commit message), write the text to a file outside .git and use "
                "`git commit -F <file>`.")
    if git_dir_of(cwd) and not PLAIN_CD.match(command):
        return ("the shell's working directory is inside a git directory, where commands can reach the hooks and "
                "verdict state. `cd` back to the work tree first.")
    # The body of a `cat` heredoc is data (Claude's usual way to pass a commit message), not commands —
    # unless the rest of its first line feeds it somewhere or chains another command.
    command = CAT_HEREDOC.sub(
        lambda m: "cat" + m.group(3) if len(m.group(3)) <= 500 and HARMLESS_REST.fullmatch(m.group(3))
        else m.group(0), command)
    pushing = may_push(command)
    if pushing and re.search(r"`|\$\(|<\(|>\(", command):
        return "a push inside command substitution can't be checked. Run `git push` as its own command."
    parsed_cmd = segments(command)
    if parsed_cmd is None:
        return "could not parse this command. Run `git push` as its own plain command." if pushing else None
    segs = parsed_cmd
    protect_plugin = not developing_plugin(cwd)

    # Every directory the shell may be in: a `cd` only replaces the current one when the next command
    # runs after it succeeded (`&&`); after `;`, `||`, a pipe or a subshell, or `popd`/`cd -`, every
    # directory seen so far stays possible. None means a directory the guard can't work out.
    heres, seen, cdpath, prev_sep = [cwd], [cwd], False, None
    for seg, redirects, sep in segs:
        if prev_sep == ")":
            heres = list(seen)
        prev_sep = sep
        # Redirect targets resolve against the directory the command has moved to.
        hit = touches_git_dir(heres, redirects, protect_plugin)
        if hit:
            return path_refusal(*hit)
        while seg and re.match(r"^[A-Za-z_][A-Za-z0-9_]*=", seg[0]):
            if seg[0].startswith("CDPATH="):
                cdpath = True
            seg = seg[1:]
        if not seg:
            continue
        head = os.path.basename(seg[0])
        if head in ("cd", "pushd", "popd"):
            args = [a for a in seg[1:] if a not in ("--", "-P", "-L", "-e", "-@")]
            if head == "popd" or args == ["-"] or (head == "pushd" and not args):
                new = list(seen)
            elif len(args) > 1 or any(a.startswith(("-", "+")) for a in args):
                new = [None]
            else:
                target = args[0] if args else "~"
                if any(b is None for b in heres) and not target.startswith(("/", "~")) and \
                        re.search(r"(?:^|/)\.git(?:/|$)", target, re.I):
                    return path_refusal(target, "lost")
                new = [None if cdpath and not target.startswith(("/", "~", ".")) else resolve(b, target)
                       for b in heres]
            for d in new:
                if d is not None and git_dir_of(d):
                    return ("this command changes into a git directory, where it can reach the hooks and verdict "
                            "state. Read files there with the Read tool.")
                if d is not None and protect_plugin and under_plugin(d):
                    return ("this command changes into the installed ravenwatch plugin, which Claude can't change. "
                            "Read its files with the Read tool, or by path without `cd`.")
            seen += [d for d in new if d not in seen]
            heres = list(dict.fromkeys(new if sep == "&&" else heres + new))
            continue
        args = seg[1:]
        if PYTHONS.match(head) and args and all(
                os.path.realpath(p) == HELPER for b in heres for p in (expand(b, args[0]) or [""])):
            # The helper records verdicts and installs the hook, so it must be the code that was committed.
            if plugin_modified():
                return ("ravenwatch's own scripts or hooks have uncommitted changes, so the helper can't be trusted "
                        "to record verdicts or install hooks. Commit them first (the review will see them).")
            args = args[1:]
        # Paths given to other programs (cp, printf >, rm …); git's own arguments may name repositories.
        word = None if head == "git" else touches_git_dir(heres, args, protect_plugin and head not in READERS)
        if word:
            return path_refusal(*word)
        if not (pushing or GIT_WORD.search(" ".join(seg))):
            continue
        parsed = parse_git(seg)
        seg_text = " ".join(seg)
        if parsed is None:
            # A push run by another program: a wrapper given a command string, or `git` and `push` as
            # separate words in its arguments (find -exec git push, xargs git push). A quoted mention such
            # as `rg "git push"` is one token and is fine.
            runs_git_push = any(os.path.basename(t) in ("git", "git-push") for t in seg[1:]) and \
                any(PUSH_WORD.fullmatch(t) or os.path.basename(t) == "git-push" for t in seg[1:])
            if (head in EXECUTORS and may_push(seg_text)) or runs_git_push:
                return (f"`{seg[0]}` runs a push the gate cannot check (wrappers, find -exec, xargs …). "
                        "Run `git push` as its own command.")
            continue
        cdir, globs, sub, args = parsed
        # The push may run in any of the directories the shell may be in; each must be gated.
        repos = list(dict.fromkeys(resolve(h, cdir) if cdir else h for h in heres))
        is_push = sub == "push"
        for value in [alias_of(r, sub) for r in repos] if not is_push and sub else []:
            if value is not None:
                if value.startswith("!"):
                    if may_push(value):
                        return f"`git {sub}` is a shell alias that pushes, which the gate cannot check. Run `git push` directly."
                else:
                    for rx, why in BYPASS:
                        if rx.search(value):
                            return f"`git {sub}` expands to `{value}`: {why}."
                    parts = value.split()
                    if parts and parts[0] == "push":
                        is_push, args = True, parts[1:] + args
        if not is_push:
            if sub in RUNS_COMMANDS and may_push(seg_text):
                # e.g. `git submodule foreach git push`, `git rebase --exec "git push"`
                return f"`git {sub}` would run a push the gate cannot check. Run `git push` as its own command."
            continue
        if "-c" in globs:
            return "per-command git settings (-c) on a push can change where it goes or skip the hook. Run it without -c."
        for a in args:
            if PUSH_OPTION.match(a):
                return (f"`{a}` replaces the receive command or pushes submodules through their own hooks, "
                        "which the gate cannot check. Run the push without it.")
        if None in repos:
            return ("the command changes directory in a way the gate cannot follow (variables, CDPATH, cd options). "
                    "Run the push from inside the repository instead.")
        for repo in repos:
            installed = hook_installed(repo) if os.path.isdir(repo) else None
            if installed is None:
                return (f"{repo} is not a git repository with the ravenwatch hook yet. Create or clone it first, run "
                        "/ravenwatch:install-git-hook there, then push in a separate command. (After `cd x;` the "
                        "push may also run where the command started; use `cd x && git push`.)")
            if not installed:
                return (f"the ravenwatch git pre-push hook is not installed (or is out of date) in {repo}, so this "
                        "push could not be checked. Run /ravenwatch:install-git-hook in that repository first. (If "
                        "the repository uses Husky or lefthook, ravenwatch can't install there yet: the owner pushes "
                        "from their own terminal.)")
            if recurses_into_submodules(repo):
                return ("this repository is configured to push submodules too (push.recurseSubmodules / "
                        "submodule.recurse), and their hooks cannot be checked. Push submodules yourself, or set "
                        "push.recurseSubmodules to check.")
    return None


def check_write(path, texts, cwd):
    if any(HOOKS_PATH_SETTING.search(t or "") for t in texts):
        return "setting the git hooks path would bypass the review hook."
    if not path:
        return None
    full = os.path.realpath(os.path.join(cwd, os.path.expanduser(path)))
    if under_plugin(full) and not developing_plugin(cwd):
        return ("this file is part of the installed ravenwatch plugin; changing it would change the push gate "
                "itself. If it needs a change, the owner makes it in the ravenwatch repository and updates the "
                "plugin.")
    if GITCONFIG_FILE.search(full):
        return "this is a git config file; changes there could skip or redirect the review hook. Ask the owner."
    gdir = git_dir_of(full)
    if gdir or STATE_NAME.search(full):
        if REPORTS_PATH.search(os.path.dirname(full)):
            return None  # review reports are records, not state the hook reads
        return ("this file is inside a git directory (hooks, config or ravenwatch verdict state). Verdicts are "
                "recorded only by the review skill; hooks are managed with /ravenwatch:install-git-hook.")
    return None


def _too_slow(signum, frame):
    raise TimeoutError("the check took too long")


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
    signal.signal(signal.SIGALRM, _too_slow)
    signal.alarm(10)  # hooks.json gives the guard 15 s
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
        # Fail closed only for pushes and for writes to git-looking paths; never brick unrelated tools.
        reason = None
        target = str(inp.get("file_path") or inp.get("notebook_path") or "")
        command = inp.get("command") or ""
        if (tool == "Bash" and (may_push(command) or isinstance(exc, TimeoutError)
                                and re.search(r"(?i)\.git|ravenwatch|hooks|>", command))) or \
                (tool != "Bash" and re.search(r"(?i)\.git\b|ravenwatch|hooks", target)):
            reason = (f"internal error while checking this ({type(exc).__name__}: {exc}). "
                      "Start Claude Code with RAVENWATCH_DISABLE=1 to bypass the gate if this persists.")
    if reason:
        deny(reason)
    allow()


if __name__ == "__main__":
    main()
