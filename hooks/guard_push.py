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

Only plain commands are parsed: literal words, quoted strings and operators. A
command with other shell features (variables, `$(…)`, backticks, subshells,
braces, comments, backslashes) can't be parsed reliably, so it is let through
only when, read as text, it can't touch git, write a file or run other code.
Matching errs on the side of denying: a false denial costs a reworded command,
a miss costs an unreviewed push. Set RAVENWATCH_DISABLE=1 in Claude
Code's environment to turn the gate off.
"""

import codecs
import glob
import itertools
import json
import os
import pwd
import re
import shlex
import signal
import subprocess
import sys
import warnings

SCRIPTS = os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "scripts"))
PLUGIN_ROOT = os.path.realpath(os.path.dirname(SCRIPTS))
HELPER = os.path.realpath(os.path.join(SCRIPTS, "ravenwatch.py"))
# Commands that only read their arguments: reading the plugin's own files is fine.
# (No pagers, tree or rg: they can write files or run commands through options.)
READERS = {"cat", "head", "tail", "ls", "grep", "egrep", "fgrep", "wc", "file", "stat", "cmp", "md5", "md5sum",
           "shasum", "sha256sum"}
PYTHONS = re.compile(r"^python3?(?:\.\d+)?$")
# Options whose value is a pattern to match, not a file (`grep --exclude-dir=.git`, `tar --exclude=.git`).
PATTERN_OPTION = re.compile(r"exclude|include|ignore|filter|pattern|regex|glob|match", re.I)
# Words bash runs a following `cd` through (`builtin cd x`, `if cd x; then`, `time cd x`).
CD_PREFIXES = {"builtin", "command", "exec", "time", "!", "if", "elif", "then", "else", "do", "while", "until"}
# More matches than this and a glob is treated as unknowable (checking them all could take too long).
GLOB_LIMIT = 2000
# More magic (`*?[`) path components than this: the pattern is uncheckable (deep globs can overflow glob).
GLOB_DEPTH = 24
# File names that matter when the directory a command runs in is unknown.
SENSITIVE_NAMES = {"status", "latest", "prepared", "checks.kv", "brief-approved.md", "brief-trust", "config",
                   "pre-push", "pre-push.local", "head", "guard_push.py", "ravenwatch.py", "git-pre-push.sh",
                   "hooks.json"}
HOOK_SOURCE = os.path.join(SCRIPTS, "git-pre-push.sh")
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
# Programs that write to files named in their arguments: a path there that the guard can't work out
# (a variable set from command output, `read` …) is refused rather than assumed harmless. sed and perl
# scripts can write files (`w file`) even without -i; `$` inside their single-quoted scripts is text.
WRITERS = {"cp", "mv", "tee", "dd", "install", "rsync", "ln", "touch", "mkdir", "truncate", "ditto", "rename",
           "patch", "chmod", "chown", "rm", "rmdir", "sed", "perl", "unlink", "shred", "link", "gzip", "gunzip",
           "bzip2", "xz", "zstd", "zip", "cpio", "pax", "split", "csplit", "mkfifo", "mknod", "chflags", "xattr",
           "setfacl", "chgrp", "sponge", "ed", "ex", "vi", "vim", "nvim", "nano", "emacs", "scp", "sftp", "base64",
           "xxd", "uniq", "sort", "openssl", "gpg", "ssh-keygen", "plutil", "defaults", "sqlite3"}
# Programs that only write where an option says (other arguments are URLs, headers, archive members …).
OUTPUT_OPTS = {
    "curl": {"-o", "--output", "-D", "--dump-header", "-c", "--cookie-jar", "--trace", "--trace-ascii",
             "--libcurl", "--etag-save", "--hsts", "--alt-svc",
             "--output-dir", "--stderr"},
    "wget": {"-O", "--output-document", "-P", "--directory-prefix", "-o", "--output-file", "-a", "--append-output"},
    "tar": {"-f", "--file", "-C", "--directory"},
    "unzip": {"-d"},
}
REPORTS_PATH = re.compile(r"/ravenwatch/reports(?:/|$)")
# ravenwatch state file names, wherever they are written (a directory may become a git dir later).
STATE_NAME = re.compile(r"/ravenwatch/(?:status|latest|brief-approved\.md|brief-trust|verdicts/|checks/"
                        r"|runs/[^/]+/(?:prepared|checks\.kv|checks\.md|brief\.md|context\.md)$)")
# git subcommands that can run arbitrary commands (and so a push the gate can't see).
RUNS_COMMANDS = {"submodule", "bisect", "rebase", "filter-branch", "filter-repo", "for-each-repo", "difftool",
                 "mergetool", "worktree"}
# git global options that take a separate value.
GIT_VALUE_OPTS = {"-C", "-c", "--namespace", "--exec-path", "--git-dir", "--work-tree", "--config-env", "--attr-source"}
# git global options that take no value. Any other option before the subcommand might take one.
GIT_FLAG_OPTS = {"-p", "--paginate", "-P", "--no-pager", "--bare", "--no-replace-objects", "--literal-pathspecs",
                 "--glob-pathspecs", "--noglob-pathspecs", "--icase-pathspecs", "--no-optional-locks", "--no-advice",
                 "--no-lazy-fetch", "--html-path", "--man-path", "--info-path", "-v", "--version", "-h", "--help"}
# git subcommand options that name a file or directory git writes to (repository paths are fine to name).
GIT_OUTPUT_OPTS = {"-o", "--output", "--output-directory", "--prefix", "--file"}
# A parameter expansion: $NAME, ${…}, $1, $@ …
EXPANSION = re.compile(r"\$(?:\{[^}]*\}?|[A-Za-z_][A-Za-z0-9_]*|[0-9@*#?!$-])")
# A review report's path inside .git (records, not state the hook reads); `..` would leave the folder.
REPORT_TEXT = re.compile(r"\.git/ravenwatch/reports/(?![^\s;&|<>\"']*\.\.)[^\s;&|<>\"']*")
# Builtins that set variables.
DECLARERS = {"export", "declare", "typeset", "readonly", "local", "set", "unset"}
# ANSI-C ($'…') quoting: the shell decodes escapes inside it.
ANSI_QUOTE = re.compile(r"\$'((?:[^'\\]|\\.)*)'")
# Escapes whose meaning differs between Python, bash and zsh (\c truncates, a bare \x, \u or \U, NUL …):
# a $'…' using them can't be decoded reliably, so it is refused.
UNSURE_ESCAPE = re.compile(r"\\(?:c|0|N|x(?![0-9A-Fa-f]{2})|u(?![0-9A-Fa-f]{4})|U(?![0-9A-Fa-f]{8}))")


def may_push(text):
    """True if `push` appears as a word, after removing quotes and backslashes (so `pu''sh` counts)."""
    return bool(PUSH_WORD.search(re.sub(r"[\"'\\]", "", text)))


def decode_ansi(text):
    """(text with each $'…' replaced by what the shell makes of it, whether every one decoded).
    `$'--no-\\x76erify'` → `--no-verify`. Only trusted once UNSURE_ESCAPE has ruled out escapes the shells
    disagree on; a body that still fails to decode makes the command uncheckable."""
    ok = [True]

    def decoded(m):
        try:
            with warnings.catch_warnings():
                warnings.simplefilter("ignore")  # escapes Python doesn't know (\e) stay as they are
                return codecs.decode(m.group(1), "unicode_escape")
        except (UnicodeDecodeError, ValueError):
            ok[0] = False
            return m.group(1)
    return ANSI_QUOTE.sub(decoded, text).replace('$"', '"'), ok[0]


def shell_views(text):
    """The ways the shell may read a command or word: as written, with line continuations joined,
    with $'…' decoded, without quotes and backslashes, and without variables (`RAVENWATCH_DIS${X}ABLE`)."""
    joined = re.sub(r"\\\r?\n", "", text)
    decoded = decode_ansi(joined)[0]
    return [text, joined, decoded, re.sub(r"[\"'\\]", "", decoded),
            re.sub(r"[\"'\\]", "", EXPANSION.sub("", decoded))]


def option_values(args, opts):
    """The values of the given options: `-o v`, `-ov`, `-sSo v`, `-sSov`, `--output v`, `--output=v`."""
    short = {o[1] for o in opts if len(o) == 2 and o[0] == "-"}
    values = []
    for i, a in enumerate(args):
        following = args[i + 1] if i + 1 < len(args) else None
        if a.startswith("--"):
            name, eq, value = a.partition("=")
            if name in opts:
                values += [value] if eq else [following] if following is not None else []
        elif a.startswith("-") and len(a) > 1:
            for j, ch in enumerate(a[1:], 1):
                if ch in short:
                    rest = a[j + 1:]
                    values += [rest] if rest else [following] if following is not None else []
                    break
    return values


def bypass_reason(text):
    """Why text skips or redirects the hook, in any of its shell views; else None."""
    for view in shell_views(text):
        for rx, why in BYPASS:
            if rx.search(view):
                return why
    return None


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
    """True if a plain push here may also push submodules (through their own, unchecked hooks): push
    recursion is switched on, whether or not the guard can find submodules (git finds them in places the
    guard would miss, such as a gitlink in an older pushed commit). push.recurseSubmodules and
    submodule.recurse both set the mode, and the one git reads last wins (the order `git config
    --get-regexp` lists them in). The git hook applies the same rule."""
    return effective_recursion(
        git(repo, "config", "--get-regexp", r"^(push\.recursesubmodules|submodule\.recurse)$")[1])


def effective_recursion(listing):
    """Whether push recursion is on, from `git config --get-regexp` output, the last entry winning like git
    does. Anything but a value known to mean off counts as on (git reads `submodule.recurse=2` as true)."""
    on = False
    for line in listing.splitlines():
        key, _, value = line.partition(" ")
        value = value.strip().lower()
        if key.lower() == "push.recursesubmodules":
            on = value not in ("check", "no", "false", "off", "0")
        elif key.lower() == "submodule.recurse":
            on = value not in ("false", "no", "off", "0")
    return on


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
    """All paths a plain shell word could refer to, relative to base (globs expanded). None if unknowable."""
    if target.startswith("-"):
        return None
    target = os.path.expanduser(target)
    if not os.path.isabs(target) and base is None:
        return None
    full = target if os.path.isabs(target) else os.path.join(base, target)
    if any(ch in target for ch in "*?["):
        # Each magic path component makes glob recurse one level; too many would overflow the stack
        # (and glob that many directories), so treat it as uncheckable rather than risk a crash.
        if sum(1 for part in full.split(os.sep) if any(ch in part for ch in "*?[")) > GLOB_DEPTH:
            raise TooManyMatches(target)
        # Like the shell: a pattern that matches nothing is passed on literally — but it is checked
        # against every existing directory its leading part matches, since the file may be created there.
        return [os.path.normpath(p) for p in glob_existing(full)] or [os.path.normpath(full)]
    return [os.path.normpath(full)]


class TooManyMatches(Exception):
    pass


class UnreadablePattern(Exception):
    """A pattern Python's glob can't read, though a shell may still expand it."""


def glob_existing(pattern):
    """Matches of a pattern; if none, the pattern's leading directories that do match, with the rest
    appended literally (the path that would be created there)."""
    found = []
    try:
        matches = list(itertools.islice(glob.iglob(pattern), GLOB_LIMIT + 1))  # stop at the limit, like before
    except (re.error, ValueError) as exc:
        raise UnreadablePattern(pattern) from exc  # the caller decides: refuse a write, ignore a read
    for path in matches:
        found.append(path)
        if len(found) > GLOB_LIMIT:
            raise TooManyMatches(pattern)
    parent, name = os.path.split(pattern)
    if found or parent == pattern or not any(ch in parent for ch in "*?["):
        return found
    return [os.path.join(d, name) for d in glob_existing(parent)]


def safe_expand(base, target):
    """expand(), with a pattern glob can't read giving no paths."""
    try:
        return expand(base, target)
    except UnreadablePattern:
        return None


def resolve(base, target):
    """The single directory a `cd` target refers to, or None if it is unknowable or ambiguous."""
    try:
        paths = expand(base, target)
    except UnreadablePattern:
        return None
    return paths[0] if paths is not None and len(paths) == 1 else None


def risky_when_lost(word):
    """A relative word that could reach hooks, verdict state or the plugin from a directory we can't know."""
    w = word.rstrip("/")
    return "/" in w or os.path.basename(w).lower() in SENSITIVE_NAMES or w.lower() in (".git", "..")


def touches_git_dir(bases, words, protect_plugin=False, writes=False, check_lost=True):
    """(word, "git" | "config" | "plugin" | "lost" | "many") for the first word (argument or redirect target)
    of a plain command that refers to something inside a git directory, to a git config file (when the command
    writes) or, when protect_plugin is set, to ravenwatch's own installed code, from any directory the
    command may be in (None = unknown); else None."""
    for w in words:
        if w.startswith("-"):
            if "=" not in w:
                continue
            opt, w = w.split("=", 1)  # --output=FILE, --target-directory=DIR
            if not w or PATTERN_OPTION.search(opt):
                continue
        for base in bases:
            if check_lost and base is None and not w.startswith(("/", "~")) and risky_when_lost(w):
                return w, "lost"
            try:
                paths = expand(base, w) or []
            except TooManyMatches:
                return w, "many"
            except UnreadablePattern:
                if writes:
                    return w, "pattern"
                continue  # a read: a regex such as `grep '[z-a]'` is just text
            for p in paths:
                if git_dir_of(p) and not REPORTS_PATH.search(p):
                    return w, "git"
                if writes and GITCONFIG_FILE.search(p):
                    return w, "config"
                if protect_plugin and under_plugin(p):
                    return w, "plugin"
    return None


def path_refusal(word, kind):
    if kind == "many":
        return (f"`{word}` matches more than {GLOB_LIMIT} paths, too many for the guard to check. Use a narrower "
                "pattern or name the files.")
    if kind == "pattern":
        return (f"the guard can't read the pattern in `{word}`, and this command writes there. Write the path "
                "out.")
    if kind == "config":
        return (f"`{word}` is a git config file; changes there (aliases, hooks path, includes) could skip or redirect "
                "the review hook. Ask the owner to make the change.")
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


def helper_refusal():
    """The helper records verdicts and installs the hook, so it must be the code that was committed."""
    if plugin_modified():
        return ("ravenwatch's own scripts or hooks have uncommitted changes, so the helper can't be trusted to "
                "record verdicts or install hooks. Commit them first (the review will see them).")
    return None

# Shells that run a command string given with -c (`sh -c '…'`, also inside xargs, find -exec, timeout …).
SHELLS = {"sh", "bash", "zsh", "dash", "ksh", "mksh", "fish", "su"}
# Programs that run code given to them (a string, a file or stdin): what they do can't be seen.
INTERPRETERS = {"python", "perl", "ruby", "node", "nodejs", "deno", "bun", "php", "lua", "osascript", "awk", "gawk",
                "nawk", "mawk", "tclsh", "Rscript"}
# Commands a command with shell features may run: they only read, print or set shell state, and none of them
# writes a file, runs another command or reaches the network (curl only without output options). Anything
# else in such a command is refused — a default deny, since such a command can't be parsed reliably.
READ_ONLY = {"echo", "printf", "cat", "head", "tail", "ls", "grep", "egrep", "fgrep", "wc", "cut", "tr", "date",
             "pwd", "basename", "dirname", "realpath", "readlink", "stat", "file", "du", "df", "seq", "expr", "test",
             "[", "[[", "true", "false", ":", "sleep", "which", "type", "jq", "diff", "cmp", "comm", "column", "nl",
             "rev", "tac", "fold", "fmt", "paste", "md5", "md5sum", "shasum", "sha256sum", "od", "hexdump", "read",
             "cd", "pushd", "popd", "export", "local", "declare", "readonly", "set", "unset", "shift", "return",
             "exit", "break", "continue", "wait", "printenv", "id", "whoami", "uname", "hostname", "nproc", "sort",
             "uniq", "curl"}
# Shell words that come before a command name rather than being one.
KEYWORDS = {"if", "then", "elif", "else", "fi", "do", "done", "while", "until", "time", "!", "esac", "in"}
GLOB_CHARS = re.compile(r"[*?\[\]]")
# Redirections that write nowhere: to /dev/null or to another file descriptor.
HARMLESS_REDIRECT = re.compile(r"\d*>>?&\d+-?|&?\d*>>?[ \t]*/dev/null\b|\d*>&-")
# Builtins that change the shell itself (its variables, functions, aliases, options), which a push in the
# same command would then run under: `export HOME=/tmp/x; git push` reads another gitconfig.
STATE_BUILTINS = DECLARERS | {"alias", "unalias", "hash", "enable", "source", ".", "eval", "exec", "trap", "shopt",
                              "setopt", "unsetopt", "emulate", "builtin", "zmodload", "autoload", "function", "let",
                              "read", "mapfile", "readarray", "getopts"}
# `set -e`, `set -o pipefail` …: options only, no variables.
SET_OPTION_NAMES = {"errexit", "nounset", "pipefail", "xtrace", "verbose", "noclobber", "noglob"}
# A comment of plain words, up to the end of its line.
INERT_COMMENT = re.compile(r"#[A-Za-z0-9 \t.,:_/+=@%-]*(?=\n|$)")
# Claude Code's way to pass a commit message: `-m "$(cat <<'EOF' … EOF)"`. With a quoted delimiter the body
# is plain text, so the whole substitution is one literal word — if the shell's own end of the body (the
# first line that is exactly the delimiter) is followed by nothing but the closing `)`.
CAT_SUBST_START = re.compile(r"\$\([ \t]*cat[ \t]+<<(-?)[ \t]*(['\"])(\w+)\2[ \t]*\n")
# Downloads named after the URL in the current directory (curl -O, wget without -O), or by the server.
NAMED_BY_URL = {"curl": {"-O", "--remote-name", "--remote-name-all"}, "wget": set()}
NAMED_BY_SERVER = {"curl": {"-J", "--remote-header-name"}, "wget": {"--content-disposition", "--trust-server-names"}}
# Options that make a URL-named download land somewhere else or under other names.
UNMODELLED_DOWNLOAD = {"curl": {"--output-dir", "--create-dirs", "-K", "--config"},
                       "wget": {"-r", "--recursive", "-m", "--mirror", "-p", "--page-requisites", "-i",
                                "--input-file", "-x", "--force-directories", "-e", "--execute", "-B", "--base",
                                "--cut-dirs", "-nH", "--no-host-directories"}}
# A heredoc (`<<'EOF'`, `<<-"EOF"`, `<<EOF`, but not `<<<`). With a quoted delimiter its body is never
# expanded; with a bare one, only a body free of `$`, backticks and backslashes counts as plain text.
DATA_HEREDOC = re.compile(r"<<(-?)[ \t]*(['\"]?)(\w+)\2(?=[\s;&|<>]|$)")
HEREDOC_STDIN = "HEREDOC_BODY"
STRICT_HELP = ("Commands with variables, `$(…)`, backticks, subshells, braces, backslashes or `#` comments may "
               "only run read-only programs (echo, cat, grep, ls, head, wc …). Anything else — git, writing files, "
               "other programs — must be plain: literal words, quoted strings and operators (`&&`, `|`, `>` …). "
               "Everything inside single quotes is plain text, so quote braces, `$` and backslashes (`'@{u}'`, "
               "`'a\\|b'`). Otherwise write paths and values out, split the command, use the Write/Edit tools for "
               "files, or a script file. A commit message can be given as `-m \"$(cat <<'EOF' … EOF)\"` or with "
               "`git commit -F <file>`.")


def quote_contexts(text):
    """The quote context (None, "'" or '"') before each character of a plain command, and after the last.
    Plain commands have no escapes, substitutions or comments, so quotes are all there is to track."""
    contexts, quote = [], None
    for ch in text:
        contexts.append(quote)
        if quote is None and ch in "'\"":
            quote = ch
        elif quote is not None and ch == quote:
            quote = None
    contexts.append(quote)
    return contexts


def cat_substitutions(command):
    """[(start, end, body)] for each `$(cat <<'EOF' … EOF)` the shell reads as exactly that: the body runs to
    the first line that is the delimiter (after leading tabs with `<<-`), and only blanks and the closing `)`
    follow it. Anything else after that line is not stripped, so the command isn't plain."""
    found, pos = [], 0
    while True:
        m = CAT_SUBST_START.search(command, pos)
        if not m:
            return found
        pos = m.end()
        delim, tabs, i = m.group(3), m.group(1) == "-", m.end()
        while i <= len(command):
            end = command.find("\n", i)
            line = command[i:] if end < 0 else command[i:end]
            if (line.lstrip("\t") if tabs else line) == delim:
                close = re.match(r"[ \t\n]*\)", command[i + len(line):])
                if close:
                    found.append((m.start(), i + len(line) + close.end(), command[m.end():i]))
                    pos = i + len(line) + close.end()
                break
            if end < 0:
                break
            i = end + 1


def strip_data_heredocs(command):
    """(the command with heredoc bodies that are plain data taken out, [(body, index in the result)]).
    `"$(cat <<'EOF' … EOF)"` becomes the literal word HEREDOC_BODY; any other heredoc with a quoted
    delimiter becomes `< HEREDOC_BODY` (its body is the command's stdin). Only exact for plain text: if the
    result isn't plain, the caller doesn't parse it, and checks the original command as text instead."""
    contexts = quote_contexts(command)
    out, pos, bodies = [], 0, []
    for start, end, body in cat_substitutions(command):
        if start < pos or contexts[start] == "'":
            continue
        out.append(command[pos:start])
        bodies.append((body, sum(map(len, out))))
        out.append(HEREDOC_STDIN)
        pos = end
    text = "".join(out) + command[pos:]
    # Other quoted-delimiter heredocs: the body starts after the line that holds `<<`, and ends at the first
    # line that is the delimiter (with `<<-`, after leading tabs). Several may queue on one line. The quote
    # state is tracked as the text is read, and never inside a body.
    result, i, pending, quote = [], 0, [], None
    while i < len(text):
        ch = text[i]
        if quote is None and ch == "<":
            m = DATA_HEREDOC.match(text, i)
            if m and not text.startswith("<<<", i) and (m.group(2) or plain_body(text, m)):
                pending.append((m.group(3), m.group(1) == "-"))
                result.append(f"< {HEREDOC_STDIN}")
                i = m.end()
                continue
        if quote is None and ch == "\n" and pending:
            result.append("\n")
            i += 1
            for delim, tabs in pending:
                lines = []
                while i < len(text):
                    end = text.find("\n", i)
                    line = text[i:] if end < 0 else text[i:end]
                    i = len(text) if end < 0 else end + 1
                    if (line.lstrip("\t") if tabs else line) == delim:
                        break
                    lines.append(line)
                bodies.append(("\n".join(lines), len("".join(result))))
            pending = []
            continue
        if quote is None and ch in "'\"":
            quote = ch
        elif quote is not None and ch == quote:
            quote = None
        result.append(ch)
        i += 1
    for _ in pending:  # a heredoc on the last line: no body at all
        bodies.append(("", len("".join(result))))
    return "".join(result), bodies


def plain_body(text, m):
    """True if the body of the bare-delimiter heredoc matched by m has nothing the shell would expand."""
    start = text.find("\n", m.end())
    if start < 0:
        return True
    end = re.search(rf"^\t*{re.escape(m.group(3))}$" if m.group(1) else rf"^{re.escape(m.group(3))}$",
                    text[start + 1:], re.M)
    body = text[start + 1:start + 1 + end.start()] if end else text[start + 1:]
    return not re.search(r"[$`\\]", body)


def strip_inert_comments(text):
    """The text without `# …` comments made of plain words only (no quotes, operators, `!` …), at the start
    of a line or after a blank. Such a comment is harmless even where `#` isn't a comment (zsh without
    INTERACTIVE_COMMENTS runs it as a command named `#`)."""
    contexts = quote_contexts(text)
    out, i = [], 0
    while i < len(text):
        if text[i] == "#" and contexts[i] is None and (i == 0 or text[i - 1] in " \t\n"):
            m = INERT_COMMENT.match(text, i)
            if m:
                i = m.end()
                continue
        out.append(text[i])
        i += 1
    return "".join(out)


def plain_tilde(rest):
    """True if a word starting with `~` (rest is the text from there on) is one every shell reads the same:
    `~`, `~/…`, or `~user` for a user that exists."""
    m = re.match(r"~([A-Za-z0-9_.-]*)(?=[/\s;&|<>:]|$)", rest)
    if not m:
        return False
    if not m.group(1):
        return True
    try:
        pwd.getpwnam(m.group(1))
        return True
    except KeyError:
        return False


def plain_problem(text):
    """None if text is a plain command (literal words, single and double quotes without `$`, backticks or
    backslashes inside, operators, newlines); else the first construct that makes it not plain. For plain
    text, shlex splits words exactly as bash and zsh do."""
    quote = None
    for i, ch in enumerate(text):
        if quote == "'":
            quote = None if ch == "'" else quote
            continue
        if quote == '"':
            if ch == '"':
                quote = None
            elif ch in "$`\\":
                return f"`{ch}` inside double quotes"
            elif ord(ch) < 32 and ch not in "\t\n":
                return "a control character"
            continue
        if ch in "'\"":
            quote = ch
        elif ch in "{}" and re.match(r"(?<![^\s;&|<>]){}(?=[\s;&|<>+]|$)", text[i - (ch == "}"):]):
            continue  # `{}` on its own (find -exec): no shell expands it
        elif ch == "#" and i > 0 and text[i - 1] not in " \t\n;&|<>":
            continue  # `a#b`: inside a word, `#` is text
        elif ch in "$`\\(){}#":
            return {"$": "a variable or `$(…)`", "`": "backticks", "\\": "a backslash", "#": "a `#` comment",
                    "(": "a subshell or `(…)`", ")": "a subshell or `(…)`", "{": "braces", "}": "braces"}[ch]
        elif ch == "<" and text.startswith("<<", i) and not text.startswith("<<<", i) and text[i - 1:i] != "<":
            return "a heredoc whose delimiter isn't quoted"
        elif ch == "<" and re.match(r"<\d*-\d*>", text[i:]):
            return "a zsh number range"
        elif ch == "=" and (i == 0 or text[i - 1] in " \t\n;&|<>"):
            return "a word starting with `=`"
        elif ch == "~" and (i == 0 or text[i - 1] in " \t\n;&|<>=:") and not plain_tilde(text[i:]):
            return "a `~` that isn't your home or a user's (zsh reads `~X` as the directory in $X)"
        elif ord(ch) < 32 and ch not in "\t\n":
            return "a control character"
    return "an unclosed quote" if quote else None


def dynamic_reason(command):
    """Why a command that isn't plain must be refused, or None if it only runs read-only programs and writes
    nothing. Such a command can't be parsed reliably, so this errs on the side of refusing: every place a
    command could start is checked (wherever `;`, `&`, `|`, `(`, `)`, braces, newlines, `$(`, `<(` or
    backticks appear, quoted or not), and the command named there must be a literal, known read-only one."""
    bodies = [m.group(1) for m in ANSI_QUOTE.finditer(command)]
    if any(body != "\\0" and UNSURE_ESCAPE.search(body) for body in bodies) or not decode_ansi(command)[1]:
        return "it uses `$'…'` escapes the shells read differently"
    for view in shell_views(command)[:3]:  # as written, lines joined, $'…' decoded: quotes kept
        view = HARMLESS_REDIRECT.sub(" ", view)
        if ">" in view.replace(">(", ""):
            return "it writes to a file"
        for piece in re.split(r"\$\(|[<>]\(|[`;&|(){}\n]", view):
            words = piece.split()
            if words and words[0] in ("for", "select", "case"):
                continue  # `for f in …`: a name and words, no command
            while words and (words[0] in KEYWORDS or re.match(r"^[A-Za-z_][A-Za-z0-9_]*=", words[0])
                             or re.match(r"^\d*<", words[0])):
                # keywords, assignments, and input redirections (`done < list`: the target goes too)
                words = words[2:] if re.fullmatch(r"\d*<", words[0]) else words[1:]
            if not words:
                continue
            head, args = words[0], words[1:]
            if head not in READ_ONLY:
                return f"it runs `{head}`, which isn't a known read-only command"
            if head in DECLARERS and any(re.search(r"[$`]", a.split("=", 1)[0]) for a in args):
                return f"`{head}` builds a variable name from another variable (`RAVENWATCH_DIS$X`)"
            if head == "sort" and any(re.match(r"-[A-Za-z]*o|--output", a.lstrip("'\"")) for a in args):
                return "it runs `sort` with an output file"
            if head == "uniq" and len([a for a in args if not a.lstrip("'\"").startswith("-")]) > 1:
                return "it runs `uniq` with an output file"
            if head == "curl":
                opts = OUTPUT_OPTS["curl"] | {"-K", "--config"} | NAMED_BY_URL["curl"] | NAMED_BY_SERVER["curl"]
                short = {o[1] for o in opts if len(o) == 2}
                for word in rough_words(piece):
                    bare = word.lstrip("'\"")
                    if bare[:1] in ("$", "`") or bare.split("=")[0] in opts or \
                            (bare[:1] == "-" and bare[1:2] != "-" and any(c in short for c in bare[1:])):
                        return "it runs `curl` with an output option or an argument a variable could turn into one"
    return None


def rough_words(text):
    """Words of a command that isn't plain, split at unquoted blanks and operators, quotes kept. Rough (no
    substitutions or escapes), and only used to look for words that start with an option or a variable."""
    words, cur, quote = [], "", None
    for ch in text:
        if quote:
            quote = None if ch == quote else quote
        elif ch in "'\"":
            quote = ch
        elif ch.isspace() or ch in ";&|<>":
            words.append(cur)
            cur = ""
            continue
        cur += ch
    return [w for w in words + [cur] if w]


def segments(text):
    """Split a plain command into simple commands, each (tokens, redirect targets, the separator after it).
    None if shlex can't split it."""
    contexts = quote_contexts(text)
    text = "".join(";" if ch == "\n" and contexts[i] is None else ch for i, ch in enumerate(text))
    lexer = shlex.shlex(text, posix=True, punctuation_chars=True)
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


def dangerous_program(word):
    """True if a command word may write files, run other code or reach git: a known writer, output-option
    program, shell, interpreter or wrapper, git itself, or a word with glob characters (it could be any
    of these once the shell expands it)."""
    name = os.path.basename(word)
    return bool(GLOB_CHARS.search(word)) or name in WRITERS or name in OUTPUT_OPTS or name in SHELLS or \
        name in INTERPRETERS or name in EXECUTORS or name in ("git", "gh", "hub") or name.startswith("git-") or \
        bool(PYTHONS.match(name))


def downloaded_names(head, args):
    """Files curl/wget write named after the URL ([] if none, None if the server picks the name): curl with
    -O/--remote-name, wget unless -O/--output-document names the file (its -P directory is checked as an
    option value already, so the name is joined to it)."""
    def has(opts):
        short = {o[1] for o in opts if len(o) == 2}
        return any(a.split("=")[0] in opts or (a[:1] == "-" and a[1:2] != "-" and any(c in short for c in a[1:]))
                   for a in args)
    if head not in NAMED_BY_URL:
        return []
    if has(NAMED_BY_SERVER[head]):
        return None
    if head == "curl" and not has(NAMED_BY_URL["curl"]):
        return []
    if head == "wget" and has({"-O", "--output-document"}):
        return []
    # Only the simplest form is modelled: a download named after a full URL, in the current directory or
    # wget's -P. Anything that changes where or under which names files land is refused instead.
    if has(UNMODELLED_DOWNLOAD[head]):
        return None
    words = [a for a in args if not a.startswith("-")]
    if not words or any(not re.match(r"(?i)[a-z][a-z0-9+.-]*://[^\s{}\[\]]*$", w) for w in words):
        return None  # a word that isn't a plain URL (no scheme, URL globbing, an option's value): can't tell
    prefix = (option_values(args, {"-P", "--directory-prefix"}) or [""])[-1] if head == "wget" else ""
    return [os.path.join(prefix, re.sub(r"[?#].*", "", u).rstrip("/").rsplit("/", 1)[-1] or "index.html")
            for u in words]


def reads_code_from_stdin(seg):
    """True if the command runs code read from its stdin: a shell without -c or a script, or an interpreter
    given no script (or `-`). awk takes its program from its arguments, never stdin."""
    head = os.path.basename(seg[0]) if seg else ""
    args = seg[1:]
    if head in SHELLS:
        return not any(re.fullmatch(r"-[A-Za-z]*c[A-Za-z]*", a) for a in args) and \
            all(a.startswith(("-", "+")) for a in args)
    if head in INTERPRETERS - {"awk", "gawk", "nawk", "mawk"} or PYTHONS.match(head):
        return not args or "-" in args or all(a.startswith("-") and a not in ("-c", "-e", "-m") for a in args)
    return False


def inner_commands(seg):
    """Command strings a simple command hands to a shell to run: `sh -c STR` (also after xargs, find -exec,
    timeout …), `eval ARGS`, `watch ARGS`."""
    head = os.path.basename(seg[0]) if seg else ""
    if head in ("eval", "watch"):
        return [" ".join(a for a in seg[1:] if not a.startswith("-"))]
    found = []
    for i, tok in enumerate(seg):
        if os.path.basename(tok) in SHELLS or GLOB_CHARS.search(tok):
            for j in range(i + 1, len(seg)):
                if re.fullmatch(r"-[A-Za-z]*c[A-Za-z]*", seg[j]) and j + 1 < len(seg):
                    found.append(seg[j + 1])
                    break
                if not seg[j].startswith("-"):
                    break
    return found


def runs_unseen(seg):
    """Why a simple command runs another command on paths or input the guard can't see, else None:
    xargs/parallel with a command that writes or runs code, find with -exec of such a command or -delete."""
    head = os.path.basename(seg[0]) if seg else ""

    def worrying(words):
        return bool(words) and dangerous_program(words[0])
    if head in ("xargs", "parallel"):
        rest = [a for a in seg[1:] if not a.startswith("-")]
        if worrying(rest):
            return f"`{head}` feeds paths the guard can't see to `{rest[0]}`"
    if head == "find":
        for i, tok in enumerate(seg):
            if tok in ("-exec", "-execdir", "-ok", "-okdir") and worrying(seg[i + 1:]):
                return f"`find {tok}` runs `{seg[i + 1]}` on files the guard can't see"
            if tok in ("-delete", "-fprint", "-fprint0", "-fprintf", "-fls"):
                return f"`find {tok}` writes to or deletes files the guard can't see"
    return None


def check_bash(command, cwd, depth=0):
    if depth > 3:
        return "commands nested this deep in `sh -c`/`eval` can't be checked. Run them directly."
    # Text checks first, on the command as written (heredoc bodies included): flags and settings that skip
    # the hook, and paths into git internals, are refused wherever they appear.
    why = bypass_reason(command)
    if why:
        return f"{why}. Run the command without it."
    if any(PROTECTED_TEXT.search(REPORT_TEXT.sub("", v)) for v in shell_views(command)):
        return ("this command touches the git hooks, git config or ravenwatch state inside .git/. Read files there "
                "with the Read tool; install or remove the hook with /ravenwatch:install-git-hook. If the path only "
                "appears in text (for example a commit message), write the text to a file outside .git and use "
                "`git commit -F <file>`.")
    if git_dir_of(cwd) and not PLAIN_CD.match(command):
        return ("the shell's working directory is inside a git directory, where commands can reach the hooks and "
                "verdict state. `cd` back to the work tree first.")
    text, bodies = strip_data_heredocs(command)
    text = strip_inert_comments(text)
    problem = plain_problem(text)
    if problem:
        # Not plain: the guard can't parse it reliably, so it only lets through what can't matter.
        why = dynamic_reason(command)
        return f"this command uses {problem}, and {why}. {STRICT_HELP}" if why else None
    segs = segments(text)
    if segs is None:
        return f"this command could not be parsed. {STRICT_HELP}"
    pushing = may_push(text)
    protect_plugin = not developing_plugin(cwd)
    # Every directory the shell may be in: a `cd` only replaces the current one when the next command
    # runs after it succeeded (`&&`); after `;`, `||` or a pipe, or `popd`/`cd -`, every directory seen so
    # far stays possible. None means a directory the guard can't work out.
    heres, seen, cdpath = [cwd], [cwd], False
    for idx, (seg, redirects, sep) in enumerate(segs):
        prev_seg, prev_sep = (segs[idx - 1][0], segs[idx - 1][2]) if idx else ([], None)
        # Each command's words as the shell splits them, checked once more (quoting can hide a flag from
        # the text checks). One command at a time, so a pattern never spans `|` or `&&`.
        why = bypass_reason(" ".join(seg + redirects))
        if why:
            return f"{why}. Run the command without it."
        hit = touches_git_dir(heres, [r for r in redirects if r != HEREDOC_STDIN], protect_plugin, writes=True)
        if hit:
            return path_refusal(*hit)
        prefix = []
        while seg and (re.match(r"^[A-Za-z_][A-Za-z0-9_]*=", seg[0]) or seg[0] in CD_PREFIXES):
            if seg[0].startswith("CDPATH="):
                cdpath = True
            drop = 2 if seg[0] in ("command", "time") and seg[1:2] == ["-p"] else 1
            prefix += seg[:drop]
            seg = seg[drop:]
        if not seg:
            if pushing and any("=" in p for p in prefix):
                return ("a command that pushes can't also set shell variables (they can change which config git "
                        "reads). Run `git push` as its own command.")
            continue
        if GLOB_CHARS.search(seg[0]):
            return (f"the program name `{seg[0]}` has glob characters, so the guard can't tell what runs. Write "
                    "the program's name out.")
        head = os.path.basename(seg[0])
        if bodies and (head in ("alias", "unalias", "hash", "enable", "builtin") or
                       any(p.startswith("PATH=") for p in prefix)):
            return ("this command changes how `cat` or other commands are found, so its heredoc can't be treated as "
                    "plain text. Run that part separately.")
        shell_options_only = head == "set" and all(a.startswith(("-", "+")) or a in SET_OPTION_NAMES for a in seg[1:])
        changes_shell = (head in STATE_BUILTINS and not shell_options_only) or \
            (head == "printf" and any(a.startswith("-v") for a in seg[1:]))
        if pushing and (changes_shell or any("=" in p for p in prefix)):
            return (f"a command that pushes can't also change the shell (`{head if head in STATE_BUILTINS else prefix[0]}`): "
                    "variables, aliases and options can change which config git reads. Run `git push` as its own "
                    "command.")
        # A heredoc that reaches a shell (directly or through a pipe) is commands; one that reaches another
        # interpreter is code the guard can't read. A push in text piped into either can't be seen at all.
        reads_code = reads_code_from_stdin(seg)
        if reads_code and prev_sep in ("|", "|&") and may_push(" ".join(prev_seg)):
            return (f"`{head}` would run a push from text piped into it, which the gate cannot check. Run "
                    "`git push` as its own command.")
        if reads_code and bodies:
            body_text = "\n".join(b for b, _ in bodies)
            if may_push(body_text):
                return (f"`{head}` would run a push from a heredoc, which the gate cannot check. Run `git push` "
                        "as its own command.")
            if head in SHELLS:
                why = check_bash(body_text, cwd, depth + 1)
                if why:
                    return f"`{head}` runs its heredoc as commands: {why}"
            elif (head in INTERPRETERS or PYTHONS.match(head)) and may_push(body_text):
                return f"`{head}` runs code that pushes, which the gate cannot check. Run `git push` as its own command."
        if head == "eval" and any(t.split()[:1] in (["cd"], ["pushd"], ["popd"]) for t in seg[1:]):
            heres = list(dict.fromkeys(heres + [None]))
        for inner in inner_commands(seg):
            why = check_bash(inner, cwd, depth + 1)
            if why:
                return f"`{head}` runs `{inner[:60]}`: {why}"
        why = runs_unseen(seg)
        if why:
            return f"{why}. Name the files and run the command on them directly."
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
                os.path.realpath(p) == HELPER for b in heres for p in (safe_expand(b, args[0]) or [""])):
            refusal = helper_refusal()
            if refusal:
                return refusal
            args = args[1:]
        # Paths given to programs (cp, printf >, rm, git checkout-index --prefix=…). git's own arguments are
        # often not paths (messages, refs), so only its output options are checked there.
        if head == "git":
            outputs = [a for a in args if a.startswith("-") and "=" in a] + option_values(args, GIT_OUTPUT_OPTS)
            word = touches_git_dir(heres, outputs, False, writes=False, check_lost=False)
        else:
            protect = protect_plugin and head not in READERS
            if head in OUTPUT_OPTS:
                # Only option values are files written to (`-o f`, `-of`, `-sSo f`, `--output=f`); URLs,
                # headers and archive members are just checked as text. Downloads named after their URL land
                # in the current directory; ones the server names can't be checked.
                named = downloaded_names(head, args)
                if named is None:
                    flag = "-o <file>" if head == "curl" else "-O <file>"
                    return (f"`{head}` would save files under names or in places the guard can't work out. Give "
                            f"the file name with `{flag}` (and a full `https://` URL).")
                word = (touches_git_dir(heres, option_values(args, OUTPUT_OPTS[head]) + named, protect, writes=True)
                        or touches_git_dir(heres, args, protect, writes=False))
            else:
                word = touches_git_dir(heres, args, protect, writes=dangerous_program(head))
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
            runs_git_push = any(os.path.basename(t) in ("git", "git-push") or GLOB_CHARS.search(t)
                                for t in seg[1:]) and \
                any(PUSH_WORD.fullmatch(t) or os.path.basename(t) == "git-push" for t in seg[1:])
            if (head in EXECUTORS and may_push(seg_text)) or runs_git_push:
                return (f"`{seg[0]}` runs a push the gate cannot check (wrappers, find -exec, xargs …). "
                        "Run `git push` as its own command.")
            continue
        cdir, globs, sub, args = parsed
        # The push may run in any of the directories the shell may be in; each must be gated.
        repos = list(dict.fromkeys(resolve(h, cdir) if cdir else h for h in heres))
        is_push = sub == "push"
        for repo in repos if not is_push and sub else []:
            # Follow aliases of aliases (`aa = bb`, `bb = push`) a few levels deep.
            name, seen_names, resolved = sub, set(), False
            chain_globs, pending = [], []  # options and arguments of the levels followed so far
            while len(seen_names) < 5 and name not in seen_names:
                seen_names.add(name)
                value = alias_of(repo, name)
                if value is None:
                    resolved = True
                    break
                if value.startswith("!"):
                    if may_push(value):
                        return f"`git {sub}` is a shell alias that pushes, which the gate cannot check. Run `git push` directly."
                    resolved = True
                    break
                why = bypass_reason(value)
                if why:
                    return f"`git {sub}` expands to `{value}`: {why}."
                try:
                    _, aglobs, alias_sub, aargs = parse_git(["git"] + shlex.split(value))
                except ValueError:
                    return f"`git {sub}` is an alias the gate cannot parse. Run `git push` directly."
                if alias_sub == name:
                    resolved = True  # an alias that hides a builtin of the same name: git ignores it
                    break
                name = alias_sub
                chain_globs += aglobs
                if name == "push":
                    if chain_globs:
                        return (f"`git {sub}` expands to a push with git options (-c, -C …) the gate cannot check. "
                                "Run `git push` directly.")
                    # git expands each level in front of the rest: `aa = bb --x`, `bb = push --y` → push --y --x …
                    is_push, args, resolved = True, aargs + pending + args, True
                    break
                pending = aargs + pending
            if not resolved:
                return (f"`git {sub}` is an alias chain too deep (or looping) for the gate to follow, so it could "
                        "hide a push that skips the hook. Run the git command it stands for directly.")
        if not is_push:
            if sub in RUNS_COMMANDS and may_push(seg_text):
                # e.g. `git submodule foreach git push`, `git rebase --exec "git push"`
                return f"`git {sub}` would run a push the gate cannot check. Run `git push` as its own command."
            if "push" in seg[1:] and any(g.startswith("-") and "=" not in g and g not in GIT_VALUE_OPTS
                                         and g not in GIT_FLAG_OPTS for g in globs):
                # An option the guard doesn't know may have taken the next word as its value (`git --attr-source
                # HEAD push`), so `push` may still be the subcommand.
                return (f"`push` appears in this git command after `{sub}`, so the guard can't tell whether it "
                        "pushes. Run `git push` as its own plain command.")
            continue
        if "-c" in globs:
            return "per-command git settings (-c) on a push can change where it goes or skip the hook. Run it without -c."
        for a in args:
            if PUSH_OPTION.match(a):
                return (f"`{a}` replaces the receive command or pushes submodules through their own hooks, "
                        "which the gate cannot check. Run the push without it.")
        if None in repos:
            return ("the command changes directory in a way the gate cannot follow (CDPATH, cd options). "
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
                return ("push recursion into submodules is on in this repository (push.recurseSubmodules / "
                        "submodule.recurse — whichever git reads last wins), and submodule hooks cannot be checked. "
                        "Set push.recurseSubmodules to check (or submodule.recurse to false) in this repository's "
                        "config, and push submodules yourself.")
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


_CURRENT = {}


def risky_on_failure(command, target):
    """Whether to refuse when the checks themselves fail (out of time, or a crash): anything that pushes,
    could write somewhere, names git internals or the plugin, or uses shell features. Never unrelated tools."""
    if command is None:  # Write/Edit: only git-looking or plugin paths
        return bool(re.search(r"(?i)\.git\b|ravenwatch|hooks", target))
    words = [re.sub(r"[\"'\\]", "", w) for w in command.split()]
    return may_push(command) or any(dangerous_program(w) for w in words) or \
        bool(re.search(r"[*?\[>$`(){}#\\]|\.git|ravenwatch|hooks", command, re.I))


def _too_slow(signum, frame):
    """Out of time. A TimeoutError raised here could be swallowed by glob/os.path (it is an OSError), and
    Claude Code lets a call through when the hook itself times out, so decide here and exit at once:
    refuse anything that pushes, writes somewhere, or names paths by pattern."""
    if risky_on_failure(_CURRENT.get("command"), _CURRENT.get("target", "")):
        sys.stdout.write(json.dumps({"hookSpecificOutput": {
            "hookEventName": "PreToolUse", "permissionDecision": "deny",
            "permissionDecisionReason": "ravenwatch push gate: checking this command took too long. Use narrower "
                                        "paths or patterns, or split it into simpler commands."}}))
        sys.stdout.flush()
    os._exit(0)


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
    _CURRENT.update(command=inp.get("command") if tool == "Bash" else None,
                    target=str(inp.get("file_path") or inp.get("notebook_path") or ""))
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
        # Fail closed for pushes, for writes to git-looking paths, and for any command that could write a
        # file (a writer, an output option, or a redirect) — a crash while checking one of those must not
        # let it through (RES-1). Never brick unrelated tools.
        reason = None
        if risky_on_failure(_CURRENT.get("command"), _CURRENT.get("target", "")):
            reason = (f"internal error while checking this ({type(exc).__name__}: {exc}), and the command could "
                      "push or write. Rephrase or split it (quote patterns, name paths directly).")
    if reason:
        deny(reason)
    allow()


if __name__ == "__main__":
    main()
