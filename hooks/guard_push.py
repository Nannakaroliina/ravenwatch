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

import codecs
import fnmatch
import glob
import json
import os
import re
import shlex
import signal
import subprocess
import sys
import tempfile
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
# Longer values are not trimmed (${X%pat} tries every cut): the word counts as unknowable instead.
TRIM_LIMIT = 4096
# File names that matter when the directory a command runs in is unknown.
SENSITIVE_NAMES = {"status", "latest", "prepared", "checks.kv", "brief-approved.md", "brief-trust", "config",
                   "pre-push", "pre-push.local", "head", "guard_push.py", "ravenwatch.py", "git-pre-push.sh",
                   "hooks.json"}
HOOK_SOURCE = os.path.join(SCRIPTS, "git-pre-push.sh")
# A single plain call of the plugin's own helper (it writes verdicts and installs hooks itself;
# those calls are not pre-approved, so the owner confirms each one).
OWN_HELPER = re.compile(r"^[ \t]*python3[ \t]+" + re.escape(os.path.join(SCRIPTS, "ravenwatch.py"))
                        + r"[ \t][^;&|<>`$\n\r\\]*\Z")

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
           "patch", "chmod", "chown", "rm", "rmdir", "sed", "perl"}
# Programs that only write where an option says (other arguments are URLs, headers, archive members …).
OUTPUT_OPTS = {
    "curl": {"-o", "--output", "-D", "--dump-header", "-c", "--cookie-jar", "--trace", "--trace-ascii",
             "--output-dir", "--stderr"},
    "wget": {"-O", "--output-document", "-P", "--directory-prefix", "-o", "--output-file", "-a", "--append-output"},
    "tar": {"-f", "--file", "-C", "--directory"},
    "unzip": {"-d"},
}
# A `cat` heredoc. Its body is only dropped when the rest of its first line is just redirections:
# `cat <<EOF | sh` or `cat <<EOF && git push` keep the body, which is then checked as commands. The body
# may be empty (the delimiter on the very next line); it ends at the first line that is the delimiter.
# `cat > file <<'EOF'` writes the same body as `cat <<'EOF' > file`; the redirect is kept (and checked).
CAT_HEREDOC = re.compile(r"\bcat\s+((?:\d?>>?\s*[^\s;&|<>()\"'`$]+\s+)?)<<-?\s*(['\"]?)(\w+)\2([^\n]*)\n"
                         r"(?:.*?\n)??[ \t]*\3[ \t]*(?=\n|\)|$)", re.S)
HARMLESS_REST = re.compile(r"[\s\"')]*(?:(?:(?<=\s)\d+)?>>?\s*[^\s;&|()<>\"']+[\s\"')]*)*")
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
# Commands whose arguments name variables to set (`export RAVENWATCH_DIS${X}ABLE=1` builds a name at run time).
DECLARERS = {"export", "declare", "typeset", "readonly", "local", "set", "unset"}
# Variables whose value the guard can't know: set from command output, `read`, or loops over unknown words.
UNKNOWN_ASSIGN = re.compile(r"(?:^|[\s;&|(])(?:read|mapfile|readarray|getopts)\b[^\n;&|]*")
ASSIGNMENT = re.compile(r"(?:^|[\s;&|(])(?:(?:export|declare|typeset|readonly|local)\s+(?:-\w+\s+)*)?"
                        r"([A-Za-z_][A-Za-z0-9_]*)=(\$\([^)]*\)|`[^`]*`|\"[^\"]*\"|'[^']*'|[^\s;&|()<>]*)")
FOR_LOOP = re.compile(r"\bfor\s+([A-Za-z_][A-Za-z0-9_]*)\s+in\s+([^;\n]*)")
MKTEMP = re.compile(r"^\$\(\s*mktemp\b([^)`]*)\)$")
TMPDIR_REF = re.compile(r"\$\{?TMPDIR(?::?-[^}]*)?\}?")
# ANSI-C ($'…') quoting: the shell decodes escapes inside it.
ANSI_QUOTE = re.compile(r"\$'((?:[^'\\]|\\.)*)'")
# Escapes whose meaning differs between Python, bash and zsh (\c truncates, a bare \x, \u or \U, NUL …):
# a $'…' using them can't be decoded reliably, so it is refused.
UNSURE_ESCAPE = re.compile(r"\\(?:c|0|N|x(?![0-9A-Fa-f]{2})|u(?![0-9A-Fa-f]{4})|U(?![0-9A-Fa-f]{8}))")
# `$` and backticks inside single quotes, as segments() hands them on: plain text, never an expansion.
LITERAL = {"$": "", "`": ""}
UNLITERAL = str.maketrans({v: k for k, v in LITERAL.items()})


def may_push(text):
    """True if `push` appears as a word, after removing quotes and backslashes (so `pu''sh` counts)."""
    return bool(PUSH_WORD.search(re.sub(r"[\"'\\]", "", text)))


def quoting(command):
    """Walk a command the way the shell's quoting does. Yields (index, context) before each character and
    once more at the end, where context is None (plain), "'", '"', "$'" (ANSI-C), "#" (comment) or "\\"
    (escaped). `$(…)` and backticks start a fresh context, even inside double quotes. The one quote
    scanner: segments() aside, everything that asks "is this quoted?" uses it."""
    stack = [[None, None]]  # [open quote, what opened this level: None, "(" or "`"]
    escaped = comment = False
    i, n = 0, len(command)
    while i < n:
        ch, quote = command[i], stack[-1][0]
        yield i, "#" if comment else "\\" if escaped else quote
        if comment:
            comment = ch != "\n"
        elif escaped:
            escaped = False
        elif quote == "'":
            stack[-1][0] = None if ch == "'" else quote
        elif quote == "$'":
            if ch == "\\":
                escaped = True
            elif ch == "'":
                stack[-1][0] = None
        elif ch == "\\":
            escaped = True
        elif ch == "$" and command[i + 1:i + 2] == "(":
            stack.append([None, "("])
            i += 2
            continue
        elif ch == "`":
            if stack[-1][1] == "`" and len(stack) > 1:
                stack.pop()
            else:
                stack.append([None, "`"])
        elif quote == '"':
            stack[-1][0] = None if ch == '"' else quote
        elif ch == "$" and command[i + 1:i + 2] == "'":
            stack[-1][0] = "$'"
            i += 2
            continue
        elif ch in "'\"":
            stack[-1][0] = ch
        elif ch == ")" and len(stack) > 1 and stack[-1][1] == "(":
            stack.pop()
        elif ch == "#" and (i == 0 or command[i - 1] in " \t\n;&|()"):
            comment = True
        i += 1
    yield n, "#" if comment else "\\" if escaped else stack[-1][0]


def unquoted_dollar_quotes(command):
    """The bodies of $'…' (and `"` for each $"…") that the shell really reads as quoting — wherever they
    are, including inside `"$(…)"` — but not a `$` at the end of a quoted string (grep 'push$')."""
    found = []
    for i, context in quoting(command):
        if context is None and command[i:i + 1] == "$" and command[i + 1:i + 2] in ("'", '"'):
            m = ANSI_QUOTE.match(command, i)
            found.append(m.group(1) if m and command[i + 1] == "'" else command[i + 1])
    return found


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
    joined = re.sub(r"\\\r?\n", "", text.translate(UNLITERAL))
    decoded = decode_ansi(joined)[0]
    return [text, joined, decoded, re.sub(r"[\"'\\]", "", decoded),
            re.sub(r"[\"'\\]", "", EXPANSION.sub("", decoded))]


def resolve_word(word, variables):
    """A word with its variables filled in, if the guard knows exactly one value for it; else None."""
    if "$" not in word and "`" not in word:
        return word
    values = expand_vars(word, variables)
    return values[0] if values and len(set(values)) == 1 else None


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


def segments(command):
    """Split a command into simple commands, each (tokens, redirect targets, the separator after it),
    honouring quotes, comments and line continuations like the shell does. None if it can't be parsed."""
    # last_escaped: index in out of the last backslash-escaped character (`a\ #` is one word, not a comment).
    out, quote, escaped, i, n, last_escaped = [], None, False, 0, len(command), -1
    while i < n:
        ch = command[i]
        if escaped:
            escaped = False
            last_escaped = len(out)
        elif ch == "\\" and quote != "'":
            if command[i + 1:i + 2] == "\n":  # line continuation: the shell joins the lines
                i += 2
                continue
            escaped = True
        elif quote:
            if ch == quote:
                quote = None
            elif quote == "'" and ch in LITERAL:
                ch = LITERAL[ch]  # `$` and backticks in single quotes are text, never an expansion
        elif ch in "'\"":
            quote = ch
        elif ch == "#" and (not out or (out[-1] in " \t;&|()" and last_escaped != len(out) - 1)):
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


def unquoted_command_start(command, idx):
    """True if idx is outside quotes and comments and starts a command (after a newline, `;`, `&`, `|` or `(`).
    `$(…)` starts a fresh quoting context, even inside double quotes (`-m "$(cat <<'EOF' …`)."""
    context = next((c for i, c in quoting(command) if i >= idx), None)
    if context is not None:
        return False
    before = command[:idx].rstrip(" \t")
    return not before or before[-1] in "\n;&|("


def shell_vars(command, cwd):
    """{name: [values it may have]} for variables the command sets, or {name: None} when a value can't be
    known (command output, `read`, a loop over unknown words). `$(mktemp …)` counts as a temp path.
    $PWD is the shell's directory (cwd), never the guard's own; after a `cd` it is unknown."""
    found = {"PWD": [cwd], "OLDPWD": None}

    def add(name, values):
        # An assignment may not run (`false && X=…`) or may only apply to one command (`X=… cmd`), so the
        # value from the environment stays possible too.
        if name not in found:
            found[name] = [os.environ[name]] if name in os.environ else []
        found[name] = None if values is None or found[name] is None else found[name] + values

    for m in ASSIGNMENT.finditer(command):
        raw = m.group(2)
        if raw.startswith("'") and raw.endswith("'") and len(raw) >= 2:
            add(m.group(1), [raw[1:-1]])
            continue
        raw = raw[1:-1] if raw.startswith('"') and raw.endswith('"') and len(raw) >= 2 else raw
        temp = MKTEMP.match(raw)
        if temp:
            # A new temp path, unless the template points somewhere the guard can't see or into git internals.
            rest = TMPDIR_REF.sub("", temp.group(1))
            safe = "$" not in rest and not re.search(r"(?i)\.git\b|hooks|ravenwatch", rest)
            add(m.group(1), [os.path.join(tempfile.gettempdir(), "tmp.XXXXXXXXXX")] if safe else None)
        else:
            add(m.group(1), expand_vars(raw, {}))
    if re.search(r"(?:^|[\s;&|(])(?:cd|pushd|popd)\b", command):
        # The shell's $PWD follows its `cd`s; the guard's environment doesn't.
        found["PWD"] = found["OLDPWD"] = None
    for m in FOR_LOOP.finditer(command):
        try:
            words = shlex.split(m.group(2).split(" do ")[0])
        except ValueError:
            words = None
        values = []
        for w in words or []:
            filled = expand_vars(w, {})
            if filled is None:
                values = None
                break
            values += filled
        add(m.group(1), values if words is not None else None)
    for m in UNKNOWN_ASSIGN.finditer(command):
        for name in re.findall(r"(?<![-\w$])[A-Za-z_][A-Za-z0-9_]*", m.group(0))[1:]:
            add(name, None)
    return found


def expand_vars(word, variables):
    """The words a shell word may become once its variables are filled in (from variables, else the
    environment), or None when a part can't be known: command output, an unset variable, $1 …
    `${X:-word}` is X or word; `${X%pat}`, `${X%%pat}`, `${X#pat}` and `${X##pat}` trim X as the shell does."""
    if "`" in word or "$(" in word:
        return None
    results, pos = [""], 0
    for m in EXPANSION.finditer(word):
        tok = m.group(0)
        inner = tok[2:-1] if tok.startswith("${") and tok.endswith("}") else (None if tok.startswith("${") else tok[1:])
        if inner is None:
            return None
        op = re.fullmatch(r"([A-Za-z_][A-Za-z0-9_]*)(?:(:?[-=])(.*)|(%%?|##?)(.*))?", inner)
        if not op:
            return None
        name = op.group(1)
        values = variables[name] if name in variables else (
            [os.environ[name]] if name in os.environ else None)
        if op.group(2):  # ${X:-word}: X when set (and non-empty), else word
            fallback = expand_vars(op.group(3), variables)
            if fallback is None or (name in variables and variables[name] is None):
                return None
            values = (values or []) + fallback
        if values is None:
            return None
        if op.group(4):
            if any(ch in op.group(5) for ch in "$`\\"):
                return None
            values = [trim(v, op.group(4), op.group(5)) for v in values]
            if None in values:
                return None
        results = [r + word[pos:m.start()] + v for r in results for v in values][:64]
        pos = m.end()
    return [r + word[pos:] for r in results]


def trim(value, op, pattern):
    """${X%pat} (shortest suffix), ${X%%pat} (longest suffix), ${X#pat}, ${X##pat} (prefixes), like the shell.
    None for values too long to trim within the guard's time budget (the word is then unknowable)."""
    if len(value) > TRIM_LIMIT:
        return None
    cuts = range(len(value) + 1)
    if op.startswith("%"):
        for i in (cuts if op == "%%" else reversed(cuts)):
            if fnmatch.fnmatchcase(value[i:], pattern):
                return value[:i]
    else:
        for i in (reversed(cuts) if op == "##" else cuts):
            if fnmatch.fnmatchcase(value[:i], pattern):
                return value[i:]
    return value


def names_sensitive(word, writes=True):
    """True if the literal parts of a word (variables removed) point at git internals or ravenwatch files.
    For a read, only `.git` and `ravenwatch` count (config/, hooks/ are common project directories)."""
    literal = EXPANSION.sub("/", word.replace("`", "/"))
    parts = [p.lower() for p in literal.split("/") if p]
    if not writes:
        return any(p in (".git", "ravenwatch") for p in parts)
    return any(p in (".git", "hooks", "ravenwatch") or p in SENSITIVE_NAMES for p in parts)


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


class TooManyMatches(Exception):
    pass


def glob_existing(pattern):
    """Matches of a pattern; if none, the pattern's leading directories that do match, with the rest
    appended literally (the path that would be created there)."""
    found = []
    for path in glob.iglob(pattern):
        found.append(path)
        if len(found) > GLOB_LIMIT:
            raise TooManyMatches(pattern)
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


def touches_git_dir(bases, words, protect_plugin=False, variables=None, writes=False, check_lost=True,
                    filled_in=False):
    """(word, "git" | "plugin" | "lost" | "var" | "many") for the first word (argument or redirect target) that
    refers to something inside a git directory or, when protect_plugin is set, to ravenwatch's own installed
    code, from any directory the command may be in (None = unknown); else None. Variables are filled in from
    `variables` and the environment (once: a `$` left after that is text, as the shell doesn't expand values
    again); a word whose value can't be known is refused when the command writes there (writes) or its
    literal parts name git internals."""
    for w in words:
        if w.startswith("-"):
            if "=" not in w:
                continue
            opt, w = w.split("=", 1)  # --output=FILE, --target-directory=DIR
            if not w or PATTERN_OPTION.search(opt):
                continue
        if not filled_in and ("$" in w or "`" in w):
            filled = expand_vars(w, variables or {})
            if filled is None:
                if writes or names_sensitive(w, writes=False):
                    return w, "var"
                continue
            hit = touches_git_dir(bases, filled, protect_plugin, None, writes, check_lost, filled_in=True)
            if hit:
                return (w, hit[1])
            continue
        if filled_in:
            w = w.replace("$", LITERAL["$"]).replace("`", LITERAL["`"])  # plain text now, for expand()
        for base in bases:
            if check_lost and base is None and not w.startswith(("/", "~")) and risky_when_lost(w):
                return w, "lost"
            try:
                paths = expand(base, w) or []
            except TooManyMatches:
                return w, "many"
            for p in paths:
                if git_dir_of(p) and not REPORTS_PATH.search(p):
                    return w, "git"
                if protect_plugin and under_plugin(p):
                    return w, "plugin"
    return None


def path_refusal(word, kind):
    word = word.translate(UNLITERAL)
    if kind == "many":
        return (f"`{word}` matches more than {GLOB_LIMIT} paths, too many for the guard to check. Use a narrower "
                "pattern or name the files.")
    if kind == "var":
        return (f"the guard can't tell where `{word}` points (a variable set from command output, `read`, a "
                "loop, or not set at all), and this command writes there or names git internals. Use a literal "
                "path, or set the variable to a literal value in the same command.")
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


def drop_cat_heredocs(command):
    """The command with the bodies of `cat` heredocs left out: they are data (Claude's usual way to pass a
    commit message), not commands — unless the rest of the first line feeds the body somewhere or chains
    another command, the `cat` isn't really a command (inside quotes, or inside the body of an earlier
    heredoc), or the delimiter is unquoted and the body has command substitutions (the shell runs those)."""
    return CAT_HEREDOC.sub(
        lambda m: "cat " + m.group(1) + m.group(4) if len(m.group(4)) <= 500 and HARMLESS_REST.fullmatch(m.group(4))
        and "<<" not in command[:m.start()] and unquoted_command_start(command, m.start())
        and (m.group(2) or not re.search(r"`|\$\(", m.group(0).split("\n", 1)[-1]))
        else m.group(0), command)


def check_bash(command, cwd):
    if "\n" not in command and "\r" not in command and OWN_HELPER.match(re.sub(r"/{2,}", "/", command)):
        return helper_refusal()
    # $'…' quoting, outside heredoc bodies that are data. Escapes the shells disagree on are refused
    # wherever they appear (also where the quote scanner thinks they are quoted), and so is any body
    # Python can't decode; in a command that mentions git, any $'…' or $"…" at all.
    data = drop_cat_heredocs(command)
    dollar_quotes = unquoted_dollar_quotes(data)
    bodies = dollar_quotes + [m.group(1) for m in ANSI_QUOTE.finditer(data)]
    if any(body != "\\0" and UNSURE_ESCAPE.search(body) for body in bodies) or not decode_ansi(data)[1]:
        return ("$'…' quoting with escapes the shells read differently (\\c, \\0, \\N, or a \\x, \\u or \\U without "
                "all its digits) can't be checked. Use printf (`printf '\\t'`) or a quoted literal instead.")
    views = shell_views(command)
    if dollar_quotes and any(PUSH_WORD.search(v) or GIT_WORD.search(v) for v in shell_views(data)):
        return ("$'…' and $\"…\" quoting in a command that mentions git can't be checked. Put the text in a variable "
                "in an earlier command (`T=$(printf '\\t')`), use printf, or for a commit message write it to a file "
                "and use `git commit -F <file>`.")
    why = bypass_reason(command)
    if why:
        return f"{why}. Run the command without it."
    stripped = views[3]
    if PROTECTED_TEXT.search(command) or PROTECTED_TEXT.search(stripped):
        return ("this command touches the git hooks, git config or ravenwatch state inside .git/. Read files there "
                "with the Read tool; install or remove the hook with /ravenwatch:install-git-hook. If the path only "
                "appears in text (for example a commit message), write the text to a file outside .git and use "
                "`git commit -F <file>`.")
    if git_dir_of(cwd) and not PLAIN_CD.match(command):
        return ("the shell's working directory is inside a git directory, where commands can reach the hooks and "
                "verdict state. `cd` back to the work tree first.")
    command = data
    pushing = any(may_push(v) for v in shell_views(command))
    if pushing and re.search(r"`|\$\(|<\(|>\(", command):
        return "a push inside command substitution can't be checked. Run `git push` as its own command."
    parsed_cmd = segments(command)
    if parsed_cmd is None:
        return "could not parse this command. Run `git push` as its own plain command." if pushing else None
    segs = parsed_cmd
    # Each command's words as the shell splits them, checked once more (quoting can hide a flag from the
    # text checks). One command at a time, so a pattern never spans `|` or `&&`.
    for seg, redirects, _ in segs:
        why = bypass_reason(" ".join(seg + redirects))
        if why:
            return f"{why}. Run the command without it."
    protect_plugin = not developing_plugin(cwd)
    variables = shell_vars(command, cwd)

    # Every directory the shell may be in: a `cd` only replaces the current one when the next command
    # runs after it succeeded (`&&`); after `;`, `||`, a pipe or a subshell, or `popd`/`cd -`, every
    # directory seen so far stays possible. None means a directory the guard can't work out.
    heres, seen, cdpath, prev_sep = [cwd], [cwd], False, None
    for seg, redirects, sep in segs:
        if prev_sep == ")":
            heres = list(seen)
        prev_sep = sep
        # Redirect targets resolve against the directory the command has moved to.
        hit = touches_git_dir(heres, redirects, protect_plugin, variables, writes=True)
        if hit:
            return path_refusal(*hit)
        dynamic_prefix = False  # `X=$Y git push`: an environment setting the guard can't read
        while seg and (re.match(r"^[A-Za-z_][A-Za-z0-9_]*=", seg[0]) or seg[0] in CD_PREFIXES):
            if seg[0].startswith("CDPATH="):
                cdpath = True
            dynamic_prefix = dynamic_prefix or "$" in seg[0] or "`" in seg[0]
            drop = 2 if seg[0] in ("command", "time") and seg[1:2] == ["-p"] else 1
            seg = seg[drop:]
        if not seg:
            continue
        # A command name from a variable (`G=git; $G push`): use its value if the guard knows it.
        if "$" in seg[0] or "`" in seg[0]:
            known = resolve_word(seg[0], variables)
            if known is None:
                if pushing or any(GIT_WORD.search(v) for v in views):
                    return ("this command takes its name from a variable the guard can't work out, in a command that "
                            "mentions git. Write the command name out.")
            else:
                seg, dynamic_prefix = [known] + seg[1:], True
        head = os.path.basename(seg[0])
        if head == "eval" and any(t.split()[0] in ("cd", "pushd", "popd") for t in seg[1:] if t.split()):
            heres = list(dict.fromkeys(heres + [None]))
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
        if head in DECLARERS and any(EXPANSION.search(a.split("=", 1)[0]) or "`" in a.split("=", 1)[0]
                                     for a in args):
            return f"`{head}` builds a variable name from another variable, which the guard can't check. Write the name out."
        if PYTHONS.match(head) and args and all(
                os.path.realpath(p) == HELPER for b in heres for p in (expand(b, args[0]) or [""])):
            refusal = helper_refusal()
            if refusal:
                return refusal
            args = args[1:]
        # Paths given to programs (cp, printf >, rm, git checkout-index --prefix=…). git's own arguments are
        # often not paths (messages, refs), so only paths that can be worked out are checked there.
        if head == "git":
            outputs = [a for a in args if a.startswith("-") and "=" in a] + option_values(args, GIT_OUTPUT_OPTS)
            word = touches_git_dir(heres, outputs, False, variables, writes=False, check_lost=False)
        else:
            protect = protect_plugin and head not in READERS
            if head in OUTPUT_OPTS:
                # Only option values are files written to (`-o f`, `-of`, `-sSo f`, `--output=f`); URLs,
                # headers and archive members are just checked as text.
                word = (touches_git_dir(heres, option_values(args, OUTPUT_OPTS[head]), protect, variables, writes=True)
                        or touches_git_dir(heres, args, protect, variables, writes=False))
            else:
                word = touches_git_dir(heres, args, protect, variables, writes=head in WRITERS)
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
        if "$" in sub or "`" in sub:
            known = resolve_word(sub, variables)
            if known is None:
                return "the git subcommand comes from a variable the guard can't work out. Write it out."
            sub, dynamic_prefix = known, True
        # The push may run in any of the directories the shell may be in; each must be gated.
        repos = list(dict.fromkeys(resolve(h, cdir) if cdir else h for h in heres))
        is_push = sub == "push"
        for repo in repos if not is_push and sub else []:
            # Follow aliases of aliases (`aa = bb`, `bb = push`) a few levels deep.
            name, seen_names = sub, set()
            while len(seen_names) < 5 and name not in seen_names:
                seen_names.add(name)
                value = alias_of(repo, name)
                if value is None:
                    break
                if value.startswith("!"):
                    if may_push(value):
                        return f"`git {sub}` is a shell alias that pushes, which the gate cannot check. Run `git push` directly."
                    break
                why = bypass_reason(value)
                if why:
                    return f"`git {sub}` expands to `{value}`: {why}."
                try:
                    _, aglobs, name, aargs = parse_git(["git"] + shlex.split(value))
                except ValueError:
                    return f"`git {sub}` is an alias the gate cannot parse. Run `git push` directly."
                if name == "push":
                    if aglobs:
                        return (f"`git {sub}` expands to `{value}`, a push with git options (-c, -C …) the gate "
                                "cannot check. Run `git push` directly.")
                    is_push, args = True, aargs + args
                    break
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
        if dynamic_prefix or any(EXPANSION.search(t) or "`" in t for t in seg):
            return ("a git push that uses shell variables can't be checked (a variable can disable the hook or "
                    "change what runs). Write the remote, branch and settings out.")
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


def _too_slow(signum, frame):
    """Out of time. A TimeoutError raised here could be swallowed by glob/os.path (it is an OSError), and
    Claude Code lets a call through when the hook itself times out, so decide here and exit at once:
    refuse anything that pushes, writes somewhere, or names paths by pattern."""
    command = _CURRENT.get("command")
    if command is None:  # Write/Edit: deny only git-looking or plugin paths, like other internal errors
        target = _CURRENT.get("target", "")
        risky = bool(re.search(r"(?i)\.git\b|ravenwatch|hooks", target))
    else:
        # Everything the checks would look at counts: writers, output options, variables, patterns, git.
        programs = sorted(WRITERS | set(OUTPUT_OPTS) | {"python", "python3", "ruby", "node", "printf", "echo", "git"})
        risky = may_push(command) or bool(re.search(r"[*?\[>$`]|\.git|ravenwatch|hooks|\b(?:"
                                                    + "|".join(map(re.escape, programs)) + r")\b", command, re.I))
    if risky:
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
        # Fail closed only for pushes and for writes to git-looking paths; never brick unrelated tools.
        reason = None
        target = str(inp.get("file_path") or inp.get("notebook_path") or "")
        command = inp.get("command") or ""
        if (tool == "Bash" and (may_push(command) or isinstance(exc, (TimeoutError, subprocess.TimeoutExpired))
                                and re.search(r"(?i)\.git|ravenwatch|hooks|>", command))) or \
                (tool != "Bash" and re.search(r"(?i)\.git\b|ravenwatch|hooks", target)):
            reason = (f"internal error while checking this ({type(exc).__name__}: {exc}). "
                      "Start Claude Code with RAVENWATCH_DISABLE=1 to bypass the gate if this persists.")
    if reason:
        deny(reason)
    allow()


if __name__ == "__main__":
    main()
