"""Secrets left behind in shell and REPL history files.

Secrets are never printed: every match is masked as ****. The fix removes the
affected lines and deliberately keeps NO backup, since a backup would keep the
secret on disk. Removing a line does not un-leak a secret: it must be rotated.
"""

from __future__ import annotations

import os
import re
import stat
from typing import Iterator, List, Pattern, Tuple

from ..core import Context, FileChange, Finding, Fix, NeedsRoot, PasswdEntry, Severity, check, failed, passed

HISTORY_FILES = [
    ".bash_history", ".zsh_history", ".histfile", ".sh_history", ".ash_history",
    ".local/share/fish/fish_history", ".mysql_history", ".psql_history", ".python_history",
    ".sqlite_history", ".rediscli_history", ".node_repl_history", ".mongosh/mongosh_repl_history",
]

# (name, regex, group holding the secret)
PATTERNS: List[Tuple[str, Pattern[str], int]] = [
    ("password option", re.compile(r"--(?:password|passwd|pass)(?:=|\s+)(?!\$)(['\"]?)([^\s'\"]+)\1"), 2),
    ("mysql -p<password>", re.compile(r"\b(?:mysql|mysqldump|mariadb|mysqladmin|mariadb-dump)\b.*?\s-p(?!\$)([^\s]+)"), 1),
    ("sshpass -p", re.compile(r"\bsshpass\b.*?\s-p\s*(?!\$)(\S+)"), 1),
    ("redis-cli -a", re.compile(r"\bredis-cli\b.*?\s-a\s+(?!\$)(\S+)"), 1),
    ("docker login -p", re.compile(r"\bdocker\s+login\b.*?\s-p\s+(?!\$)(\S+)"), 1),
    ("credentials in URL", re.compile(r"\b[a-zA-Z][a-zA-Z0-9+.-]*://[^\s/:@]+:([^\s/@]+)@"), 1),
    ("curl -u user:pass", re.compile(r"\bcurl\b.*?\s(?:-u|--user)\s+['\"]?[^\s:'\"]+:([^\s'\"]+)"), 1),
    ("secret in variable", re.compile(
        r"\b[A-Za-z0-9_]*(?:PASSWORD|PASSWD|SECRET|TOKEN|API_?KEY|ACCESS_?KEY|PRIVATE_?KEY)[A-Za-z0-9_]*"
        r"\s*=\s*(['\"]?)(?![\s$'\"])([^\s'\"]+)\1", re.I), 2),
    ("password piped to sudo -S", re.compile(r"\becho\s+(['\"]?)([^\s|'\"]+)\1\s*\|\s*sudo\s+(?:\S+\s+)*-S\b"), 2),
    ("password piped to chpasswd", re.compile(r"\b(?:echo|printf)\s+['\"]?[^\s:'\"]+:([^\s'\"|]+)['\"]?\s*\|.*\bchpasswd\b"), 1),
    ("htpasswd -b", re.compile(r"\bhtpasswd\b\s+(?:-\S*\s+)*-\w*b\w*\s+(?:-\S+\s+)*\S+\s+\S+\s+(\S+)"), 1),
    ("useradd/usermod -p", re.compile(r"\b(?:useradd|usermod)\b.*?\s-p\s+(\S+)"), 1),
    ("SQL password", re.compile(r"(?i)\b(?:identified\s+(?:with\s+\S+\s+)?by|password)\s*(?:=\s*)?'([^']+)'"), 1),
    ("AWS access key", re.compile(r"\b(A(?:KIA|SIA)[0-9A-Z]{16})\b"), 1),
    ("GitHub token", re.compile(r"\b(gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{22,})\b"), 1),
    ("GitLab token", re.compile(r"\b(glpat-[A-Za-z0-9_-]{20,})\b"), 1),
    ("Slack token", re.compile(r"\b(xox[abposr]-[A-Za-z0-9-]{10,})\b"), 1),
    ("API key (sk-...)", re.compile(r"\b(sk-(?:ant-|proj-)?[A-Za-z0-9_-]{20,})\b"), 1),
    ("Bearer token", re.compile(r"(?i)authorization:\s*bearer\s+([A-Za-z0-9._~+/=-]{8,})"), 1),
    ("private key", re.compile(r"(-----BEGIN [A-Z ]*PRIVATE KEY-----)"), 1),
]

MASK = "****"
MAX_SHOWN_LINE = 140


# A "secret" that starts like this is almost always a regex, a shell expansion or a
# placeholder, e.g. grep -oP 'KEY = "\K[^"]+', sed "s|^SECRET=.*|...|", TOKEN=$(cat f), PASS=<pass>.
_EXPRESSION_START = (".", "\\", "[", "(", "*", "^", "<", "{", "$")


def looks_like_expression(value: str) -> bool:
    v = value.strip("'\"")
    return (not v or v.startswith(_EXPRESSION_START) or "$(" in v or "${" in v
            or set(v) <= set("*x.-_"))


def scan_line(line: str) -> Tuple[List[str], str]:
    """Return (pattern names that matched, line with every secret masked)."""
    names: List[str] = []
    spans: List[Tuple[int, int]] = []
    for name, regex, group in PATTERNS:
        for m in regex.finditer(line):
            start, end = m.span(group)
            if end > start and not looks_like_expression(line[start:end]):
                names.append(name)
                spans.append((start, end))
    if not spans:
        return [], line
    masked = line
    for start, end in sorted(_merge(spans), reverse=True):
        masked = masked[:start] + MASK + masked[end:]
    return sorted(set(names)), masked


def _merge(spans: List[Tuple[int, int]]) -> List[Tuple[int, int]]:
    merged: List[Tuple[int, int]] = []
    for s, e in sorted(spans):
        if merged and s <= merged[-1][1]:
            merged[-1] = (merged[-1][0], max(e, merged[-1][1]))
        else:
            merged.append((s, e))
    return merged


def _users(ctx: Context) -> List[PasswdEntry]:
    entries = [e for e in ctx.passwd() if (e.uid == 0 or 1000 <= e.uid < 65534) and e.home not in ("", "/")]
    if ctx.live and not ctx.is_root:
        me = ctx.invoking_user()
        entries = [e for e in entries if e.name == me]
    return entries


def _history_files(ctx: Context) -> Iterator[Tuple[PasswdEntry, str, os.stat_result]]:
    seen = set()
    for user in _users(ctx):
        for rel in HISTORY_FILES:
            path = user.home.rstrip("/") + "/" + rel
            if path in seen:
                continue
            seen.add(path)
            try:
                st = ctx.lstat(path)
            except NeedsRoot:
                continue
            if st is None or not stat.S_ISREG(st.st_mode):
                continue  # symlinks are ignored on purpose
            yield user, path, st



@check("HIST-001", "Secrets in shell history", "history")
def secrets_in_history(ctx: Context) -> Iterator[Finding]:
    scanned = 0
    found = False
    for user, path, _st in _history_files(ctx):
        try:
            text = ctx.read_text(path, nofollow=True)
        except NeedsRoot:
            continue
        if text is None:
            continue
        scanned += 1
        lines = text.splitlines(True)
        keep: List[str] = []
        hits: List[str] = []
        for no, line in enumerate(lines, 1):
            names, masked = scan_line(line.rstrip("\n"))
            if names:
                if len(masked) > MAX_SHOWN_LINE:
                    masked = masked[:MAX_SHOWN_LINE] + "..."
                hits.append("line %d [%s]: %s" % (no, ", ".join(names), masked))
            else:
                keep.append(line)
        if not hits:
            continue
        found = True
        yield failed(
            Severity.HIGH, "%d line(s) with secrets in %s" % (len(hits), path), id="HIST-001:%s" % path,
            details=hits,
            recommendation="Change every exposed password/token NOW - it has been sitting on disk. "
                           "Tip: on Ubuntu (HISTCONTROL=ignoreboth) a command that starts with a space "
                           "is not saved to history.",
            fix=Fix(summary="Remove %d line(s) containing secrets from %s (no backup is kept)" % (len(hits), path),
                    changes=[FileChange(path, content="".join(keep), sensitive=True)],
                    warnings=["Removing the lines does not make the secrets safe again: rotate them.",
                              "If a shell that ran these commands is still open, run 'history -c' in it, "
                              "otherwise it may write them back when it exits."]),
        )
    if not found:
        if scanned == 0 and ctx.live and not ctx.is_root:
            yield passed("No history files found for the current user (run with sudo to scan all users)")
        else:
            yield passed("No secrets found in %d history file(s)" % scanned)


@check("HIST-002", "History file permissions", "history")
def history_permissions(ctx: Context) -> Iterator[Finding]:
    bad = False
    for _user, path, st in _history_files(ctx):
        mode = stat.S_IMODE(st.st_mode)
        if mode & 0o077:
            bad = True
            yield failed(Severity.MEDIUM, "%s is readable by other users (mode %04o)" % (path, mode),
                         id="HIST-002:%s" % path, recommendation="chmod 600 %s" % path,
                         fix=Fix(summary="chmod %04o %s" % (mode & ~0o077, path),
                                 changes=[FileChange(path, mode=mode & ~0o077)]))
    if not bad:
        yield passed("History files are private")
