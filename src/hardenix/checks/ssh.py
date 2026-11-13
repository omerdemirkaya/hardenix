"""OpenSSH server configuration checks.

Fixes are written to a single drop-in file, /etc/ssh/sshd_config.d/00-hardenix.conf.
sshd uses the *first* value it reads for a keyword, and Debian/Ubuntu include
sshd_config.d/*.conf at the top of sshd_config, so a "00-" file wins over e.g.
cloud-init's "50-cloud-init.conf". Every SSH fix is validated with ``sshd -t``
before sshd is reloaded; if validation fails the file is restored automatically.
"""

from __future__ import annotations

import re
from typing import Dict, Iterator, List, Optional

from ..core import Context, FileChange, Finding, Fix, NeedsRoot, NotApplicable, Severity, check, failed, passed

SSHD_CONFIG = "/etc/ssh/sshd_config"
DROPIN_DIR = "/etc/ssh/sshd_config.d"
DROPIN = DROPIN_DIR + "/00-hardenix.conf"
DROPIN_HEADER = (
    "# Managed by hardenix. Settings here override later files because sshd uses the\n"
    "# first value it reads. Undo with: hardenix rollback\n"
)
KEEP_SESSION = (
    "Keep your current SSH session open and test a NEW login from another terminal "
    "before you log out. If the new login fails, run 'hardenix rollback' from this session."
)

# OpenSSH defaults as shipped on Debian/Ubuntu when a keyword is not set.
DEFAULTS = {
    "permitrootlogin": "prohibit-password",
    "passwordauthentication": "yes",
    "kbdinteractiveauthentication": "yes",
    "usepam": "no",
    "permitemptypasswords": "no",
    "x11forwarding": "no",
    "maxauthtries": "6",
    "port": "22",
    "authorizedkeysfile": ".ssh/authorized_keys .ssh/authorized_keys2",
}
ALIASES = {"challengeresponseauthentication": "kbdinteractiveauthentication"}


class SshdConfig:
    def __init__(self) -> None:
        self.values: Dict[str, str] = {}
        self.includes_dropin = False
        self.source = "parsed"

    def get(self, key: str) -> str:
        return self.values.get(key, DEFAULTS.get(key, "")).strip().lower()


def _parse_file(ctx: Context, path: str, cfg: SshdConfig, depth: int = 0) -> None:
    if depth > 8:
        return
    text = ctx.read_text(path)
    if text is None:
        return
    in_match = False
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        m = re.match(r"^([^\s=]+)\s*(?:=\s*|\s+|$)(.*)$", line)
        if not m:
            continue
        key, value = m.group(1).lower(), m.group(2)
        key = ALIASES.get(key, key)
        value = value.strip().strip('"')
        if key == "match":
            in_match = value.lower() != "all"
            continue
        if in_match:
            continue
        if key == "include":
            for pattern in value.split():
                if not pattern.startswith("/"):
                    pattern = "/etc/ssh/" + pattern
                if pattern.startswith(DROPIN_DIR + "/"):
                    cfg.includes_dropin = True
                for included in ctx.glob(pattern):
                    _parse_file(ctx, included, cfg, depth + 1)
            continue
        cfg.values.setdefault(key, value)  # first value wins, like sshd


def load_sshd(ctx: Context) -> SshdConfig:
    if "sshd" in ctx.cache:
        return ctx.cache["sshd"]  # type: ignore[return-value]
    if not ctx.exists(SSHD_CONFIG):
        raise NotApplicable("OpenSSH server is not installed")
    cfg = SshdConfig()
    _parse_file(ctx, SSHD_CONFIG, cfg)  # may raise NeedsRoot for 0600 drop-ins
    if ctx.is_root and ctx.run_commands:
        # sshd -T prints the effective configuration; more accurate than our parser.
        res = ctx.run(["sshd", "-T"])
        if res is not None and res.returncode == 0:
            effective = {}
            for line in res.stdout.splitlines():
                k, _, v = line.partition(" ")
                effective[ALIASES.get(k.lower(), k.lower())] = v
            cfg.values = effective
            cfg.source = "sshd -T"
    ctx.cache["sshd"] = cfg
    return cfg


def has_authorized_keys(ctx: Context, username: str, cfg: SshdConfig) -> Optional[bool]:
    """True/False if we can tell whether the user has an SSH key installed, None if unknown."""
    user = ctx.user(username)
    if user is None:
        return None
    files = cfg.get("authorizedkeysfile").split()
    if any("%" in f or f.startswith("/") for f in files):
        return None  # custom AuthorizedKeysFile layouts are not interpreted
    try:
        for rel in files:
            text = ctx.read_text(user.home.rstrip("/") + "/" + rel, nofollow=True)
            if text and any(l.strip() and not l.strip().startswith("#") for l in text.splitlines()):
                return True
    except NeedsRoot:
        return None
    return False


def _fix(ctx: Context, cfg: SshdConfig, settings: Dict[str, str], summary: str, risky: bool,
         warnings: Optional[List[str]] = None) -> Optional[Fix]:
    if not cfg.includes_dropin:
        return None  # without an Include of sshd_config.d our drop-in would be ignored
    return Fix(
        summary=summary,
        changes=[FileChange(DROPIN, set_keys=settings, header=DROPIN_HEADER, mode=0o644)],
        validate=["sshd", "-t"],
        commands=[["systemctl", "try-reload-or-restart", "ssh"]],
        undo_commands=[["systemctl", "try-reload-or-restart", "ssh"]],
        warnings=([KEEP_SESSION] if risky else []) + (warnings or []),
        risky=risky,
    )


def _no_fix_note(cfg: SshdConfig) -> List[str]:
    if not cfg.includes_dropin:
        return ["No automatic fix: sshd_config does not include sshd_config.d/*.conf; edit sshd_config directly."]
    return []


@check("SSH-001", "Root login over SSH", "ssh")
def root_login(ctx: Context) -> Iterator[Finding]:
    cfg = load_sshd(ctx)
    value = cfg.get("permitrootlogin")
    if value in ("no", "forced-commands-only"):
        yield passed("PermitRootLogin is '%s'" % value)
        return
    sev = Severity.HIGH if value == "yes" else Severity.LOW
    msg = ("Root can log in over SSH with a password" if value == "yes"
           else "Root can log in over SSH with a key (PermitRootLogin %s)" % value)
    details = _no_fix_note(cfg)
    fix = None
    user = ctx.invoking_user()
    if user and user != "root" and ctx.is_admin(user) and has_authorized_keys(ctx, user, cfg):
        fix = _fix(ctx, cfg, {"PermitRootLogin": "no"}, "Disable root login over SSH", risky=True)
    elif cfg.includes_dropin:
        details.append(
            "No automatic fix offered: first make sure a non-root user with sudo rights can log in "
            "with an SSH key, then run hardenix as that user (via sudo).")
    yield failed(sev, msg, details=details, fix=fix,
                 recommendation="Set 'PermitRootLogin no' and log in as a regular user who uses sudo.")


@check("SSH-002", "SSH password authentication", "ssh")
def password_auth(ctx: Context) -> Iterator[Finding]:
    cfg = load_sshd(ctx)
    pw = cfg.get("passwordauthentication") == "yes"
    kbd = cfg.get("kbdinteractiveauthentication") == "yes" and cfg.get("usepam") == "yes"
    if not pw and not kbd:
        yield passed("Password logins over SSH are disabled")
        return
    via = "PasswordAuthentication yes" if pw else "KbdInteractiveAuthentication yes with UsePAM"
    details = _no_fix_note(cfg)
    fix = None
    user = ctx.invoking_user()
    if user and has_authorized_keys(ctx, user, cfg):
        fix = _fix(ctx, cfg, {"PasswordAuthentication": "no", "KbdInteractiveAuthentication": "no"},
                   "Allow SSH logins with keys only", risky=True,
                   warnings=["Users who log in with a password today (not '%s') will be locked out of SSH." % user])
    elif cfg.includes_dropin:
        details.append("No automatic fix offered: the user running hardenix (%s) has no SSH key in "
                       "authorized_keys, so disabling passwords could lock you out." % (user or "unknown"))
    yield failed(Severity.MEDIUM, "SSH accepts password logins (%s)" % via, details=details, fix=fix,
                 recommendation="Use SSH keys (ssh-copy-id) and set 'PasswordAuthentication no'.")


@check("SSH-003", "SSH empty passwords", "ssh")
def empty_passwords(ctx: Context) -> Iterator[Finding]:
    cfg = load_sshd(ctx)
    if cfg.get("permitemptypasswords") != "yes":
        yield passed("PermitEmptyPasswords is 'no'")
        return
    yield failed(Severity.HIGH, "SSH allows accounts with empty passwords to log in",
                 recommendation="Set 'PermitEmptyPasswords no'.", details=_no_fix_note(cfg),
                 fix=_fix(ctx, cfg, {"PermitEmptyPasswords": "no"}, "Forbid empty passwords over SSH", risky=False))


@check("SSH-004", "SSH X11 forwarding", "ssh")
def x11(ctx: Context) -> Iterator[Finding]:
    cfg = load_sshd(ctx)
    if cfg.get("x11forwarding") != "yes":
        yield passed("X11Forwarding is 'no'")
        return
    yield failed(Severity.LOW, "X11 forwarding is enabled (rarely needed on servers)",
                 recommendation="Set 'X11Forwarding no'.", details=_no_fix_note(cfg),
                 fix=_fix(ctx, cfg, {"X11Forwarding": "no"}, "Disable X11 forwarding", risky=False))


@check("SSH-005", "SSH authentication attempts", "ssh")
def max_auth_tries(ctx: Context) -> Iterator[Finding]:
    cfg = load_sshd(ctx)
    try:
        tries = int(cfg.get("maxauthtries"))
    except ValueError:
        return
    if tries <= 4:
        yield passed("MaxAuthTries is %d" % tries)
        return
    yield failed(Severity.LOW, "MaxAuthTries is %d (allows more guesses per connection)" % tries,
                 recommendation="Set 'MaxAuthTries 4'.", details=_no_fix_note(cfg),
                 fix=_fix(ctx, cfg, {"MaxAuthTries": "4"}, "Limit authentication attempts to 4", risky=False))
