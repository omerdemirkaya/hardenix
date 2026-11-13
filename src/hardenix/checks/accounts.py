"""User account checks."""

from __future__ import annotations

from typing import Iterator, List

from ..core import Context, Finding, Fix, NeedsRoot, Severity, check, failed, info, passed

NOLOGIN_SHELLS = ("/usr/sbin/nologin", "/sbin/nologin", "/bin/false", "/usr/bin/false", "")


@check("ACC-001", "Extra accounts with UID 0", "accounts")
def uid_zero(ctx: Context) -> Iterator[Finding]:
    extra = [e.name for e in ctx.passwd() if e.uid == 0 and e.name != "root"]
    if not extra:
        yield passed("Only 'root' has UID 0")
        return
    yield failed(Severity.CRITICAL, "Accounts other than root have UID 0: %s" % ", ".join(extra),
                 recommendation="Every UID 0 account is a full root account. Remove them or give them a "
                                "normal UID unless you created them on purpose.")


@check("ACC-002", "Accounts without a password", "accounts")
def empty_passwords(ctx: Context) -> Iterator[Finding]:
    empty = [e.name for e in ctx.passwd() if e.password_field == ""]
    shadow = ctx.read_text("/etc/shadow")  # raises NeedsRoot for normal users
    for line in (shadow or "").splitlines():
        parts = line.split(":")
        if len(parts) >= 2 and parts[1] == "" and parts[0] not in empty:
            empty.append(parts[0])
    if not empty:
        yield passed("No account has an empty password")
        return
    for name in empty:
        yield failed(
            Severity.CRITICAL, "Account '%s' has an empty password (anyone can log in as it)" % name,
            id="ACC-002:%s" % name,
            recommendation="Set a password (passwd %s) or lock the account (passwd -l %s)." % (name, name),
            fix=Fix(summary="Lock account '%s' (passwd -l)" % name, commands=[["passwd", "-l", name]],
                    warnings=["Rollback cannot restore an empty password. Set a password later with: sudo passwd %s"
                              % name]),
        )


def _sudoers_files(ctx: Context) -> List[str]:
    files = ["/etc/sudoers"]
    for name in ctx.listdir("/etc/sudoers.d"):
        if "." in name or name.endswith("~"):
            continue  # sudo ignores these names
        files.append("/etc/sudoers.d/" + name)
    return files


@check("ACC-003", "Passwordless sudo", "accounts")
def nopasswd(ctx: Context) -> Iterator[Finding]:
    hits = []
    for path in _sudoers_files(ctx):
        text = ctx.read_text(path)
        for line in (text or "").splitlines():
            stripped = line.strip()
            if stripped.startswith("#") or "NOPASSWD" not in stripped:
                continue
            hits.append((path, stripped))
    if not hits:
        yield passed("No NOPASSWD rules in sudoers")
        return
    all_cmds = any(l.rstrip().endswith("ALL") for _, l in hits)
    yield failed(
        Severity.MEDIUM if all_cmds else Severity.LOW,
        "%d sudo rule(s) allow running commands as root without a password" % len(hits),
        details=["%s: %s" % h for h in hits],
        recommendation="If an attacker gets that user's shell (e.g. a stolen SSH key) they get root instantly. "
                       "Prefer sudo with a password. Cloud images often add this for the default user. "
                       "Edit with 'sudo visudo -f <file>'.",
    )


@check("ACC-004", "Accounts that can log in", "accounts")
def login_accounts(ctx: Context) -> Iterator[Finding]:
    users = [e for e in ctx.passwd() if e.shell not in NOLOGIN_SHELLS and (e.uid == 0 or e.uid >= 1000)
             and e.uid != 65534]
    yield info("%d account(s) have a login shell: %s" % (len(users), ", ".join(u.name for u in users)),
               recommendation="Remove or lock accounts nobody uses.")
