"""File permission checks."""

from __future__ import annotations

import os
import stat
from typing import Iterator, List, Tuple

from ..core import Context, FileChange, Finding, Fix, Severity, check, failed, passed

# (path or glob, forbidden permission bits, severity)
SENSITIVE_FILES: List[Tuple[str, int, Severity]] = [
    ("/etc/passwd", 0o022, Severity.HIGH),
    ("/etc/group", 0o022, Severity.HIGH),
    ("/etc/shadow", 0o037, Severity.CRITICAL),
    ("/etc/gshadow", 0o037, Severity.CRITICAL),
    ("/etc/sudoers", 0o027, Severity.HIGH),
    ("/etc/ssh/sshd_config", 0o022, Severity.HIGH),
    ("/etc/ssh/ssh_host_*_key", 0o077, Severity.HIGH),
    ("/etc/crontab", 0o022, Severity.HIGH),
]

KNOWN_SETUID = {
    "passwd", "chfn", "chsh", "gpasswd", "newgrp", "su", "sudo", "mount", "umount", "pkexec",
    "fusermount", "fusermount3", "ssh-keysign", "dbus-daemon-launch-helper", "at", "crontab",
    "ssh-agent", "chage", "expiry", "wall", "write", "bsd-write", "unix_chkpwd", "pam_extrausers_chkpwd",
    "polkit-agent-helper-1", "snap-confine", "ntfs-3g", "Xorg.wrap", "mount.nfs", "mount.cifs",
    "newuidmap", "newgidmap", "dotlockfile", "uuidd", "ping", "traceroute6.iputils", "mlocate",
    "plocate", "locate", "chrome-sandbox", "dmcrypt-get-device", "utempter", "sg", "staprun",
    "lxc-user-nic", "exim4", "procmail", "screen", "mail-lock", "mail-unlock", "mail-touchlock",
}
SETUID_DIRS = ["/bin", "/sbin", "/usr", "/opt", "/tmp", "/var/tmp", "/dev/shm", "/home", "/srv"]
TEMP_DIRS = ("/tmp", "/var/tmp", "/dev/shm")


@check("FILE-001", "Permissions of sensitive files", "files")
def sensitive_files(ctx: Context) -> Iterator[Finding]:
    found_bad = False
    checked = 0
    for pattern, forbidden, sev in SENSITIVE_FILES:
        paths = ctx.glob(pattern) if "*" in pattern else [pattern]
        for path in paths:
            st = ctx.lstat(path)
            if st is None or not stat.S_ISREG(st.st_mode):
                continue
            checked += 1
            mode = stat.S_IMODE(st.st_mode)
            problems = []
            if st.st_uid != 0:
                problems.append("owned by uid %d instead of root" % st.st_uid)
            if mode & forbidden:
                problems.append("mode %04o (should not have %04o)" % (mode, mode & forbidden))
            if not problems:
                continue
            found_bad = True
            fix = None
            if mode & forbidden:
                new_mode = mode & ~forbidden
                fix = Fix(summary="chmod %04o %s" % (new_mode, path), changes=[FileChange(path, mode=new_mode)])
            yield failed(sev, "%s: %s" % (path, "; ".join(problems)), id="FILE-001:%s" % path, fix=fix,
                         recommendation="Restrict permissions; ownership must be root (chown root %s)." % path
                         if st.st_uid != 0 else "Remove the extra permission bits.")
    if not found_bad:
        yield passed("%d sensitive files have safe permissions" % checked)


@check("FILE-002", "World-writable files in /etc", "files")
def world_writable_etc(ctx: Context) -> Iterator[Finding]:
    bad = []
    base = ctx.path("/etc")
    for dirpath, dirnames, filenames in os.walk(base, followlinks=False):
        for name in dirnames + filenames:
            real = os.path.join(dirpath, name)
            try:
                st = os.lstat(real)
            except OSError:
                continue
            if stat.S_ISLNK(st.st_mode):
                continue
            if st.st_mode & 0o002 and not (stat.S_ISDIR(st.st_mode) and st.st_mode & stat.S_ISVTX):
                bad.append((ctx.logical(real), stat.S_IMODE(st.st_mode)))
    if not bad:
        yield passed("No world-writable files under /etc")
        return
    changes = [FileChange(p, mode=m & ~0o002) for p, m in bad]
    yield failed(Severity.HIGH, "%d world-writable path(s) under /etc (any user can modify them)" % len(bad),
                 details=["%04o %s" % (m, p) for p, m in bad],
                 recommendation="Remove the world-writable bit (chmod o-w).",
                 fix=Fix(summary="chmod o-w on %d path(s) under /etc" % len(bad), changes=changes))


def _walk_setuid(ctx: Context, top: str):
    stack = [ctx.path(top)]
    while stack:
        current = stack.pop()
        try:
            entries = list(os.scandir(current))
        except OSError:
            continue
        for entry in entries:
            try:
                st = entry.stat(follow_symlinks=False)
            except OSError:
                continue
            if stat.S_ISDIR(st.st_mode):
                stack.append(entry.path)
            elif stat.S_ISREG(st.st_mode) and st.st_mode & (stat.S_ISUID | stat.S_ISGID):
                yield ctx.logical(entry.path), st


@check("FILE-003", "Unexpected setuid/setgid programs", "files")
def setuid(ctx: Context) -> Iterator[Finding]:
    known, unknown, in_temp = 0, [], []
    for top in SETUID_DIRS:
        if not ctx.isdir(top) or (top != "/" and os.path.islink(ctx.path(top))):
            continue
        for path, st in _walk_setuid(ctx, top):
            kind = "setuid" if st.st_mode & stat.S_ISUID else "setgid"
            if path.startswith(tuple(d + "/" for d in TEMP_DIRS)):
                in_temp.append("%s %s" % (kind, path))
            elif os.path.basename(path) in KNOWN_SETUID:
                known += 1
            else:
                unknown.append("%s (uid %d) %s" % (kind, st.st_uid, path))
    if in_temp:
        yield failed(Severity.HIGH, "setuid/setgid programs in temporary directories", id="FILE-003:temp",
                     details=in_temp, recommendation="This is a common backdoor technique. Investigate and delete them.")
    if unknown:
        yield failed(Severity.MEDIUM, "%d setuid/setgid program(s) not on the known list" % len(unknown),
                     id="FILE-003:unknown", details=unknown,
                     recommendation="Check that each one comes from a package you trust (dpkg -S <path>); "
                                    "remove the bit from anything you don't need (chmod u-s,g-s <path>).")
    if not in_temp and not unknown:
        yield passed("%d setuid/setgid programs found, all on the known list" % known)


@check("FILE-004", "Sticky bit on temporary directories", "files")
def sticky_tmp(ctx: Context) -> Iterator[Finding]:
    ok = True
    for path in TEMP_DIRS:
        st = ctx.lstat(path)
        if st is None or not stat.S_ISDIR(st.st_mode):
            continue
        mode = stat.S_IMODE(st.st_mode)
        if mode & 0o002 and not mode & stat.S_ISVTX:
            ok = False
            yield failed(Severity.HIGH, "%s is world-writable without the sticky bit" % path, id="FILE-004:%s" % path,
                         recommendation="Without it, any user can delete or replace other users' files (chmod +t).",
                         fix=Fix(summary="chmod +t %s" % path, changes=[FileChange(path, mode=mode | stat.S_ISVTX)]))
    if ok:
        yield passed("Temporary directories have the sticky bit")
