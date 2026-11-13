"""Security update checks (Debian/Ubuntu)."""

from __future__ import annotations

import re
from typing import Iterator, Optional

from ..core import Context, FileChange, Finding, Fix, Severity, check, failed, passed

AUTO_UPGRADES = "/etc/apt/apt.conf.d/99hardenix-auto-upgrades"


def _apt_periodic(ctx: Context, key: str) -> Optional[str]:
    """Last value of APT::Periodic::<key> across apt.conf.d (later files win)."""
    value = None
    files = ["/etc/apt/apt.conf"] + ["/etc/apt/apt.conf.d/" + n for n in ctx.listdir("/etc/apt/apt.conf.d")]
    pattern = re.compile(r'^\s*APT::Periodic::%s\s+"([^"]*)"\s*;' % re.escape(key), re.M)
    for path in files:
        for m in pattern.finditer(ctx.read_text(path) or ""):
            value = m.group(1)
    return value


@check("UPD-001", "Automatic security updates", "updates")
def unattended(ctx: Context) -> Iterator[Finding]:
    if not ctx.has_package("unattended-upgrades"):
        yield failed(Severity.MEDIUM, "unattended-upgrades is not installed (security patches are not applied "
                                      "automatically)",
                     recommendation="sudo apt install unattended-upgrades && sudo dpkg-reconfigure -plow "
                                    "unattended-upgrades")
        return
    lists = _apt_periodic(ctx, "Update-Package-Lists")
    upgrade = _apt_periodic(ctx, "Unattended-Upgrade")
    if upgrade not in (None, "0") and lists not in (None, "0"):
        yield passed("Automatic security updates are enabled")
        return
    yield failed(Severity.MEDIUM, "unattended-upgrades is installed but not enabled",
                 recommendation="sudo dpkg-reconfigure -plow unattended-upgrades",
                 fix=Fix(summary="Enable daily automatic security updates (%s)" % AUTO_UPGRADES,
                         changes=[FileChange(AUTO_UPGRADES, mode=0o644, content=(
                             "// Managed by hardenix. Undo with: hardenix rollback\n"
                             'APT::Periodic::Update-Package-Lists "1";\n'
                             'APT::Periodic::Unattended-Upgrade "1";\n'))]))


@check("UPD-002", "Pending reboot", "updates")
def reboot_required(ctx: Context) -> Iterator[Finding]:
    if not ctx.exists("/var/run/reboot-required") and not ctx.exists("/run/reboot-required"):
        yield passed("No reboot pending")
        return
    pkgs = (ctx.read_text("/var/run/reboot-required.pkgs") or ctx.read_text("/run/reboot-required.pkgs") or "")
    yield failed(Severity.LOW, "A reboot is required to finish installing updates",
                 details=sorted(set(pkgs.split())),
                 recommendation="Updated kernels/libraries are not in use until you reboot. Plan a reboot.")
