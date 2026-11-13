"""Kernel hardening parameters (read from /proc/sys, persisted in /etc/sysctl.d)."""

from __future__ import annotations

from typing import Iterator, List, Set, Tuple

from ..core import Context, FileChange, Finding, Fix, Severity, check, failed, info, passed

SYSCTL_FILE = "/etc/sysctl.d/99-hardenix.conf"
HEADER = "# Managed by hardenix. Undo with: hardenix rollback\n"

# key, accepted values, recommended value, severity, why
RULES: List[Tuple[str, Set[str], str, Severity, str]] = [
    ("kernel.randomize_va_space", {"2"}, "2", Severity.HIGH, "full ASLR makes memory exploits harder"),
    ("net.ipv4.tcp_syncookies", {"1"}, "1", Severity.MEDIUM, "protects against SYN flood attacks"),
    ("net.ipv4.conf.all.accept_redirects", {"0"}, "0", Severity.MEDIUM, "ignore ICMP redirects (traffic hijacking)"),
    ("net.ipv4.conf.default.accept_redirects", {"0"}, "0", Severity.MEDIUM, "same, for new interfaces"),
    ("net.ipv6.conf.all.accept_redirects", {"0"}, "0", Severity.MEDIUM, "ignore IPv6 ICMP redirects"),
    ("net.ipv4.conf.all.send_redirects", {"0"}, "0", Severity.LOW, "a server is not a router"),
    ("net.ipv4.conf.all.accept_source_route", {"0"}, "0", Severity.MEDIUM, "reject source-routed packets"),
    ("net.ipv4.conf.all.log_martians", {"1"}, "1", Severity.LOW, "log packets with impossible addresses"),
    ("net.ipv4.icmp_echo_ignore_broadcasts", {"1"}, "1", Severity.LOW, "no smurf amplification"),
    ("fs.protected_hardlinks", {"1"}, "1", Severity.MEDIUM, "blocks hardlink attacks in shared dirs"),
    ("fs.protected_symlinks", {"1"}, "1", Severity.MEDIUM, "blocks symlink attacks in /tmp"),
    ("fs.suid_dumpable", {"0"}, "0", Severity.LOW, "setuid programs must not dump core (may contain secrets)"),
    ("kernel.dmesg_restrict", {"1"}, "1", Severity.LOW, "kernel log is readable only by root"),
    ("kernel.kptr_restrict", {"1", "2"}, "1", Severity.LOW, "hide kernel addresses from users"),
    ("kernel.yama.ptrace_scope", {"1", "2", "3"}, "1", Severity.LOW, "processes cannot snoop on each other"),
]


def read_sysctl(ctx: Context, key: str):
    text = ctx.read_text("/proc/sys/" + key.replace(".", "/"))
    return None if text is None else text.strip()


@check("SYS-001", "Kernel hardening (sysctl)", "kernel")
def sysctl(ctx: Context) -> Iterator[Finding]:
    good = 0
    for key, accepted, recommended, sev, why in RULES:
        value = read_sysctl(ctx, key)
        if value is None:
            continue
        if value in accepted:
            good += 1
            continue
        yield failed(sev, "%s = %s (recommended %s: %s)" % (key, value, recommended, why), id="SYS-001:%s" % key,
                     recommendation="Set '%s = %s' in /etc/sysctl.d/." % (key, recommended),
                     fix=Fix(summary="Set %s = %s (now and at boot)" % (key, recommended),
                             changes=[FileChange(SYSCTL_FILE, set_keys={key: recommended}, kv_format="{key} = {value}",
                                                 header=HEADER, mode=0o644)],
                             commands=[["sysctl", "-q", "-p", SYSCTL_FILE]],
                             undo_commands=[["sysctl", "-q", "-w", "%s=%s" % (key, value)]]))
    if good:
        yield passed("%d kernel parameters are set securely" % good)
    forward = read_sysctl(ctx, "net.ipv4.ip_forward")
    if forward == "1":
        yield info("IP forwarding is enabled (normal with Docker/Kubernetes/VPN; otherwise disable it)",
                   id="SYS-001:ip_forward")
