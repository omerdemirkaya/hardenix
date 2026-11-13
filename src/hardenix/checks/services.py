"""Network-exposed services and brute-force protection.

Listening sockets are read from /proc/net/tcp{,6}; hardenix never opens a socket itself.
"""

from __future__ import annotations

import ipaddress
import os
import re
from typing import Dict, Iterator, List, Tuple

from ..core import Context, Finding, NotApplicable, Severity, check, failed, info, passed

RISKY_PORTS: Dict[int, Tuple[str, Severity]] = {
    2375: ("Docker API without TLS (gives root to anyone who can reach it)", Severity.CRITICAL),
    2379: ("etcd", Severity.HIGH),
    6379: ("Redis", Severity.HIGH),
    11211: ("Memcached", Severity.HIGH),
    27017: ("MongoDB", Severity.HIGH),
    9200: ("Elasticsearch", Severity.HIGH),
    5984: ("CouchDB", Severity.HIGH),
    10250: ("Kubelet API", Severity.HIGH),
    5900: ("VNC", Severity.HIGH),
    23: ("Telnet (unencrypted)", Severity.HIGH),
    3306: ("MySQL/MariaDB", Severity.MEDIUM),
    5432: ("PostgreSQL", Severity.MEDIUM),
    21: ("FTP (unencrypted)", Severity.MEDIUM),
    111: ("rpcbind", Severity.LOW),
}


def _decode(hex_addr: str, v6: bool) -> ipaddress._BaseAddress:  # type: ignore[name-defined]
    raw = bytes.fromhex(hex_addr)
    if not v6:
        return ipaddress.ip_address(raw[::-1])
    return ipaddress.ip_address(b"".join(raw[i:i + 4][::-1] for i in range(0, 16, 4)))


def _socket_owners(ctx: Context) -> Dict[str, str]:
    """Map socket inode -> process name. Needs root to see other users' processes."""
    owners: Dict[str, str] = {}
    if not (ctx.live and ctx.is_root):
        return owners
    for pid in os.listdir("/proc"):
        if not pid.isdigit():
            continue
        try:
            with open("/proc/%s/comm" % pid) as fh:
                comm = fh.read().strip()
            for fd in os.listdir("/proc/%s/fd" % pid):
                target = os.readlink("/proc/%s/fd/%s" % (pid, fd))
                m = re.match(r"socket:\[(\d+)\]", target)
                if m:
                    owners.setdefault(m.group(1), comm)
        except OSError:
            continue
    return owners


def exposed_listeners(ctx: Context) -> List[Tuple[str, int, str]]:
    """Return (address, port, inode) for TCP sockets listening on non-loopback addresses."""
    if "listeners" in ctx.cache:
        return ctx.cache["listeners"]  # type: ignore[return-value]
    result = []
    seen = set()
    for name, v6 in (("/proc/net/tcp", False), ("/proc/net/tcp6", True)):
        text = ctx.read_text(name) or ""
        for line in text.splitlines()[1:]:
            parts = line.split()
            if len(parts) < 10 or parts[3] != "0A":  # 0A = LISTEN
                continue
            addr_hex, port_hex = parts[1].split(":")
            try:
                addr = _decode(addr_hex, v6)
            except ValueError:
                continue
            mapped = getattr(addr, "ipv4_mapped", None)
            if addr.is_loopback or (mapped is not None and mapped.is_loopback):
                continue
            port = int(port_hex, 16)
            key = (str(addr), port)
            if key in seen:
                continue
            seen.add(key)
            result.append((str(addr), port, parts[9]))
    result.sort(key=lambda r: (r[1], r[0]))
    ctx.cache["listeners"] = result
    return result


@check("SVC-001", "Network-exposed services", "services")
def exposed(ctx: Context) -> Iterator[Finding]:
    listeners = exposed_listeners(ctx)
    owners = _socket_owners(ctx)
    if not listeners:
        yield passed("No TCP services listen on public interfaces")
        return
    for addr, port, inode in listeners:
        if port in RISKY_PORTS:
            name, sev = RISKY_PORTS[port]
            proc = owners.get(inode)
            yield failed(sev, "%s listens on %s:%d%s" % (name, addr, port, " (%s)" % proc if proc else ""),
                         id="SVC-001:%d" % port,
                         recommendation="Bind it to 127.0.0.1 in its config, or block the port in the firewall "
                                        "and allow only the hosts that need it.")
    yield info("Listening on network interfaces: " + ", ".join(
        "%s:%d%s" % (a, p, "/" + owners[i] if i in owners else "") for a, p, i in listeners),
        id="SVC-001:list", recommendation="Make sure every one of these is meant to be reachable.")


@check("SVC-002", "Brute-force protection (fail2ban)", "services")
def fail2ban(ctx: Context) -> Iterator[Finding]:
    if not ctx.has_package("openssh-server"):
        raise NotApplicable("openssh-server is not installed")
    if ctx.has_package("fail2ban"):
        active = ctx.service_active("fail2ban")
        if active is False:
            yield failed(Severity.LOW, "fail2ban is installed but not running",
                         recommendation="sudo systemctl enable --now fail2ban")
        else:
            yield passed("fail2ban is installed")
        return
    yield failed(Severity.LOW, "No brute-force protection for SSH (fail2ban not installed)",
                 recommendation="sudo apt install fail2ban  (its default config protects sshd)")
