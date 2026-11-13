"""Host firewall check."""

from __future__ import annotations

import re
from typing import Iterator, Optional

from ..core import Context, Finding, Fix, NeedsRoot, NotApplicable, Severity, check, failed, passed
from .services import exposed_listeners
from .ssh import load_sshd


def _nft_filters_input(ruleset: str) -> bool:
    for body in re.findall(r"chain\s+\S+\s*\{(.*?)^\s*\}\s*$", ruleset, re.S | re.M):
        if "hook input" not in body:
            continue
        if re.search(r"policy\s+drop", body):
            return True
        if any(re.search(r"\b(drop|reject)\b", l) for l in body.splitlines() if "hook input" not in l):
            return True
    return False


def _iptables_filters_input(rules: str) -> bool:
    return bool(re.search(r"^-P INPUT DROP", rules, re.M) or re.search(r"^-A INPUT .*-j (DROP|REJECT)", rules, re.M))


def _ssh_port(ctx: Context) -> str:
    try:
        return load_sshd(ctx).get("port") or "22"
    except (NeedsRoot, NotApplicable):
        return "22"


@check("FW-001", "Host firewall", "firewall")
def firewall(ctx: Context) -> Iterator[Finding]:
    conf = ctx.read_text("/etc/ufw/ufw.conf") or ""
    if re.search(r"^\s*ENABLED\s*=\s*yes", conf, re.M | re.I):
        yield passed("ufw is enabled")
        return
    if ctx.service_active("firewalld"):
        yield passed("firewalld is active")
        return
    if ctx.live and not ctx.is_root:
        raise NeedsRoot("the nftables/iptables ruleset")
    res = ctx.run(["nft", "list", "ruleset"])
    if res is not None and res.returncode == 0 and _nft_filters_input(res.stdout):
        yield passed("nftables filters incoming traffic")
        return
    res = ctx.run(["iptables", "-S", "INPUT"])
    if res is not None and res.returncode == 0 and _iptables_filters_input(res.stdout):
        yield passed("iptables filters incoming traffic")
        return

    port = _ssh_port(ctx)
    others = sorted({p for _, p, _ in exposed_listeners(ctx) if str(p) != port})
    details = []
    if ctx.has_package("docker-ce") or ctx.has_package("docker.io"):
        details.append("Docker is installed: ports published by containers bypass ufw "
                       "(Docker edits iptables directly). Bind them to 127.0.0.1 where possible.")
    fix: Optional[Fix] = None
    if ctx.has_package("ufw"):
        warnings = ["Your cloud provider may also have a firewall (security group); this is in addition to it."]
        if others:
            warnings.insert(0, "These ports are listening now and will be BLOCKED after enabling ufw: %s. "
                               "Allow the ones you need first, e.g. 'sudo ufw allow 443/tcp'."
                            % ", ".join(map(str, others)))
        fix = Fix(summary="Allow SSH (port %s/tcp) in ufw, then enable ufw (deny all other incoming)" % port,
                  commands=[["ufw", "allow", "%s/tcp" % port], ["ufw", "--force", "enable"]],
                  undo_commands=[["ufw", "disable"]], warnings=warnings, risky=True)
    yield failed(Severity.HIGH, "No active host firewall detected", details=details, fix=fix,
                 recommendation="sudo apt install ufw && sudo ufw allow %s/tcp && sudo ufw enable" % port)
