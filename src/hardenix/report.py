"""Text and JSON reports."""

from __future__ import annotations

import json
import os
from collections import OrderedDict
from typing import Dict, List, TextIO

from . import __version__
from .core import Finding, Severity, Status

RESET = "\033[0m"
BOLD = "\033[1m"
DIM = "\033[2m"
GREEN = "\033[32m"
SEV_COLOR = {
    Severity.CRITICAL: "\033[1;35m",
    Severity.HIGH: "\033[1;31m",
    Severity.MEDIUM: "\033[33m",
    Severity.LOW: "\033[36m",
    Severity.INFO: "\033[37m",
}


def use_color(stream: TextIO) -> bool:
    return hasattr(stream, "isatty") and stream.isatty() and not os.environ.get("NO_COLOR")


def summarize(findings: List[Finding]) -> Dict[str, object]:
    by_sev: Dict[str, int] = OrderedDict((s.label, 0) for s in sorted(Severity, reverse=True))
    counts = {s.value: 0 for s in Status}
    for f in findings:
        counts[f.status.value] += 1
        if f.status == Status.FAIL:
            by_sev[f.severity.label] += 1
    fixable = sum(1 for f in findings if f.status == Status.FAIL and f.fix)
    return {"counts": counts, "failed_by_severity": by_sev, "fixable": fixable}


def render_json(findings: List[Finding], host: str) -> str:
    return json.dumps(
        {
            "tool": "hardenix",
            "version": __version__,
            "host": host,
            "summary": summarize(findings),
            "findings": [f.to_dict() for f in findings],
        },
        indent=2,
    )


def render_text(findings: List[Finding], host: str, stream: TextIO, verbose: bool = False) -> None:
    color = use_color(stream)

    def c(code: str, text: str) -> str:
        return code + text + RESET if color else text

    w = stream.write
    w(c(BOLD, "hardenix %s - security audit of %s" % (__version__, host)) + "\n")

    groups: "OrderedDict[str, List[Finding]]" = OrderedDict()
    for f in findings:
        groups.setdefault(f.category, []).append(f)

    for category, items in groups.items():
        shown = [f for f in items if verbose or f.status not in (Status.PASS, Status.NA)]
        if not verbose and items and all(f.status == Status.NA for f in items):
            shown = items[:1]
        n_pass = sum(1 for f in items if f.status == Status.PASS)
        w("\n" + c(BOLD, "== %s ==" % category.upper()))
        w(c(DIM, "  (%d passed)" % n_pass) + "\n" if n_pass and not verbose else "\n")
        for f in sorted(shown, key=lambda x: (x.status != Status.FAIL, -int(x.severity))):
            if f.status == Status.FAIL:
                tag = c(SEV_COLOR[f.severity], "%-10s" % ("[%s]" % f.severity.name))
            elif f.status == Status.PASS:
                tag = c(GREEN, "%-10s" % "[OK]")
            else:
                tag = c(DIM, "%-10s" % ("[%s]" % f.status.value))
            w("  %s %-9s %s\n" % (tag, f.check_id, f.message))
            for d in f.details[:15]:
                w(c(DIM, "      | ") + d + "\n")
            if len(f.details) > 15:
                w(c(DIM, "      | ... and %d more" % (len(f.details) - 15)) + "\n")
            if f.status == Status.FAIL and f.recommendation:
                w("      -> %s\n" % f.recommendation)
            if f.status == Status.FAIL and f.fix:
                w(c(DIM, "      fix available: hardenix fix --only %s" % f.id) + "\n")

    s = summarize(findings)
    counts = s["counts"]
    sev = ", ".join("%d %s" % (n, k) for k, n in s["failed_by_severity"].items() if n)  # type: ignore[union-attr]
    w("\n" + c(BOLD, "Summary: ") + "%d passed, %d failed%s, %d info, %d skipped, %d not applicable, %d errors\n" % (
        counts["pass"], counts["fail"], " (%s)" % sev if sev else "",  # type: ignore[index]
        counts["info"], counts["skip"], counts["n/a"], counts["error"]))  # type: ignore[index]
    if s["fixable"]:
        w("%d issue(s) can be fixed automatically. Review them with: hardenix fix --dry-run\n" % s["fixable"])
    if counts["skip"]:  # type: ignore[index]
        w(c(DIM, "Some checks were skipped; run as root (hardenix audit --sudo) for a complete audit.") + "\n")
