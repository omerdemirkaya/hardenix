"""Runs registered checks and normalises their findings."""

from __future__ import annotations

from typing import Iterable, List, Optional, Sequence

from .core import REGISTRY, Context, Finding, NeedsRoot, NotApplicable, Status, passed


def load_checks() -> None:
    # Importing the package registers every check via the @check decorator.
    from . import checks  # noqa: F401


def _matches(selectors: Sequence[str], check_id: str, category: str, finding_id: str = "") -> bool:
    for sel in selectors:
        s = sel.strip().upper()
        if not s:
            continue
        if s in (check_id.upper(), finding_id.upper(), category.upper()):
            return True
        if check_id.upper().startswith(s + "-"):
            return True
    return False


def select_findings(findings: Iterable[Finding], selectors: Optional[Sequence[str]]) -> List[Finding]:
    if not selectors:
        return list(findings)
    return [f for f in findings if _matches(selectors, f.check_id, f.category, f.id)]


def run_checks(ctx: Context, selectors: Optional[Sequence[str]] = None) -> List[Finding]:
    load_checks()
    results: List[Finding] = []
    for chk in REGISTRY:
        if selectors and not _matches(selectors, chk.id, chk.category):
            # A selector may name a specific finding id like "SYS-001:kernel.x"; keep the check then.
            if not any(sel.upper().startswith(chk.id.upper() + ":") for sel in selectors):
                continue
        try:
            findings = list(chk.func(ctx)) or [passed("OK")]
        except NeedsRoot as exc:
            findings = [Finding(Status.SKIP, "needs root to read %s (run with sudo)" % exc)]
        except NotApplicable as exc:
            findings = [Finding(Status.NA, "not applicable: %s" % exc)]
        except Exception as exc:  # a broken check must never stop the audit
            findings = [Finding(Status.ERROR, "check failed: %s: %s" % (type(exc).__name__, exc))]
        for f in findings:
            f.check_id = chk.id
            f.category = chk.category
            f.title = chk.title
            if not f.id:
                f.id = chk.id
        results.extend(findings)
    if selectors:
        results = [
            f for f in results
            if _matches(selectors, f.check_id, f.category, f.id)
            or not any(":" in s for s in selectors)
        ]
    return results
