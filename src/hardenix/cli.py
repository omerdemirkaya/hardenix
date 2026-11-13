"""Command line interface."""

from __future__ import annotations

import argparse
import os
import shutil
import sys
from typing import List, Optional

from . import __version__
from .core import SAFE_PATH, Context, Severity, Status
from .fixer import (FixError, BackupSession, apply_fix, commit_virtual, describe, list_sessions, plan,
                    rollback)
from .report import render_json, render_text
from .runner import REGISTRY, load_checks, run_checks, select_findings

EXIT_OK, EXIT_FINDINGS, EXIT_ERROR = 0, 1, 2


def _hostname(ctx: Context) -> str:
    if ctx.live:
        return os.uname().nodename
    return (ctx.read_text("/etc/hostname") or ctx.root).strip()


def _discard_typeahead() -> None:
    """Throw away input typed or pasted before the question was shown, so a pasted
    next command is never taken as the answer."""
    try:
        import termios

        termios.tcflush(sys.stdin.fileno(), termios.TCIFLUSH)
    except (ImportError, OSError, ValueError):
        pass


def _ask(question: str, default: bool = False) -> bool:
    suffix = " [Y/n] " if default else " [y/N] "
    _discard_typeahead()
    while True:
        try:
            answer = input(question + suffix).strip().lower()
        except EOFError:
            return False
        if not answer:
            return default
        if answer in ("y", "yes"):
            return True
        if answer in ("n", "no"):
            return False
        print("Please answer 'y' or 'n'.")


def _interactive() -> bool:
    return sys.stdin.isatty() and sys.stdout.isatty()


def _reexec_with_sudo(argv: List[str]) -> int:
    """Re-run this exact command under sudo. sudo itself asks for the password;
    hardenix never sees or stores it."""
    sudo = shutil.which("sudo", path=SAFE_PATH)
    if sudo is None:
        print("sudo is not installed; run this command as root.", file=sys.stderr)
        return EXIT_ERROR
    # -I: isolated mode, ignores PYTHON* environment variables and the user site-packages.
    cmd = [sudo, "--", sys.executable, "-I", "-m", "hardenix"] + argv + ["--no-sudo"]
    sys.stdout.flush()
    os.execv(sudo, cmd)
    return EXIT_ERROR  # pragma: no cover


def _elevate_if_needed(args: argparse.Namespace, ctx: Context, reason: str, required: bool) -> Optional[int]:
    """Return an exit code if we re-executed or must stop, None to continue as is."""
    if not ctx.live or ctx.is_root or args.no_sudo:
        if required and ctx.live and not ctx.is_root:
            print("%s needs root. Run: hardenix %s --sudo" % (reason, " ".join(_user_argv())), file=sys.stderr)
            return EXIT_ERROR
        return None
    if args.sudo or (_interactive() and _ask("%s needs root. Re-run with sudo (sudo will ask for your password)?"
                                              % reason, default=True)):
        return _reexec_with_sudo(_user_argv())
    if required:
        print("%s needs root. Aborting." % reason, file=sys.stderr)
        return EXIT_ERROR
    return None


def _user_argv() -> List[str]:
    return [a for a in sys.argv[1:] if a not in ("--sudo", "--no-sudo")]


def _make_ctx(args: argparse.Namespace) -> Context:
    return Context(root=args.root)


def _selectors(args: argparse.Namespace) -> Optional[List[str]]:
    if not getattr(args, "only", None):
        return None
    return [s for part in args.only for s in part.split(",") if s.strip()]


# --------------------------------------------------------------------------- commands
def cmd_audit(args: argparse.Namespace) -> int:
    ctx = _make_ctx(args)
    if not args.json:
        rc = _elevate_if_needed(args, ctx, "A complete audit", required=False)
        if rc is not None:
            return rc
    findings = run_checks(ctx, _selectors(args))
    if args.json:
        print(render_json(findings, _hostname(ctx)))
    else:
        render_text(findings, _hostname(ctx), sys.stdout, verbose=args.verbose)
    threshold = Severity.parse(args.fail_on)
    if any(f.status == Status.FAIL and f.severity >= threshold for f in findings):
        return EXIT_FINDINGS
    return EXIT_OK


def cmd_fix(args: argparse.Namespace) -> int:
    ctx = _make_ctx(args)
    rc = _elevate_if_needed(args, ctx, "A complete preview" if args.dry_run else "Applying fixes",
                            required=not args.dry_run)
    if rc is not None:
        return rc
    if not args.dry_run and not args.yes and not _interactive():
        print("No terminal to ask for confirmation. Use --dry-run to preview or --yes to apply.", file=sys.stderr)
        return EXIT_ERROR

    findings = [f for f in run_checks(ctx, _selectors(args)) if f.status == Status.FAIL and f.fix]
    findings = select_findings(findings, _selectors(args))
    findings.sort(key=lambda f: -int(f.severity))
    if not findings:
        print("Nothing to fix.")
        return EXIT_OK

    session = BackupSession(ctx)
    virtual: dict = {}
    applied = failed = skipped = 0
    print("%d fixable issue(s)%s.\n" % (len(findings), " (dry run: nothing will be changed)" if args.dry_run else ""))
    for f in findings:
        fix = f.fix
        assert fix is not None
        print("=" * 72)
        print("[%s] %s  %s" % (f.severity.name, f.id, f.message))
        print("Fix: %s" % fix.summary)
        try:
            planned = plan(ctx, fix, virtual)
        except (FixError, OSError) as exc:
            print("  cannot plan this fix: %s" % exc)
            failed += 1
            continue
        for pc in planned:
            for line in describe(pc):
                print(line)
        if fix.validate:
            print("  then validate with: %s" % " ".join(fix.validate))
        for cmd in fix.commands:
            print("  then run: %s" % " ".join(cmd))
        for w in fix.warnings:
            print("  ! %s" % w)
        if args.dry_run:
            commit_virtual(virtual, planned)
            continue
        if fix.risky and args.yes and not args.allow_risky:
            print("  skipped: this fix can lock you out; apply it interactively or add --allow-risky")
            skipped += 1
            continue
        if not args.yes and not _ask("Apply this fix?"):
            skipped += 1
            continue
        ok, messages = apply_fix(ctx, fix, f.id, planned, session)
        for m in messages:
            print("  " + m)
        if ok:
            commit_virtual(virtual, planned)
            applied += 1
            print("  done.")
        else:
            failed += 1
    print("=" * 72)
    if args.dry_run:
        print("Dry run finished. Apply with: hardenix fix")
        return EXIT_OK
    print("Applied %d, skipped %d, failed %d." % (applied, skipped, failed))
    if session.dir:
        print("Backups: %s\nUndo everything from this run with: hardenix rollback" % ctx.logical(session.dir))
    return EXIT_OK if failed == 0 else EXIT_FINDINGS


def cmd_rollback(args: argparse.Namespace) -> int:
    ctx = _make_ctx(args)
    rc = _elevate_if_needed(args, ctx, "Rollback", required=not args.list)
    if rc is not None:
        return rc
    sessions = list_sessions(ctx)
    if args.list:
        if not sessions:
            print("No backup sessions.")
        for name, m in sessions:
            state = "rolled back %s" % m["rolled_back"] if m.get("rolled_back") else "active"
            print("%s  %d change(s)  %s" % (name, len(m.get("entries", [])), state))
        return EXIT_OK
    if args.session:
        chosen = [(n, m) for n, m in sessions if n == args.session]
    else:
        chosen = [(n, m) for n, m in sessions if not m.get("rolled_back")][-1:]
    if not chosen:
        print("Nothing to roll back.")
        return EXIT_OK
    name, manifest = chosen[0]
    print("Session %s:" % name)
    for e in manifest["entries"]:
        print("  %s  (%s)" % (e["path"], e["fix"]))
    for c in sorted({tuple(c) for cmds in manifest.get("undo_commands", []) for c in cmds}):
        print("  then run: %s" % " ".join(c))
    if not args.yes and not (_interactive() and _ask("Restore these files?")):
        print("Aborted.")
        return EXIT_ERROR
    for m in rollback(ctx, name, manifest):
        print("  " + m)
    return EXIT_OK


def cmd_list(args: argparse.Namespace) -> int:
    load_checks()
    for chk in REGISTRY:
        print("%-9s %-10s %s" % (chk.id, chk.category, chk.title))
    return EXIT_OK


# --------------------------------------------------------------------------- parser
def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="hardenix",
        description="Offline security audit and safe hardening for Debian/Ubuntu servers. "
                    "hardenix never connects to the network.")
    p.add_argument("--version", action="version", version="hardenix %s" % __version__)
    sub = p.add_subparsers(dest="command")

    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--root", default="/", help=argparse.SUPPRESS)  # audit a mounted image / tests
    g = common.add_mutually_exclusive_group()
    g.add_argument("--sudo", action="store_true", help="re-run with sudo without asking")
    g.add_argument("--no-sudo", action="store_true", help="never offer to re-run with sudo")

    a = sub.add_parser("audit", parents=[common], help="check the system (read-only)")
    a.add_argument("--json", action="store_true", help="machine-readable output")
    a.add_argument("-v", "--verbose", action="store_true", help="also show passed checks")
    a.add_argument("--only", action="append", metavar="IDS", help="comma-separated check ids or categories")
    a.add_argument("--fail-on", default="low", choices=[s.label for s in Severity],
                   help="exit with code 1 if a finding of at least this severity fails (default: low)")
    a.set_defaults(func=cmd_audit)

    f = sub.add_parser("fix", parents=[common], help="review and apply fixes (asks before every change)")
    f.add_argument("--dry-run", action="store_true", help="show what would change, change nothing")
    f.add_argument("--only", action="append", metavar="IDS", help="comma-separated check/finding ids")
    f.add_argument("-y", "--yes", action="store_true", help="apply without asking (skips risky fixes)")
    f.add_argument("--allow-risky", action="store_true", help="with --yes, also apply fixes that could lock you out")
    f.set_defaults(func=cmd_fix)

    r = sub.add_parser("rollback", parents=[common], help="undo the last fix session")
    r.add_argument("session", nargs="?", help="session name (default: latest)")
    r.add_argument("--list", action="store_true", help="list backup sessions")
    r.add_argument("-y", "--yes", action="store_true", help="do not ask for confirmation")
    r.set_defaults(func=cmd_rollback)

    lst = sub.add_parser("list", help="list all checks")
    lst.set_defaults(func=cmd_list, root="/")
    return p


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if not getattr(args, "func", None):
        parser.print_help()
        return EXIT_OK
    try:
        return args.func(args)
    except KeyboardInterrupt:
        print("\nInterrupted.", file=sys.stderr)
        return EXIT_ERROR
