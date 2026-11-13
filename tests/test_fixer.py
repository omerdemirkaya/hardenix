import os
import stat

import pytest
from conftest import write

from hardenix.core import FileChange, Fix, Status
from hardenix.fixer import BackupSession, FixError, apply_fix, apply_kv, list_sessions, plan, rollback
from hardenix.runner import run_checks


def apply_all(ctx, findings):
    session = BackupSession(ctx)
    virtual = {}
    for f in findings:
        planned = plan(ctx, f.fix, virtual)
        ok, msgs = apply_fix(ctx, f.fix, f.id, planned, session)
        assert ok, msgs
    return session


def test_apply_kv_replaces_case_insensitive():
    out = apply_kv("# hdr\npermitrootlogin yes\nPermitRootLogin yes\n", {"PermitRootLogin": "no"}, "{key} {value}", "")
    assert out == "# hdr\nPermitRootLogin no\n"


def test_ssh_fix_then_rollback(ctx, fakeroot):
    fixes = [f for f in run_checks(ctx, ["ssh"]) if f.status == Status.FAIL and f.fix]
    apply_all(ctx, fixes)
    dropin = os.path.join(str(fakeroot), "etc/ssh/sshd_config.d/00-hardenix.conf")
    content = open(dropin).read()
    assert "PasswordAuthentication no" in content and "PermitRootLogin no" in content
    # A fresh audit (new context, no cache) now passes.
    from hardenix.core import Context
    again = run_checks(Context(root=str(fakeroot), euid=0, invoking_user="alice"), ["ssh"])
    assert all(f.status == Status.PASS for f in again)

    (name, manifest), = list_sessions(ctx)
    rollback(ctx, name, manifest)
    assert not os.path.exists(dropin)


def test_permission_fix_and_rollback(ctx, fakeroot):
    shadow = os.path.join(str(fakeroot), "etc/shadow")
    os.chmod(shadow, 0o644)
    fixes = [f for f in run_checks(ctx, ["FILE-001"]) if f.fix]
    apply_all(ctx, fixes)
    assert stat.S_IMODE(os.stat(shadow).st_mode) == 0o640
    (name, manifest), = list_sessions(ctx)
    rollback(ctx, name, manifest)
    assert stat.S_IMODE(os.stat(shadow).st_mode) == 0o644


def test_history_fix_keeps_no_copy_of_secrets(ctx, fakeroot):
    hist = write(fakeroot, "/home/alice/.bash_history", "ls\nexport DB_PASSWORD=topsecret\npwd\n", 0o644)
    fixes = [f for f in run_checks(ctx, ["history"]) if f.status == Status.FAIL and f.fix]
    # Apply the chmod first: a permission-only change must not back up content either.
    fixes.sort(key=lambda f: not f.id.startswith("HIST-002"))
    apply_all(ctx, fixes)
    assert open(hist).read() == "ls\npwd\n"
    assert stat.S_IMODE(os.stat(hist).st_mode) == 0o600
    for dirpath, _, files in os.walk(os.path.join(str(fakeroot), "var/lib/hardenix")):
        for name in files:
            assert b"topsecret" not in open(os.path.join(dirpath, name), "rb").read()


def test_refuses_to_write_through_symlink(ctx, fakeroot):
    target = write(fakeroot, "/etc/important", "keep me\n")
    os.symlink(target, os.path.join(str(fakeroot), "etc/sysctl.d/99-hardenix.conf"))
    fix = Fix("x", changes=[FileChange("/etc/sysctl.d/99-hardenix.conf", set_keys={"a": "1"})])
    with pytest.raises(FixError):
        plan(ctx, fix, {})
    assert open(target).read() == "keep me\n"


def test_failed_change_is_reverted(ctx, fakeroot):
    a = write(fakeroot, "/etc/sysctl.d/a.conf", "old\n")
    fix = Fix("x", changes=[FileChange("/etc/sysctl.d/a.conf", content="new\n"),
                            FileChange("/etc/missing-dir/b.conf", content="x\n")])
    session = BackupSession(ctx)
    ok, msgs = apply_fix(ctx, fix, "T", plan(ctx, fix, {}), session)
    assert not ok and "reverted" in msgs[-1]
    assert open(a).read() == "old\n"
    assert session.manifest["entries"] == []


def test_backups_are_private(ctx, fakeroot):
    os.chmod(os.path.join(str(fakeroot), "etc/shadow"), 0o644)
    apply_all(ctx, [f for f in run_checks(ctx, ["FILE-001"]) if f.fix])
    root = os.path.join(str(fakeroot), "var/lib/hardenix")
    for dirpath, dirs, files in os.walk(root):
        assert stat.S_IMODE(os.stat(dirpath).st_mode) == 0o700
        for name in files:
            assert stat.S_IMODE(os.stat(os.path.join(dirpath, name)).st_mode) == 0o600
