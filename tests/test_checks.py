import os

from conftest import write

from hardenix.checks.history import scan_line
from hardenix.checks.ssh import load_sshd
from hardenix.core import Context, Severity, Status
from hardenix.runner import run_checks


def by_id(findings, prefix):
    return [f for f in findings if f.id.startswith(prefix)]


def test_sshd_first_value_wins_and_match_blocks_ignored(ctx, fakeroot):
    write(fakeroot, "/etc/ssh/sshd_config.d/10-a.conf",
          "PermitRootLogin no\nMatch User bob\n  PermitRootLogin yes\n")
    write(fakeroot, "/etc/ssh/sshd_config.d/20-b.conf", "PermitRootLogin=yes\n")
    cfg = load_sshd(ctx)
    assert cfg.includes_dropin
    assert cfg.get("permitrootlogin") == "no"
    assert cfg.get("passwordauthentication") == "yes"


def test_ssh_findings_and_safe_fix_offer(ctx):
    findings = run_checks(ctx, ["ssh"])
    pw = by_id(findings, "SSH-002")[0]
    assert pw.status == Status.FAIL and pw.fix is not None and pw.fix.risky
    root = by_id(findings, "SSH-001")[0]  # default prohibit-password -> LOW, alice is sudo + has a key
    assert root.status == Status.FAIL and root.severity == Severity.LOW and root.fix is not None


def test_no_ssh_lockout_fix_without_key(fakeroot):
    os.remove(os.path.join(str(fakeroot), "home/alice/.ssh/authorized_keys"))
    ctx = Context(root=str(fakeroot), euid=0, invoking_user="alice")
    findings = run_checks(ctx, ["SSH-001", "SSH-002"])
    assert all(f.fix is None for f in findings if f.status == Status.FAIL)


def test_uid0_and_empty_password(ctx, fakeroot):
    write(fakeroot, "/etc/passwd", open(os.path.join(str(fakeroot), "etc/passwd")).read()
          + "toor:x:0:0::/root:/bin/sh\n")
    write(fakeroot, "/etc/shadow", "root:!:1::::::\nalice::1::::::\n", 0o640)
    findings = run_checks(ctx, ["accounts"])
    assert by_id(findings, "ACC-001")[0].severity == Severity.CRITICAL
    assert by_id(findings, "ACC-002:alice")[0].status == Status.FAIL


def test_sensitive_file_permissions(ctx, fakeroot):
    os.chmod(os.path.join(str(fakeroot), "etc/shadow"), 0o644)
    findings = run_checks(ctx, ["FILE-001"])
    bad = by_id(findings, "FILE-001:/etc/shadow")
    assert bad and bad[0].fix.changes[0].mode == 0o640


def test_sysctl(ctx, fakeroot):
    write(fakeroot, "/proc/sys/kernel/randomize_va_space", "0\n")
    write(fakeroot, "/proc/sys/fs/protected_symlinks", "1\n")
    findings = run_checks(ctx, ["SYS-001"])
    assert by_id(findings, "SYS-001:kernel.randomize_va_space")[0].severity == Severity.HIGH
    assert not by_id(findings, "SYS-001:fs.protected_symlinks")


def test_exposed_redis_detected(ctx, fakeroot):
    header = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"
    write(fakeroot, "/proc/net/tcp", header +
          "   0: 00000000:18EB 00000000:0000 0A 00000000:00000000 00:00000000 00000000   0 0 111 1\n"
          "   1: 0100007F:0CEA 00000000:0000 0A 00000000:00000000 00:00000000 00000000   0 0 112 1\n")
    findings = run_checks(ctx, ["SVC-001"])
    assert by_id(findings, "SVC-001:6379")[0].severity == Severity.HIGH  # 0x18EB = 6379 on 0.0.0.0
    assert not by_id(findings, "SVC-001:3306")  # 0x0CEA = 3306 on 127.0.0.1 is fine


def test_history_secrets_masked(ctx, fakeroot):
    write(fakeroot, "/home/alice/.bash_history",
          "ls\nmysql -u root -pS3cretPass db\nmysql -u root -p db\nexport API_TOKEN=abc123xyz\n"
          "export TOKEN=$OTHER\n", 0o600)
    findings = run_checks(ctx, ["HIST-001"])
    f = by_id(findings, "HIST-001:/home/alice/.bash_history")[0]
    text = " ".join(f.details) + f.message
    assert "S3cretPass" not in text and "abc123xyz" not in text
    assert len(f.details) == 2  # "-p db" and "$OTHER" are not secrets
    assert f.fix.changes[0].sensitive


def test_scan_line_patterns():
    cases = {
        "sshpass -p hunter2 ssh host": "hunter2",
        "psql postgres://app:pw0rd@db/app": "pw0rd",
        "aws configure set aws_access_key_id AKIAABCDEFGHIJKLMNOP": "AKIAABCDEFGHIJKLMNOP",
        "redis-cli -a r3dis ping": "r3dis",
        "htpasswd -b -c /etc/nginx/.htpasswd admin s3cret": "s3cret",
        "CREATE USER 'x'@'%' IDENTIFIED BY 'dbpass';": "dbpass",
    }
    for line, secret in cases.items():
        names, masked = scan_line(line)
        assert names, line
        assert secret not in masked, line
    for clean in ("ls -la", "mysql -u root -p", "git push", "echo $PASSWORD", "ssh -p 2222 host",
                  # regexes, shell expansions and placeholders seen on real servers:
                  """KEY=$(grep -oP 'GEMINI_API_KEY = "\\K[^"]+' legacy/gen.py)""",
                  'sed -e "s|^JWT_SECRET=.*|JWT_SECRET=$JWT|" .env.example > .env',
                  "export API_TOKEN=$(cat /run/secrets/token)", "DB_PASSWORD=<password> ./run.sh",
                  "export SECRET_KEY=${SECRET_KEY:-x}", "PASSWORD=****"):
        assert scan_line(clean)[0] == [], clean


def test_history_symlink_ignored(ctx, fakeroot):
    write(fakeroot, "/etc/secretfile", "export DB_PASSWORD=topsecret\n", 0o600)
    os.symlink(os.path.join(str(fakeroot), "etc/secretfile"),
               os.path.join(str(fakeroot), "home/alice/.zsh_history"))
    findings = run_checks(ctx, ["HIST-001"])
    assert all(f.status == Status.PASS for f in findings)


def test_broken_check_does_not_stop_audit(ctx, monkeypatch):
    from hardenix import core

    def boom(_ctx):
        raise RuntimeError("bug")

    monkeypatch.setattr(core, "REGISTRY", core.REGISTRY + [core.Check("X-1", "x", "x", boom)])
    import hardenix.runner as runner
    monkeypatch.setattr(runner, "REGISTRY", core.REGISTRY)
    findings = runner.run_checks(ctx)
    assert by_id(findings, "X-1")[0].status == Status.ERROR
    assert len(findings) > 5


def test_suid_dumpable_2_ok_with_apport_pipe(ctx, fakeroot):
    write(fakeroot, "/proc/sys/fs/suid_dumpable", "2\n")
    write(fakeroot, "/proc/sys/kernel/core_pattern", "|/usr/share/apport/apport -p%p -s%s -c%c\n")
    assert not by_id(run_checks(ctx, ["SYS-001"]), "SYS-001:fs.suid_dumpable")


def test_suid_dumpable_2_flagged_with_plain_core_pattern(ctx, fakeroot):
    write(fakeroot, "/proc/sys/fs/suid_dumpable", "2\n")
    write(fakeroot, "/proc/sys/kernel/core_pattern", "core\n")
    assert by_id(run_checks(ctx, ["SYS-001"]), "SYS-001:fs.suid_dumpable")
