# hardenix

**Offline security audit and safe, reversible hardening for Debian and Ubuntu servers.**

Most servers are set up by people who are good at shipping software, not at Linux security.
`hardenix` checks the things that are most often left open: SSH settings, accounts,
file permissions, the firewall, automatic updates, kernel settings, exposed databases,
and passwords or tokens left behind in shell history. It explains each problem in plain
language, and if you want, it fixes the problem for you: it shows exactly what will change, asks
first, keeps a backup, and can undo everything.

```
$ hardenix audit
hardenix 0.1.0 - security audit of web-01

== SSH ==  (2 passed)
  [HIGH]     SSH-001   Root can log in over SSH with a password
      -> Set 'PermitRootLogin no' and log in as a regular user who uses sudo.
      fix available: hardenix fix --only SSH-001
  [MEDIUM]   SSH-002   SSH accepts password logins (PasswordAuthentication yes)
...
== HISTORY ==
  [HIGH]     HIST-001  3 line(s) with secrets in /home/alice/.bash_history
      | line 2 [mysql -p<password>]: mysql -u root -p**** mydb
      | line 3 [GitHub token, credentials in URL]: git clone https://alice:****@github.com/acme/app.git
      | line 4 [secret in variable]: export DB_PASSWORD=****
```

## Install

```bash
sudo apt install pipx
pipx install hardenix
```

(On current Debian/Ubuntu releases, a plain `sudo pip install` is blocked by the system on purpose; `pipx`
installs the tool into its own isolated environment. `pip install hardenix` inside a virtualenv also works.)

Requirements: Python 3.9+, Debian 11+ or Ubuntu 22.04+. **No other dependencies.**

## Usage

```bash
hardenix audit              # read-only check; offers to re-run with sudo for a complete audit
hardenix audit --json       # machine-readable output (exit code 1 if something failed)
hardenix fix --dry-run      # show every change that would be made, change nothing
hardenix fix                # go through the fixes one by one; nothing happens without your "y"
hardenix fix --only SSH-002 # fix a single finding
hardenix rollback           # undo the last fix session
hardenix rollback --list
hardenix list               # list all checks
```

When something needs root, hardenix asks whether to re-run itself with `sudo` (or pass `--sudo`).
Use `hardenix ... --sudo` rather than `sudo hardenix ...`: `sudo` does not see commands installed by pipx.
**The password prompt comes from `sudo`, not from hardenix; hardenix never sees your password.**

## What it checks

| ID | Check | Auto-fix |
|---|---|---|
| SSH-001 | Root login over SSH | yes, only if you have a sudo user with an SSH key |
| SSH-002 | Password logins over SSH | yes, only if the user running hardenix has an SSH key |
| SSH-003/004/005 | Empty passwords, X11 forwarding, MaxAuthTries | yes |
| ACC-001 | Extra UID 0 (root) accounts | no (needs a human decision) |
| ACC-002 | Accounts with an empty password | yes (locks the account) |
| ACC-003 | Passwordless sudo rules | no |
| ACC-004 | Accounts with a login shell | (info) |
| FILE-001 | Permissions of /etc/shadow, sudoers, SSH host keys, ... | yes |
| FILE-002 | World-writable files in /etc | yes |
| FILE-003 | Unknown setuid/setgid programs (and any in /tmp) | no |
| FILE-004 | Sticky bit on /tmp, /var/tmp, /dev/shm | yes |
| SVC-001 | Databases/admin services listening on public interfaces | no |
| SVC-002 | fail2ban | no |
| FW-001 | No active firewall | yes (ufw; allows your SSH port first) |
| UPD-001 | Automatic security updates | yes, if unattended-upgrades is installed |
| UPD-002 | Reboot pending after updates | no |
| SYS-001 | 15 kernel hardening settings (sysctl) | yes |
| HIST-001 | Passwords, tokens and keys left in shell/REPL history | yes (removes the lines) |
| HIST-002 | History files readable by other users | yes |

## Designed to be safe, even if something goes wrong

A tool that runs as root on your servers is an attractive target. hardenix is built so that
the damage is limited even in bad scenarios:

* **No network access, ever.** hardenix does not import any networking module, has no telemetry and no
  self-update. A test in CI fails if anyone adds one.
* **No third-party dependencies.** Only the Python standard library, so a compromised dependency cannot
  affect it. CI fails if a dependency is added.
* **No shell.** Commands run without a shell, with a fixed `PATH` (`/usr/sbin:/usr/bin:/sbin:/bin`) and an
  empty environment. `eval`, `exec`, `shell=True` and `os.system` are banned by tests.
* **Audit is read-only.** Only `hardenix fix` changes anything, and it shows a diff and asks before each change.
* **Lock-out protection.** SSH fixes are offered only when you can still log in afterwards, are validated
  with `sshd -t` (and reverted automatically if that fails), and are never applied by `--yes` alone. The
  firewall fix opens your SSH port before turning the firewall on.
* **Backups and rollback.** Every changed file is backed up to `/var/lib/hardenix/backups` (root-only, mode
  0700) and `hardenix rollback` restores them. Exception: lines containing secrets are removed without a
  backup, because a backup would keep the secret on disk.
* **Secrets are never printed.** Findings in history files are masked (`****`) in both text and JSON output.
* **Symlink-safe writes.** Files are written atomically and never through a symlink, so a user cannot trick
  hardenix (running as root) into overwriting another file.
* **Verifiable releases.** Releases are built and uploaded by GitHub Actions using PyPI Trusted Publishing
  (no stored tokens) and carry signed provenance. See [SECURITY.md](SECURITY.md) for how to verify.

## Limitations

hardenix covers the most common mistakes; it is not a full compliance scanner (see Lynis or OpenSCAP for
CIS-level audits). Removing a leaked password from history does not make it safe again: **change it**.
A cloud provider firewall (security group) is separate from the host firewall checked here.

## Development

```bash
python3 -m venv .venv && .venv/bin/pip install -e . pytest
.venv/bin/pytest
.venv/bin/hardenix audit --root /path/to/mounted/image   # audit a directory tree instead of /
```

Every check is a small function in `src/hardenix/checks/` that only reads; fixes are returned as data
and applied by `fixer.py`. New checks need tests that run against a fake filesystem (see `tests/conftest.py`).

## License

MIT
