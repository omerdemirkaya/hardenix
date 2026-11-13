# Security policy

## Reporting a vulnerability

Please do **not** open a public issue. Use GitHub's private vulnerability reporting
("Security" tab -> "Report a vulnerability") on this repository. You should get an answer within 7 days.

## Threat model

hardenix runs as root on production servers, so we assume someone may try to:

1. **Publish a malicious version** (stolen maintainer credentials).
   - Releases can only be uploaded by the `release.yml` workflow through PyPI Trusted Publishing.
     There is no API token that could be stolen. Maintainer accounts on PyPI and GitHub must use 2FA.
   - Publishing runs in a protected GitHub environment (`pypi`) that requires a maintainer's approval.
   - Every release carries signed provenance that ties each file to the exact commit and workflow run.
2. **Compromise a dependency.** hardenix has none at runtime. CI fails if one is added.
3. **Hide malicious behaviour in a pull request.** CI rejects networking imports, `eval`/`exec`,
   `shell=True`, `os.system` and use of `subprocess` outside `core.py`. Review every PR that touches
   `core.py`, `fixer.py`, `cli.py` or `.github/`.
4. **Trick hardenix into damaging the system** from a normal user account (e.g. symlinks in a home
   directory). Writes never follow symlinks, are atomic, and refuse directories that contain symlinks.

Installing hardenix with `pipx` as an admin user and running it with `--sudo` means root runs code
from that user's home directory. That is equivalent to the sudo rights the user already has, but
install it only for accounts that are trusted with root.

What hardenix cannot protect against: an attacker who already has root on the server, or a
compromised Python interpreter.

## Verifying a release

Download the file you are about to install and check where it came from:

```bash
pip download --no-deps hardenix==0.1.0 -d dl/

# Option 1: GitHub CLI
gh attestation verify dl/hardenix-0.1.0-py3-none-any.whl --repo omerdemirkaya/hardenix

# Option 2: PyPI attestations (PEP 740)
pipx run pypi-attestations verify pypi --repository https://github.com/omerdemirkaya/hardenix \
    pypi:hardenix-0.1.0-py3-none-any.whl
```

Then install from the verified file: `pipx install dl/hardenix-0.1.0-py3-none-any.whl`.

## Running safely

* Run `hardenix fix --dry-run` first and read the diff.
* Keep an existing SSH session open while applying SSH or firewall fixes, and test a new login.
* `hardenix rollback` restores files from `/var/lib/hardenix/backups`.
