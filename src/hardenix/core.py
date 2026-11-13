"""Core data model: severities, findings, fixes, the check registry and the system context.

Design rules that every check must follow (enforced by tests where possible):

* Checks only *read*. They never write files or run commands that change state.
* Checks never use the network. hardenix does not import socket/urllib/http/ssl.
* External commands are run without a shell, with a fixed PATH and a minimal
  environment, so a hijacked $PATH or environment cannot inject a binary.
* Anything that would change the system is described as a :class:`Fix` and is
  only applied by :mod:`hardenix.fixer` after the user has seen it and agreed.
"""

from __future__ import annotations

import enum
import errno
import glob as _glob
import os
import shutil
import stat
import subprocess
from dataclasses import dataclass, field
from typing import Callable, Dict, Iterable, List, Optional, Tuple

# Only system directories. /usr/local is deliberately excluded: on some systems it is
# group-writable (e.g. group "staff"), which would let a non-root user plant binaries.
SAFE_PATH = "/usr/sbin:/usr/bin:/sbin:/bin"
SAFE_ENV = {"PATH": SAFE_PATH, "LC_ALL": "C", "LANG": "C"}
MAX_READ_BYTES = 64 * 1024 * 1024


class Severity(enum.IntEnum):
    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @classmethod
    def parse(cls, value: str) -> "Severity":
        return cls[value.strip().upper()]

    @property
    def label(self) -> str:
        return self.name.lower()


class Status(str, enum.Enum):
    PASS = "pass"
    FAIL = "fail"
    INFO = "info"
    SKIP = "skip"
    NA = "n/a"
    ERROR = "error"


class NeedsRoot(Exception):
    """Raised by a check when it cannot read something without root privileges."""


class NotApplicable(Exception):
    """Raised by a check when it does not apply to this system (e.g. sshd not installed)."""


@dataclass
class FileChange:
    """A single file modification proposed by a fix.

    Exactly one way of changing content may be used:
      * ``content``  - the full new content of the file;
      * ``set_keys`` - key/value lines to set in a (usually hardenix-managed) config file.
    ``mode`` may be combined with either, or used alone for a permission-only change.
    """

    path: str
    content: Optional[str] = None
    set_keys: Optional[Dict[str, str]] = None
    kv_format: str = "{key} {value}"
    header: str = ""
    mode: Optional[int] = None
    # Sensitive changes (e.g. removing leaked secrets) are never printed and never backed up,
    # because a backup would keep the secret on disk.
    sensitive: bool = False


@dataclass
class Fix:
    summary: str
    changes: List[FileChange] = field(default_factory=list)
    # Command that must succeed after the files are written; if it fails, files are restored.
    validate: Optional[List[str]] = None
    # Commands run after a successful validation (e.g. reload a service).
    commands: List[List[str]] = field(default_factory=list)
    # Commands that undo ``commands`` during rollback (file contents are restored separately).
    undo_commands: List[List[str]] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    # Risky fixes can lock you out if misused; they are never applied by --yes alone.
    risky: bool = False


@dataclass
class Finding:
    status: Status
    message: str
    severity: Severity = Severity.INFO
    details: List[str] = field(default_factory=list)
    recommendation: str = ""
    fix: Optional[Fix] = None
    id: str = ""
    check_id: str = ""
    category: str = ""
    title: str = ""

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "check": self.check_id,
            "category": self.category,
            "title": self.title,
            "status": self.status.value,
            "severity": self.severity.label,
            "message": self.message,
            "details": list(self.details),
            "recommendation": self.recommendation,
            "fixable": self.fix is not None,
            "fix_summary": self.fix.summary if self.fix else None,
        }


def passed(message: str, **kw) -> Finding:
    return Finding(Status.PASS, message, **kw)


def failed(severity: Severity, message: str, **kw) -> Finding:
    return Finding(Status.FAIL, message, severity=severity, **kw)


def info(message: str, **kw) -> Finding:
    return Finding(Status.INFO, message, **kw)


@dataclass
class Check:
    id: str
    title: str
    category: str
    func: Callable[["Context"], Iterable[Finding]]


REGISTRY: List[Check] = []


def check(check_id: str, title: str, category: str):
    """Decorator registering a check function."""

    def deco(func):
        REGISTRY.append(Check(check_id, title, category, func))
        return func

    return deco


@dataclass
class PasswdEntry:
    name: str
    uid: int
    gid: int
    home: str
    shell: str
    password_field: str


class Context:
    """Read-only view of the system being audited.

    ``root`` lets the whole tool run against a directory tree instead of ``/``
    (used by the tests, and for auditing a mounted disk image). When ``root`` is
    not ``/`` no external commands are executed.
    """

    def __init__(
        self,
        root: str = "/",
        run_commands: Optional[bool] = None,
        euid: Optional[int] = None,
        invoking_user: Optional[str] = None,
    ) -> None:
        self.root = os.path.abspath(root)
        self.live = self.root == "/"
        self.run_commands = self.live if run_commands is None else run_commands
        self.euid = os.geteuid() if euid is None else euid
        self._invoking_user = invoking_user
        self.cache: Dict[str, object] = {}

    # ----------------------------------------------------------------- paths
    @property
    def is_root(self) -> bool:
        return self.euid == 0

    def path(self, logical: str) -> str:
        if self.live:
            return logical
        return os.path.join(self.root, logical.lstrip("/"))

    def logical(self, real: str) -> str:
        if self.live:
            return real
        rel = os.path.relpath(real, self.root)
        return "/" + ("" if rel == "." else rel)

    # ------------------------------------------------------------ file reads
    def read_bytes(self, logical: str, nofollow: bool = False) -> Optional[bytes]:
        flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NONBLOCK", 0)
        if nofollow:
            flags |= os.O_NOFOLLOW
        try:
            fd = os.open(self.path(logical), flags)
        except (FileNotFoundError, NotADirectoryError):
            return None
        except PermissionError:
            raise NeedsRoot(logical)
        except OSError as exc:
            if exc.errno == errno.ELOOP:  # symlink refused by O_NOFOLLOW
                return None
            raise
        with os.fdopen(fd, "rb") as fh:
            if not stat.S_ISREG(os.fstat(fh.fileno()).st_mode):
                return None
            # Read in chunks: procfs files reject very large single reads.
            chunks, total = [], 0
            while total < MAX_READ_BYTES:
                chunk = fh.read(65536)
                if not chunk:
                    break
                chunks.append(chunk)
                total += len(chunk)
            return b"".join(chunks)

    def read_text(self, logical: str, nofollow: bool = False) -> Optional[str]:
        data = self.read_bytes(logical, nofollow=nofollow)
        if data is None:
            return None
        return data.decode("utf-8", "surrogateescape")

    def lstat(self, logical: str) -> Optional[os.stat_result]:
        try:
            return os.lstat(self.path(logical))
        except (FileNotFoundError, NotADirectoryError):
            return None
        except PermissionError:
            raise NeedsRoot(logical)

    def exists(self, logical: str) -> bool:
        try:
            return self.lstat(logical) is not None
        except NeedsRoot:
            return True

    def isdir(self, logical: str) -> bool:
        return os.path.isdir(self.path(logical))

    def listdir(self, logical: str) -> List[str]:
        try:
            return sorted(os.listdir(self.path(logical)))
        except (FileNotFoundError, NotADirectoryError):
            return []
        except PermissionError:
            raise NeedsRoot(logical)

    def glob(self, pattern: str) -> List[str]:
        return sorted(self.logical(p) for p in _glob.glob(self.path(pattern)))

    # -------------------------------------------------------------- commands
    def which(self, name: str) -> Optional[str]:
        if not self.run_commands:
            return None
        return shutil.which(name, path=SAFE_PATH)

    def run(self, argv: List[str], timeout: int = 60) -> Optional[subprocess.CompletedProcess]:
        """Run a command without a shell. Returns None if commands are disabled or missing."""
        exe = self.which(argv[0])
        if exe is None:
            return None
        try:
            return subprocess.run(
                [exe] + list(argv[1:]),
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                universal_newlines=True,
                timeout=timeout,
                env=dict(SAFE_ENV),
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired):
            return None

    # ------------------------------------------------------- users & groups
    def passwd(self) -> List[PasswdEntry]:
        if "passwd" not in self.cache:
            entries = []
            for line in (self.read_text("/etc/passwd") or "").splitlines():
                parts = line.split(":")
                if len(parts) < 7 or line.startswith("#"):
                    continue
                try:
                    uid, gid = int(parts[2]), int(parts[3])
                except ValueError:
                    continue
                entries.append(PasswdEntry(parts[0], uid, gid, parts[5], parts[6], parts[1]))
            self.cache["passwd"] = entries
        return self.cache["passwd"]  # type: ignore[return-value]

    def user(self, name: str) -> Optional[PasswdEntry]:
        for entry in self.passwd():
            if entry.name == name:
                return entry
        return None

    def groups(self) -> Dict[str, Tuple[int, List[str]]]:
        if "groups" not in self.cache:
            result = {}
            for line in (self.read_text("/etc/group") or "").splitlines():
                parts = line.split(":")
                if len(parts) < 4:
                    continue
                try:
                    gid = int(parts[2])
                except ValueError:
                    continue
                result[parts[0]] = (gid, [m for m in parts[3].split(",") if m])
            self.cache["groups"] = result
        return self.cache["groups"]  # type: ignore[return-value]

    def is_admin(self, username: str) -> bool:
        """True if the user is in a group that typically grants sudo (sudo/admin/wheel)."""
        user = self.user(username)
        for name in ("sudo", "admin", "wheel"):
            group = self.groups().get(name)
            if group is None:
                continue
            gid, members = group
            if username in members or (user is not None and user.gid == gid):
                return True
        return False

    def invoking_user(self) -> Optional[str]:
        """The human behind this run: SUDO_USER when elevated via sudo, else the current user."""
        if self._invoking_user is not None:
            return self._invoking_user
        sudo_user = os.environ.get("SUDO_USER")
        if sudo_user:
            return sudo_user
        if self.live:
            try:
                import pwd

                return pwd.getpwuid(os.getuid()).pw_name
            except (KeyError, ImportError):
                return None
        return None

    # -------------------------------------------------------------- packages
    def installed_packages(self) -> Dict[str, str]:
        """Parse the dpkg status database (no command needed). Returns name -> version."""
        if "dpkg" not in self.cache:
            pkgs: Dict[str, str] = {}
            text = self.read_text("/var/lib/dpkg/status") or ""
            for block in text.split("\n\n"):
                fields = {}
                for line in block.splitlines():
                    if line[:1].isspace() or ":" not in line:
                        continue
                    key, _, value = line.partition(":")
                    fields[key.strip()] = value.strip()
                if fields.get("Package") and fields.get("Status", "").endswith(" installed"):
                    pkgs[fields["Package"]] = fields.get("Version", "")
            self.cache["dpkg"] = pkgs
        return self.cache["dpkg"]  # type: ignore[return-value]

    def has_package(self, name: str) -> bool:
        return name in self.installed_packages()

    def service_active(self, unit: str) -> Optional[bool]:
        res = self.run(["systemctl", "is-active", unit])
        if res is None:
            return None
        return res.stdout.strip() == "active"
