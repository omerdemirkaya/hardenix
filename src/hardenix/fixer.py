"""Planning, applying and rolling back fixes.

Safety properties:
  * every change is shown (as a diff) before it is applied and needs confirmation;
  * every changed file is backed up first (except "sensitive" changes, see FileChange);
  * files are written atomically (temp file + rename) and never through a symlink;
  * a fix with a ``validate`` command is reverted automatically if validation fails;
  * ``hardenix rollback`` restores the last session from its manifest.
"""

from __future__ import annotations

import difflib
import json
import os
import re
import stat
import tempfile
import time
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple

from . import __version__
from .core import Context, FileChange, Fix

BACKUP_ROOT = "/var/lib/hardenix/backups"


class FixError(Exception):
    pass


@dataclass
class PlannedChange:
    change: FileChange
    old: Optional[str]  # None: file does not exist (or is a directory)
    new: Optional[str]  # None: content unchanged
    old_mode: Optional[int]
    new_mode: Optional[int]  # None: mode unchanged

    @property
    def path(self) -> str:
        return self.change.path


# Virtual view of files after the fixes accepted so far: path -> (content, mode)
Virtual = Dict[str, Tuple[Optional[str], Optional[int]]]


def apply_kv(text: Optional[str], settings: Dict[str, str], fmt: str, header: str) -> str:
    """Set ``key value`` lines in a config file, replacing existing ones (case-insensitive)."""
    if text:
        lines = text.splitlines(True)
        if not lines[-1].endswith("\n"):
            lines[-1] += "\n"
    else:
        lines = [header] if header else []
    for key, value in settings.items():
        rendered = fmt.format(key=key, value=value) + "\n"
        pattern = re.compile(r"^\s*%s(?:\s|=|$)" % re.escape(key), re.I)
        replaced = False
        for i, line in enumerate(lines):
            if pattern.match(line):
                lines[i] = "" if replaced else rendered
                replaced = True
        if not replaced:
            lines.append(rendered)
    return "".join(lines)


def plan(ctx: Context, fix: Fix, virtual: Virtual) -> List[PlannedChange]:
    planned = []
    for ch in fix.changes:
        if ch.path in virtual:
            old, old_mode = virtual[ch.path]
        else:
            st = ctx.lstat(ch.path)
            if st is not None and stat.S_ISLNK(st.st_mode):
                raise FixError("%s is a symlink; refusing to modify it" % ch.path)
            writes_content = ch.content is not None or ch.set_keys is not None
            if st is not None and writes_content and not stat.S_ISREG(st.st_mode):
                raise FixError("%s is not a regular file; refusing to modify it" % ch.path)
            old = ctx.read_text(ch.path, nofollow=True) if st is not None and stat.S_ISREG(st.st_mode) else None
            old_mode = stat.S_IMODE(st.st_mode) if st is not None else None
        new: Optional[str] = None
        if ch.content is not None:
            new = ch.content
        elif ch.set_keys:
            new = apply_kv(old, ch.set_keys, ch.kv_format, ch.header)
        if new is not None and new == old:
            new = None
        new_mode = ch.mode if ch.mode is not None and ch.mode != old_mode else None
        if old_mode is None and new is None and new_mode is not None:
            raise FixError("%s does not exist" % ch.path)
        planned.append(PlannedChange(ch, old, new, old_mode, new_mode))
    return planned


def commit_virtual(virtual: Virtual, planned: List[PlannedChange]) -> None:
    for pc in planned:
        content = pc.new if pc.new is not None else pc.old
        mode = pc.new_mode if pc.new_mode is not None else pc.old_mode
        if mode is None and pc.new is not None:
            mode = 0o644
        virtual[pc.path] = (content, mode)


def describe(pc: PlannedChange) -> List[str]:
    out: List[str] = []
    if pc.new is not None:
        old_lines = (pc.old or "").splitlines(True)
        new_lines = pc.new.splitlines(True)
        if pc.change.sensitive:
            removed = sum(1 for l in difflib.ndiff(old_lines, new_lines) if l.startswith("- "))
            out.append("  %s: %d line(s) will be removed (content hidden because it contains secrets)"
                       % (pc.path, removed))
        else:
            out.extend(l.rstrip("\n") for l in difflib.unified_diff(
                old_lines, new_lines, fromfile=pc.path if pc.old is not None else "/dev/null", tofile=pc.path))
    if pc.new_mode is not None:
        if pc.old_mode is None:
            out.append("  new file mode %04o %s" % (pc.new_mode, pc.path))
        else:
            out.append("  chmod %04o -> %04o %s" % (pc.old_mode, pc.new_mode, pc.path))
    return out


# --------------------------------------------------------------------------- file ops
def _check_no_symlinks_in_dir(real_dir: str) -> None:
    if os.path.realpath(real_dir) != os.path.abspath(real_dir):
        raise FixError("%s contains a symlink; refusing to write there" % real_dir)


def atomic_write(ctx: Context, logical: str, data: bytes, mode: int, uid: Optional[int], gid: Optional[int]) -> None:
    real = ctx.path(logical)
    directory = os.path.dirname(real)
    if not os.path.isdir(directory):
        raise FixError("directory %s does not exist" % ctx.logical(directory))
    _check_no_symlinks_in_dir(directory)
    try:
        st = os.lstat(real)
        if not stat.S_ISREG(st.st_mode):
            raise FixError("%s is not a regular file; refusing to replace it" % logical)
    except FileNotFoundError:
        pass
    fd, tmp = tempfile.mkstemp(prefix=".hardenix-", dir=directory)
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(data)
            fh.flush()
            os.fchmod(fh.fileno(), mode)
            if ctx.live and ctx.is_root and uid is not None and gid is not None:
                os.fchown(fh.fileno(), uid, gid)
            os.fsync(fh.fileno())
        os.replace(tmp, real)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise
    dfd = os.open(directory, os.O_RDONLY)
    try:
        os.fsync(dfd)
    finally:
        os.close(dfd)


def set_mode(ctx: Context, logical: str, mode: int) -> None:
    real = ctx.path(logical)
    st = os.lstat(real)
    if stat.S_ISLNK(st.st_mode):
        raise FixError("%s is a symlink; refusing to chmod it" % logical)
    fd = os.open(real, os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_NONBLOCK", 0))
    try:
        os.fchmod(fd, mode)
    finally:
        os.close(fd)


def _write_private(path: str, data: bytes) -> None:
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "wb") as fh:
        fh.write(data)
        fh.flush()
        os.fsync(fh.fileno())


# --------------------------------------------------------------------------- backups
class BackupSession:
    def __init__(self, ctx: Context) -> None:
        self.ctx = ctx
        self.dir: Optional[str] = None
        self.manifest: dict = {
            "tool": "hardenix", "version": __version__, "created": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
            "entries": [], "undo_commands": [], "rolled_back": None,
        }

    def _ensure(self) -> str:
        if self.dir is None:
            root = self.ctx.path(BACKUP_ROOT)
            os.makedirs(root, mode=0o700, exist_ok=True)
            for d in (os.path.dirname(root), root):
                os.chmod(d, 0o700)
            name = time.strftime("%Y%m%d-%H%M%S") + "-%d" % os.getpid()
            self.dir = os.path.join(root, name)
            os.mkdir(self.dir, 0o700)
            os.mkdir(os.path.join(self.dir, "files"), 0o700)
        return self.dir

    def save(self) -> None:
        d = self._ensure()
        data = json.dumps(self.manifest, indent=2).encode()
        tmp = os.path.join(d, ".manifest.tmp")
        if os.path.lexists(tmp):
            os.unlink(tmp)
        _write_private(tmp, data)
        os.replace(tmp, os.path.join(d, "manifest.json"))

    def record(self, pc: PlannedChange, fix_id: str) -> dict:
        d = self._ensure()
        st = self.ctx.lstat(pc.path)
        entry = {
            "path": pc.path, "fix": fix_id, "existed": st is not None,
            "is_dir": bool(st is not None and stat.S_ISDIR(st.st_mode)),
            "mode": stat.S_IMODE(st.st_mode) if st else None,
            "uid": st.st_uid if st else None, "gid": st.st_gid if st else None,
            "content_changed": pc.new is not None, "sensitive": pc.change.sensitive, "backup": None,
        }
        # Only back up content that is about to change. Permission-only changes record the old
        # mode alone, so e.g. a chmod on a history file never copies its contents anywhere.
        if pc.new is not None and st is not None and stat.S_ISREG(st.st_mode) and not pc.change.sensitive:
            data = self.ctx.read_bytes(pc.path, nofollow=True)
            if data is None:
                raise FixError("cannot back up %s" % pc.path)
            name = "%04d" % len(self.manifest["entries"])
            _write_private(os.path.join(d, "files", name), data)
            entry["backup"] = name
        self.manifest["entries"].append(entry)
        self.save()
        return entry

    def drop(self, entries: List[dict]) -> None:
        self.manifest["entries"] = [e for e in self.manifest["entries"] if not any(e is x for x in entries)]
        self.save()

    def add_undo(self, commands: List[List[str]]) -> None:
        self.manifest["undo_commands"].append(commands)
        self.save()


def restore_entry(ctx: Context, session_dir: str, entry: dict) -> str:
    path = entry["path"]
    if not entry["existed"]:
        st = ctx.lstat(path)
        if st is not None and stat.S_ISREG(st.st_mode):
            os.unlink(ctx.path(path))
            return "removed %s" % path
        return "%s already gone" % path
    if entry["content_changed"] and entry["backup"] is None:
        return "NOT restored %s (secrets were removed on purpose; no backup was kept)" % path
    if entry["backup"]:
        with open(os.path.join(session_dir, "files", entry["backup"]), "rb") as fh:
            data = fh.read()
        atomic_write(ctx, path, data, entry["mode"], entry["uid"], entry["gid"])
        return "restored %s" % path
    set_mode(ctx, path, entry["mode"])
    return "restored mode %04o on %s" % (entry["mode"], path)


# --------------------------------------------------------------------------- apply
def apply_fix(ctx: Context, fix: Fix, fix_id: str, planned: List[PlannedChange],
              session: BackupSession) -> Tuple[bool, List[str]]:
    messages: List[str] = []
    entries: List[dict] = []

    def revert(reason: str) -> Tuple[bool, List[str]]:
        for e in reversed(entries):
            try:
                restore_entry(ctx, session._ensure(), e)
            except Exception as exc:  # pragma: no cover - best effort
                messages.append("could not revert %s: %s" % (e["path"], exc))
        session.drop(entries)
        messages.append(reason + " - changes were reverted")
        return False, messages

    try:
        for pc in planned:
            entries.append(session.record(pc, fix_id))
            if pc.new is not None:
                st = ctx.lstat(pc.path)
                mode = pc.new_mode if pc.new_mode is not None else (pc.old_mode if pc.old_mode is not None else 0o644)
                uid, gid = (st.st_uid, st.st_gid) if st is not None else (0, 0)
                atomic_write(ctx, pc.path, pc.new.encode("utf-8", "surrogateescape"), mode, uid, gid)
            elif pc.new_mode is not None:
                set_mode(ctx, pc.path, pc.new_mode)
    except Exception as exc:
        return revert("failed: %s" % exc)

    if fix.validate and ctx.run_commands:
        res = ctx.run(fix.validate)
        if res is None or res.returncode != 0:
            err = (res.stderr.strip() if res is not None else "command not found")
            return revert("validation '%s' failed: %s" % (" ".join(fix.validate), err))

    ok = True
    if fix.commands and fix.undo_commands:
        session.add_undo(fix.undo_commands)
    for cmd in fix.commands:
        if not ctx.run_commands:
            messages.append("skipped command (not running on the live system): %s" % " ".join(cmd))
            continue
        res = ctx.run(cmd)
        if res is None or res.returncode != 0:
            err = res.stderr.strip() if res is not None else "command not found"
            if planned:
                # Files are written (and validated); only the follow-up step failed.
                messages.append("WARNING: files were changed, but '%s' failed: %s. Run it yourself."
                                % (" ".join(cmd), err))
            else:
                ok = False  # the commands *are* the fix
                messages.append("command failed: %s: %s" % (" ".join(cmd), err))
                break
            continue
        messages.append("ran: %s" % " ".join(cmd))
    return ok, messages


# --------------------------------------------------------------------------- rollback
def list_sessions(ctx: Context) -> List[Tuple[str, dict]]:
    root = ctx.path(BACKUP_ROOT)
    try:
        names = sorted(os.listdir(root))
    except FileNotFoundError:
        return []
    sessions = []
    for name in names:
        try:
            with open(os.path.join(root, name, "manifest.json")) as fh:
                sessions.append((name, json.load(fh)))
        except (OSError, ValueError):
            continue
    return sessions


def rollback(ctx: Context, name: str, manifest: dict) -> List[str]:
    session_dir = os.path.join(ctx.path(BACKUP_ROOT), name)
    messages = []
    for entry in reversed(manifest["entries"]):
        try:
            messages.append(restore_entry(ctx, session_dir, entry))
        except Exception as exc:
            messages.append("FAILED to restore %s: %s" % (entry["path"], exc))
    done = set()
    for commands in reversed(manifest.get("undo_commands", [])):
        for cmd in commands:
            if tuple(cmd) in done:
                continue
            done.add(tuple(cmd))
            if not ctx.run_commands:
                messages.append("skipped undo command: %s" % " ".join(cmd))
                continue
            res = ctx.run(cmd)
            ok = res is not None and res.returncode == 0
            messages.append("%s: %s" % ("ran" if ok else "FAILED", " ".join(cmd)))
    manifest["rolled_back"] = time.strftime("%Y-%m-%dT%H:%M:%S%z")
    session = BackupSession(ctx)
    session.dir = session_dir
    session.manifest = manifest
    session.save()
    return messages
