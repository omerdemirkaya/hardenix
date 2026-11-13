"""Static guarantees about the code base itself.

These tests are the tripwire for a compromised or careless change: if anyone adds
network access, a shell invocation or a third-party dependency, CI fails.
"""

import ast
import json
import os
import subprocess
import sys

SRC = os.path.join(os.path.dirname(__file__), "..", "src", "hardenix")
ROOT = os.path.join(os.path.dirname(__file__), "..")

FORBIDDEN_MODULES = {
    "socket", "ssl", "http", "urllib", "urllib2", "urllib3", "requests", "httpx", "aiohttp", "ftplib",
    "smtplib", "poplib", "imaplib", "telnetlib", "xmlrpc", "asyncio", "socketserver", "webbrowser",
    "pickle", "marshal", "ctypes", "importlib", "pip", "setuptools",
}
FORBIDDEN_CALLS = {"eval", "exec", "compile", "__import__"}
FORBIDDEN_ATTRS = {("os", "system"), ("os", "popen"), ("subprocess", "Popen"), ("subprocess", "call"),
                   ("subprocess", "check_output"), ("subprocess", "getoutput"), ("subprocess", "getstatusoutput")}


def sources():
    for dirpath, _, files in os.walk(SRC):
        for name in files:
            if name.endswith(".py"):
                path = os.path.join(dirpath, name)
                with open(path) as fh:
                    yield path, ast.parse(fh.read(), path)


def test_no_network_or_dangerous_imports():
    for path, tree in sources():
        for node in ast.walk(tree):
            names = []
            if isinstance(node, ast.Import):
                names = [a.name for a in node.names]
            elif isinstance(node, ast.ImportFrom) and node.level == 0:
                names = [node.module or ""]
            for n in names:
                assert n.split(".")[0] not in FORBIDDEN_MODULES, "%s imports %s" % (path, n)


def test_no_shell_eval_or_unsafe_process_calls():
    for path, tree in sources():
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                if isinstance(node.func, ast.Name):
                    assert node.func.id not in FORBIDDEN_CALLS, "%s calls %s" % (path, node.func.id)
                if isinstance(node.func, ast.Attribute) and isinstance(node.func.value, ast.Name):
                    assert (node.func.value.id, node.func.attr) not in FORBIDDEN_ATTRS, \
                        "%s calls %s.%s" % (path, node.func.value.id, node.func.attr)
                for kw in node.keywords:
                    if kw.arg == "shell":
                        assert isinstance(kw.value, ast.Constant) and kw.value.value is False, \
                            "%s uses shell=True" % path


def test_subprocess_only_in_core():
    for path, tree in sources():
        uses = any(isinstance(n, ast.Import) and any(a.name == "subprocess" for a in n.names)
                   for n in ast.walk(tree))
        if uses:
            assert path.endswith("core.py"), "%s imports subprocess; use Context.run" % path


def test_no_runtime_dependencies():
    with open(os.path.join(ROOT, "pyproject.toml")) as fh:
        text = fh.read()
    assert "dependencies = []" in text


def test_json_output_never_contains_secrets(fakeroot):
    from conftest import write
    write(fakeroot, "/home/alice/.bash_history", "mysql -uroot -pVeryS3cret\n", 0o600)
    env = dict(os.environ, PYTHONPATH=os.path.join(ROOT, "src"))
    out = subprocess.run([sys.executable, "-m", "hardenix", "audit", "--json", "--root", str(fakeroot)],
                         stdout=subprocess.PIPE, env=env, check=False).stdout.decode()
    assert "VeryS3cret" not in out
    data = json.loads(out)
    assert any(f["id"].startswith("HIST-001:") for f in data["findings"])
