import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from hardenix.core import Context  # noqa: E402


def write(root, path, content, mode=0o644):
    real = os.path.join(str(root), path.lstrip("/"))
    os.makedirs(os.path.dirname(real), exist_ok=True)
    with open(real, "w") as fh:
        fh.write(content)
    os.chmod(real, mode)
    return real


@pytest.fixture
def fakeroot(tmp_path):
    """A minimal Debian-like filesystem tree."""
    write(tmp_path, "/etc/passwd",
          "root:x:0:0:root:/root:/bin/bash\n"
          "alice:x:1000:1000:Alice:/home/alice:/bin/bash\n"
          "nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin\n")
    write(tmp_path, "/etc/group", "root:x:0:\nsudo:x:27:alice\nalice:x:1000:\n")
    write(tmp_path, "/etc/shadow", "root:!:19000::::::\nalice:$6$abc$def:19000::::::\n", 0o640)
    write(tmp_path, "/etc/ssh/sshd_config", "Include /etc/ssh/sshd_config.d/*.conf\nUsePAM yes\n"
                                            "KbdInteractiveAuthentication no\n")
    write(tmp_path, "/etc/ssh/sshd_config.d/50-cloud-init.conf", "PasswordAuthentication yes\n")
    write(tmp_path, "/home/alice/.ssh/authorized_keys", "ssh-ed25519 AAAAfake alice@laptop\n", 0o600)
    os.makedirs(os.path.join(str(tmp_path), "etc/sysctl.d"))
    os.makedirs(os.path.join(str(tmp_path), "etc/apt/apt.conf.d"))
    os.makedirs(os.path.join(str(tmp_path), "var/lib/dpkg"))
    write(tmp_path, "/var/lib/dpkg/status", "Package: openssh-server\nStatus: install ok installed\n"
                                            "Version: 1:9.6\n\nPackage: ufw\nStatus: install ok installed\n")
    return tmp_path


@pytest.fixture
def ctx(fakeroot):
    return Context(root=str(fakeroot), euid=0, invoking_user="alice")
