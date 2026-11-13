"""All checks. Importing this package registers them (order = report order)."""

from . import ssh, accounts, files, firewall, updates, sysctl, services, history  # noqa: F401
