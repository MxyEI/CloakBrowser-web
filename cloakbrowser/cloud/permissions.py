"""Organization roles and permission checks."""

from __future__ import annotations

from typing import FrozenSet


ROLES = ("owner", "admin", "operator", "viewer", "member")

ROLE_PERMISSIONS: dict[str, FrozenSet[str]] = {
    "owner": frozenset(
        {
            "organization.manage",
            "members.manage",
            "assignments.manage",
            "agents.read",
            "agents.manage",
            "leases.read",
            "tasks.read",
            "snapshots.read",
            "snapshots.manage",
            "extensions.read",
            "extensions.manage",
            "groups.manage",
            "environments.read",
            "environments.create",
            "environments.edit",
            "environments.delete",
            "environments.launch",
            "audit.read",
        }
    ),
    "admin": frozenset(
        {
            "members.manage",
            "assignments.manage",
            "agents.read",
            "agents.manage",
            "leases.read",
            "tasks.read",
            "snapshots.read",
            "snapshots.manage",
            "extensions.read",
            "extensions.manage",
            "groups.manage",
            "environments.read",
            "environments.create",
            "environments.edit",
            "environments.delete",
            "environments.launch",
            "audit.read",
        }
    ),
    "operator": frozenset(
        {
            "environments.read",
            "environments.create",
            "environments.edit",
            "agents.read",
            "leases.read",
            "tasks.read",
            "snapshots.read",
            "extensions.read",
            "environments.launch",
        }
    ),
    "viewer": frozenset(
        {
            "environments.read",
            "agents.read",
            "leases.read",
            "tasks.read",
            "snapshots.read",
            "extensions.read",
        }
    ),
    "member": frozenset(
        {
            "agents.read",
            "leases.read",
            "tasks.read",
            "snapshots.read",
            "extensions.read",
            "environments.read",
            "environments.launch",
        }
    ),
}


def has_permission(role: str, permission: str) -> bool:
    return permission in ROLE_PERMISSIONS.get(role, frozenset())
