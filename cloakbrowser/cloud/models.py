"""SQLAlchemy models for cloud organizations, access control, and environments."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from sqlalchemy import (
    JSON,
    BigInteger,
    Boolean,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def new_id() -> str:
    return str(uuid.uuid4())


class Base(DeclarativeBase):
    pass


class User(Base):
    __tablename__ = "users"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    email: Mapped[str] = mapped_column(String(254), unique=True, index=True)
    display_name: Mapped[str] = mapped_column(String(80))
    password_hash: Mapped[str] = mapped_column(Text)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)

    memberships: Mapped[List["Membership"]] = relationship(back_populates="user")


class Organization(Base):
    __tablename__ = "organizations"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    name: Mapped[str] = mapped_column(String(100))
    slug: Mapped[str] = mapped_column(String(70), unique=True, index=True)
    created_by: Mapped[str] = mapped_column(ForeignKey("users.id"))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)

    memberships: Mapped[List["Membership"]] = relationship(
        back_populates="organization", cascade="all, delete-orphan"
    )


class Membership(Base):
    __tablename__ = "memberships"
    __table_args__ = (UniqueConstraint("organization_id", "user_id"),)

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    organization_id: Mapped[str] = mapped_column(
        ForeignKey("organizations.id", ondelete="CASCADE"), index=True
    )
    user_id: Mapped[str] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), index=True
    )
    role: Mapped[str] = mapped_column(String(20))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)

    organization: Mapped[Organization] = relationship(back_populates="memberships")
    user: Mapped[User] = relationship(back_populates="memberships")
    environment_assignments: Mapped[List["EnvironmentAssignment"]] = relationship(
        back_populates="membership", cascade="all, delete-orphan"
    )


class Session(Base):
    __tablename__ = "cloud_sessions"

    token_digest: Mapped[str] = mapped_column(String(64), primary_key=True)
    user_id: Mapped[str] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True)
    organization_id: Mapped[str] = mapped_column(
        ForeignKey("organizations.id", ondelete="CASCADE"), index=True
    )
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)


class Group(Base):
    __tablename__ = "environment_groups"
    __table_args__ = (UniqueConstraint("organization_id", "name"),)

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    organization_id: Mapped[str] = mapped_column(
        ForeignKey("organizations.id", ondelete="CASCADE"), index=True
    )
    name: Mapped[str] = mapped_column(String(80))
    description: Mapped[str] = mapped_column(String(300), default="")
    created_by: Mapped[str] = mapped_column(ForeignKey("users.id"))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utc_now, onupdate=utc_now
    )


class Environment(Base):
    __tablename__ = "cloud_environments"
    __table_args__ = (
        UniqueConstraint("organization_id", "name"),
        Index("ix_cloud_environments_org_updated", "organization_id", "updated_at"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    organization_id: Mapped[str] = mapped_column(
        ForeignKey("organizations.id", ondelete="CASCADE"), index=True
    )
    group_id: Mapped[Optional[str]] = mapped_column(
        ForeignKey("environment_groups.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )
    name: Mapped[str] = mapped_column(String(100))
    tags: Mapped[List[str]] = mapped_column(JSON, default=list)
    storage_policy: Mapped[str] = mapped_column(String(20), default="local")
    config: Mapped[Dict[str, Any]] = mapped_column(JSON, default=dict)
    revision: Mapped[int] = mapped_column(Integer, default=1)
    created_by: Mapped[str] = mapped_column(ForeignKey("users.id"))
    updated_by: Mapped[str] = mapped_column(ForeignKey("users.id"))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utc_now, onupdate=utc_now
    )

    group: Mapped[Optional[Group]] = relationship()
    secret: Mapped[Optional["EnvironmentSecret"]] = relationship(
        back_populates="environment",
        cascade="all, delete-orphan",
        uselist=False,
    )
    extension_links: Mapped[List["EnvironmentExtension"]] = relationship(
        back_populates="environment",
        cascade="all, delete-orphan",
        order_by="EnvironmentExtension.position",
    )
    assignments: Mapped[List["EnvironmentAssignment"]] = relationship(
        back_populates="environment",
        cascade="all, delete-orphan",
        order_by="EnvironmentAssignment.assigned_at",
    )


class EnvironmentAssignment(Base):
    __tablename__ = "environment_assignments"
    __table_args__ = (
        Index("ix_environment_assignments_membership", "membership_id"),
    )

    environment_id: Mapped[str] = mapped_column(
        ForeignKey("cloud_environments.id", ondelete="CASCADE"), primary_key=True
    )
    membership_id: Mapped[str] = mapped_column(
        ForeignKey("memberships.id", ondelete="CASCADE"), primary_key=True
    )
    organization_id: Mapped[str] = mapped_column(
        ForeignKey("organizations.id", ondelete="CASCADE"), index=True
    )
    assigned_by: Mapped[str] = mapped_column(ForeignKey("users.id"))
    assigned_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)

    environment: Mapped[Environment] = relationship(back_populates="assignments")
    membership: Mapped[Membership] = relationship(back_populates="environment_assignments")


class EnvironmentSecret(Base):
    __tablename__ = "environment_secrets"

    environment_id: Mapped[str] = mapped_column(
        ForeignKey("cloud_environments.id", ondelete="CASCADE"), primary_key=True
    )
    organization_id: Mapped[str] = mapped_column(
        ForeignKey("organizations.id", ondelete="CASCADE"), index=True
    )
    proxy_envelope: Mapped[Optional[str]] = mapped_column(Text)
    proxy_masked: Mapped[str] = mapped_column(String(500), default="")
    version: Mapped[int] = mapped_column(Integer, default=0)
    updated_by: Mapped[str] = mapped_column(ForeignKey("users.id"))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utc_now, onupdate=utc_now
    )

    environment: Mapped[Environment] = relationship(back_populates="secret")


class ExtensionPackage(Base):
    __tablename__ = "extension_packages"
    __table_args__ = (
        UniqueConstraint("organization_id", "name", "version"),
        Index("ix_extension_packages_org_created", "organization_id", "created_at"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    organization_id: Mapped[str] = mapped_column(
        ForeignKey("organizations.id", ondelete="CASCADE"), index=True
    )
    name: Mapped[str] = mapped_column(String(100))
    version: Mapped[str] = mapped_column(String(40))
    status: Mapped[str] = mapped_column(String(20), default="pending")
    object_key: Mapped[Optional[str]] = mapped_column(String(500))
    content_sha256: Mapped[str] = mapped_column(String(64))
    content_size: Mapped[int] = mapped_column(BigInteger)
    manifest: Mapped[Dict[str, Any]] = mapped_column(JSON, default=dict)
    created_by: Mapped[str] = mapped_column(ForeignKey("users.id"))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utc_now, onupdate=utc_now
    )

    environment_links: Mapped[List["EnvironmentExtension"]] = relationship(
        back_populates="extension",
        cascade="all, delete-orphan",
    )


class EnvironmentExtension(Base):
    __tablename__ = "environment_extensions"
    __table_args__ = (
        Index("ix_environment_extensions_package", "extension_id"),
    )

    environment_id: Mapped[str] = mapped_column(
        ForeignKey("cloud_environments.id", ondelete="CASCADE"), primary_key=True
    )
    extension_id: Mapped[str] = mapped_column(
        ForeignKey("extension_packages.id", ondelete="CASCADE"), primary_key=True
    )
    position: Mapped[int] = mapped_column(Integer, default=0)

    environment: Mapped[Environment] = relationship(back_populates="extension_links")
    extension: Mapped[ExtensionPackage] = relationship(back_populates="environment_links")


class AuditLog(Base):
    __tablename__ = "audit_logs"
    __table_args__ = (Index("ix_audit_org_created", "organization_id", "created_at"),)

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    organization_id: Mapped[str] = mapped_column(
        ForeignKey("organizations.id", ondelete="CASCADE"), index=True
    )
    actor_id: Mapped[str] = mapped_column(ForeignKey("users.id"), index=True)
    action: Mapped[str] = mapped_column(String(80))
    target_type: Mapped[str] = mapped_column(String(40))
    target_id: Mapped[str] = mapped_column(String(80))
    details: Mapped[Dict[str, Any]] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)


class AgentNode(Base):
    __tablename__ = "agent_nodes"
    __table_args__ = (UniqueConstraint("organization_id", "name"),)

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    organization_id: Mapped[str] = mapped_column(
        ForeignKey("organizations.id", ondelete="CASCADE"), index=True
    )
    name: Mapped[str] = mapped_column(String(100))
    token_digest: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    hostname: Mapped[str] = mapped_column(String(255), default="")
    platform: Mapped[str] = mapped_column(String(120), default="")
    version: Mapped[str] = mapped_column(String(40), default="")
    capabilities: Mapped[Dict[str, bool]] = mapped_column(JSON, default=dict)
    created_by: Mapped[str] = mapped_column(ForeignKey("users.id"))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)
    last_seen_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))
    revoked_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))

    client_device: Mapped[Optional["ClientDevice"]] = relationship(
        back_populates="agent",
        cascade="all, delete-orphan",
        uselist=False,
    )


class ClientDevice(Base):
    __tablename__ = "client_devices"
    __table_args__ = (
        UniqueConstraint("organization_id", "user_id", "device_uid"),
        Index("ix_client_devices_membership", "membership_id"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    organization_id: Mapped[str] = mapped_column(
        ForeignKey("organizations.id", ondelete="CASCADE"), index=True
    )
    user_id: Mapped[str] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), index=True
    )
    membership_id: Mapped[str] = mapped_column(
        ForeignKey("memberships.id", ondelete="CASCADE"), index=True
    )
    agent_id: Mapped[str] = mapped_column(
        ForeignKey("agent_nodes.id", ondelete="CASCADE"), unique=True, index=True
    )
    device_uid: Mapped[str] = mapped_column(String(64))
    token_digest: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    last_login_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)

    agent: Mapped[AgentNode] = relationship(back_populates="client_device")
    membership: Mapped[Membership] = relationship()
    user: Mapped[User] = relationship()


class EnvironmentLease(Base):
    __tablename__ = "environment_leases"
    __table_args__ = (
        Index("ix_environment_leases_org_expires", "organization_id", "expires_at"),
    )

    environment_id: Mapped[str] = mapped_column(
        ForeignKey("cloud_environments.id", ondelete="CASCADE"), primary_key=True
    )
    organization_id: Mapped[str] = mapped_column(
        ForeignKey("organizations.id", ondelete="CASCADE"), index=True
    )
    agent_id: Mapped[Optional[str]] = mapped_column(
        ForeignKey("agent_nodes.id", ondelete="SET NULL"), index=True
    )
    lease_id: Mapped[Optional[str]] = mapped_column(String(36), unique=True)
    lease_token_digest: Mapped[Optional[str]] = mapped_column(String(64))
    fencing_token: Mapped[int] = mapped_column(Integer, default=0)
    acquired_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))
    heartbeat_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))
    expires_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), index=True)

    environment: Mapped[Environment] = relationship()
    agent: Mapped[Optional[AgentNode]] = relationship()


class EnvironmentSnapshot(Base):
    __tablename__ = "environment_snapshots"
    __table_args__ = (
        Index("ix_environment_snapshots_org_updated", "organization_id", "updated_at"),
    )

    environment_id: Mapped[str] = mapped_column(
        ForeignKey("cloud_environments.id", ondelete="CASCADE"), primary_key=True
    )
    organization_id: Mapped[str] = mapped_column(
        ForeignKey("organizations.id", ondelete="CASCADE"), index=True
    )
    key_envelope: Mapped[str] = mapped_column(Text)
    version: Mapped[int] = mapped_column(Integer, default=0)
    fencing_token: Mapped[int] = mapped_column(Integer, default=0)
    object_key: Mapped[Optional[str]] = mapped_column(String(500))
    ciphertext_sha256: Mapped[Optional[str]] = mapped_column(String(64))
    ciphertext_size: Mapped[int] = mapped_column(BigInteger, default=0)
    plaintext_size: Mapped[int] = mapped_column(BigInteger, default=0)
    uploaded_by_agent_id: Mapped[Optional[str]] = mapped_column(
        ForeignKey("agent_nodes.id", ondelete="SET NULL"), index=True
    )
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utc_now, onupdate=utc_now
    )

    environment: Mapped[Environment] = relationship()
    uploaded_by_agent: Mapped[Optional[AgentNode]] = relationship()


class RemoteTask(Base):
    __tablename__ = "remote_tasks"
    __table_args__ = (
        Index("ix_remote_tasks_agent_status_created", "agent_id", "status", "created_at"),
        Index("ix_remote_tasks_org_created", "organization_id", "created_at"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    organization_id: Mapped[str] = mapped_column(
        ForeignKey("organizations.id", ondelete="CASCADE"), index=True
    )
    environment_id: Mapped[str] = mapped_column(
        ForeignKey("cloud_environments.id", ondelete="CASCADE"), index=True
    )
    agent_id: Mapped[str] = mapped_column(
        ForeignKey("agent_nodes.id", ondelete="CASCADE"), index=True
    )
    kind: Mapped[str] = mapped_column(String(20))
    status: Mapped[str] = mapped_column(String(20), default="pending")
    dedupe_key: Mapped[Optional[str]] = mapped_column(String(36), unique=True)
    claim_token_digest: Mapped[Optional[str]] = mapped_column(String(64))
    environment_revision: Mapped[int] = mapped_column(Integer)
    payload: Mapped[Dict[str, Any]] = mapped_column(JSON, default=dict)
    result: Mapped[Dict[str, Any]] = mapped_column(JSON, default=dict)
    error: Mapped[str] = mapped_column(Text, default="")
    created_by: Mapped[str] = mapped_column(ForeignKey("users.id"))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)
    claimed_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))
    completed_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utc_now, onupdate=utc_now
    )

    environment: Mapped[Environment] = relationship()
    agent: Mapped[AgentNode] = relationship()
