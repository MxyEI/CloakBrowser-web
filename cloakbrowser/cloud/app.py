"""FastAPI application for the CloakBrowser collaborative control plane."""

from __future__ import annotations

import hashlib
import os
import re
import secrets
import tempfile
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Callable, Generator, Optional
from urllib.parse import urlsplit

from fastapi import Depends, FastAPI, HTTPException, Request, Response, status
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from sqlalchemy import delete, func, or_, select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session as DatabaseSession
from sqlalchemy.orm import joinedload

from .database import create_database_engine, create_session_factory, initialize_database
from .constants import AGENT_TOKEN_PREFIX
from .models import (
    AuditLog,
    AgentNode,
    Environment,
    EnvironmentExtension,
    EnvironmentLease,
    EnvironmentSecret,
    EnvironmentSnapshot,
    ExtensionPackage,
    Group,
    Membership,
    Organization,
    RemoteTask,
    Session,
    User,
    new_id,
    utc_now,
)
from .permissions import ROLE_PERMISSIONS, has_permission
from .schemas import (
    AgentCreate,
    AgentHeartbeat,
    AgentLeaseAcquire,
    AgentLeaseProof,
    AgentTaskCompletion,
    AgentTaskProof,
    EnvironmentCreate,
    EnvironmentUpdate,
    ExtensionCreate,
    GroupCreate,
    GroupUpdate,
    LoginRequest,
    MemberCreate,
    MemberUpdate,
    OrganizationCreate,
    OrganizationSwitch,
    RegisterRequest,
    RemoteLaunchRequest,
)
from .security import (
    SESSION_COOKIE,
    agent_token_digest,
    csrf_matches,
    csrf_token,
    hash_password,
    lease_token_digest,
    new_agent_token,
    new_lease_token,
    new_session_token,
    new_task_token,
    session_digest,
    task_token_digest,
    verify_password,
)
from .settings import CloudSettings
from .extension_packages import ExtensionPackageError, inspect_extension_zip
from .secrets_crypto import (
    SecretCryptoError,
    decrypt_environment_secret,
    encrypt_environment_secret,
)
from .snapshot_crypto import (
    NONCE_BYTES,
    SNAPSHOT_MAGIC,
    TAG_BYTES,
    SnapshotError,
    encode_snapshot_key,
    unwrap_snapshot_key,
    wrap_snapshot_key,
)


MAX_REQUEST_BYTES = 1024 * 1024
AGENT_ONLINE_SECONDS = 45
LEASE_TTL_SECONDS = 60
TASK_CLAIM_TTL_SECONDS = 120


@dataclass
class AuthContext:
    user: User
    organization: Organization
    membership: Membership
    session: Session
    raw_token: str


@dataclass
class AgentAuthContext:
    agent: AgentNode
    raw_token: str


def _iso(value: datetime) -> str:
    if value.tzinfo is None:
        value = value.replace(tzinfo=utc_now().tzinfo)
    return value.isoformat()


def _session_expired(value: datetime) -> bool:
    now = utc_now()
    if value.tzinfo is None:
        now = now.replace(tzinfo=None)
    return value <= now


def _is_after(value: Optional[datetime], reference: datetime) -> bool:
    if value is None:
        return False
    if value.tzinfo is None:
        reference = reference.replace(tzinfo=None)
    return value > reference


def _slug_base(name: str) -> str:
    slug = re.sub(r"[^a-z0-9]+", "-", name.strip().lower()).strip("-")[:50]
    return slug or "team"


def _unique_slug(db: DatabaseSession, name: str) -> str:
    base = _slug_base(name)
    candidate = base
    while db.scalar(select(Organization.id).where(Organization.slug == candidate)):
        candidate = f"{base[:50]}-{secrets.token_hex(3)}"
    return candidate


def _user_json(user: User) -> dict[str, Any]:
    return {
        "id": user.id,
        "email": user.email,
        "display_name": user.display_name,
    }


def _organization_json(organization: Organization, role: str) -> dict[str, Any]:
    return {
        "id": organization.id,
        "name": organization.name,
        "slug": organization.slug,
        "role": role,
    }


def _member_json(membership: Membership) -> dict[str, Any]:
    return {
        "id": membership.id,
        "role": membership.role,
        "created_at": _iso(membership.created_at),
        "user": _user_json(membership.user),
    }


def _group_json(group: Group) -> dict[str, Any]:
    return {
        "id": group.id,
        "name": group.name,
        "description": group.description,
        "created_at": _iso(group.created_at),
        "updated_at": _iso(group.updated_at),
    }


def _environment_json(environment: Environment) -> dict[str, Any]:
    secret = environment.secret
    extensions = [
        link.extension
        for link in environment.extension_links
        if link.extension.status == "ready"
    ]
    return {
        "id": environment.id,
        "name": environment.name,
        "group_id": environment.group_id,
        "group_name": environment.group.name if environment.group else "",
        "tags": list(environment.tags or []),
        "storage_policy": environment.storage_policy,
        "config": dict(environment.config or {}),
        "proxy_configured": bool(secret and secret.proxy_envelope),
        "proxy_masked": secret.proxy_masked if secret and secret.proxy_envelope else "",
        "secret_revision": secret.version if secret else 0,
        "extension_ids": [extension.id for extension in extensions],
        "extensions": [
            {
                "id": extension.id,
                "name": extension.name,
                "version": extension.version,
                "content_sha256": extension.content_sha256,
            }
            for extension in extensions
        ],
        "revision": environment.revision,
        "created_at": _iso(environment.created_at),
        "updated_at": _iso(environment.updated_at),
    }


def _extension_json(extension: ExtensionPackage) -> dict[str, Any]:
    return {
        "id": extension.id,
        "name": extension.name,
        "version": extension.version,
        "status": extension.status,
        "content_sha256": extension.content_sha256,
        "content_size": extension.content_size,
        "manifest": dict(extension.manifest or {}),
        "assigned_environments": len(extension.environment_links),
        "created_at": _iso(extension.created_at),
        "updated_at": _iso(extension.updated_at),
    }


def _mask_proxy(proxy: str) -> str:
    parsed = urlsplit(proxy)
    hostname = parsed.hostname or ""
    host = f"[{hostname}]" if ":" in hostname else hostname
    if parsed.port is not None:
        host = f"{host}:{parsed.port}"
    credentials = "***@" if parsed.username is not None or parsed.password is not None else ""
    return f"{parsed.scheme}://{credentials}{host}"


def _agent_json(agent: AgentNode, active_leases: int = 0) -> dict[str, Any]:
    online_after = utc_now() - timedelta(seconds=AGENT_ONLINE_SECONDS)
    if agent.revoked_at is not None:
        agent_status = "revoked"
    elif _is_after(agent.last_seen_at, online_after):
        agent_status = "online"
    else:
        agent_status = "offline"
    return {
        "id": agent.id,
        "name": agent.name,
        "status": agent_status,
        "hostname": agent.hostname,
        "platform": agent.platform,
        "version": agent.version,
        "capabilities": dict(agent.capabilities or {}),
        "active_leases": active_leases,
        "created_at": _iso(agent.created_at),
        "last_seen_at": _iso(agent.last_seen_at) if agent.last_seen_at else None,
        "revoked_at": _iso(agent.revoked_at) if agent.revoked_at else None,
    }


def _agent_is_online(agent: AgentNode) -> bool:
    online_after = utc_now() - timedelta(seconds=AGENT_ONLINE_SECONDS)
    return agent.revoked_at is None and _is_after(agent.last_seen_at, online_after)


def _lease_json(lease: EnvironmentLease) -> dict[str, Any]:
    return {
        "environment_id": lease.environment_id,
        "environment_name": lease.environment.name,
        "agent_id": lease.agent_id,
        "agent_name": lease.agent.name if lease.agent else "",
        "lease_id": lease.lease_id,
        "fencing_token": lease.fencing_token,
        "acquired_at": _iso(lease.acquired_at) if lease.acquired_at else None,
        "heartbeat_at": _iso(lease.heartbeat_at) if lease.heartbeat_at else None,
        "expires_at": _iso(lease.expires_at) if lease.expires_at else None,
    }


def _task_json(task: RemoteTask, *, include_payload: bool = False) -> dict[str, Any]:
    result = {
        "id": task.id,
        "kind": task.kind,
        "status": task.status,
        "environment_id": task.environment_id,
        "environment_name": task.environment.name,
        "environment_revision": task.environment_revision,
        "agent_id": task.agent_id,
        "agent_name": task.agent.name,
        "result": dict(task.result or {}),
        "error": task.error,
        "created_at": _iso(task.created_at),
        "claimed_at": _iso(task.claimed_at) if task.claimed_at else None,
        "completed_at": _iso(task.completed_at) if task.completed_at else None,
    }
    if include_payload:
        result["payload"] = dict(task.payload or {})
    return result


def _snapshot_json(snapshot: EnvironmentSnapshot) -> dict[str, Any]:
    return {
        "environment_id": snapshot.environment_id,
        "environment_name": snapshot.environment.name,
        "storage_policy": snapshot.environment.storage_policy,
        "version": snapshot.version,
        "fencing_token": snapshot.fencing_token,
        "ciphertext_size": snapshot.ciphertext_size,
        "plaintext_size": snapshot.plaintext_size,
        "ciphertext_sha256": snapshot.ciphertext_sha256,
        "uploaded_by_agent_id": snapshot.uploaded_by_agent_id,
        "uploaded_by_agent_name": (
            snapshot.uploaded_by_agent.name if snapshot.uploaded_by_agent else ""
        ),
        "updated_at": _iso(snapshot.updated_at),
    }


def _audit(
    db: DatabaseSession,
    auth: AuthContext,
    action: str,
    target_type: str,
    target_id: str,
    details: Optional[dict[str, Any]] = None,
) -> None:
    db.add(
        AuditLog(
            organization_id=auth.organization.id,
            actor_id=auth.user.id,
            action=action,
            target_type=target_type,
            target_id=target_id,
            details=details or {},
        )
    )


def create_app(settings: Optional[CloudSettings] = None) -> FastAPI:
    settings = settings or CloudSettings.from_env()
    engine = create_database_engine(settings.database_url)
    initialize_database(engine)
    session_factory = create_session_factory(engine)
    assets_dir = settings.assets_dir or Path(__file__).with_name("ui")
    if settings.snapshot_dir is not None:
        snapshot_dir = settings.snapshot_dir.resolve()
    elif settings.database_url.startswith("sqlite:///"):
        database_path = Path(settings.database_url[len("sqlite:///"):]).resolve()
        snapshot_dir = database_path.parent / "snapshots"
    else:
        raise ValueError("snapshot_dir is required for non-SQLite cloud databases")
    snapshot_dir.mkdir(parents=True, exist_ok=True)
    try:
        snapshot_dir.chmod(0o700)
    except OSError:
        pass
    extension_dir = (
        settings.extension_dir.resolve()
        if settings.extension_dir is not None
        else snapshot_dir.parent / "extensions"
    )
    extension_dir.mkdir(parents=True, exist_ok=True)
    try:
        extension_dir.chmod(0o700)
    except OSError:
        pass
    snapshot_master_key = settings.snapshot_master_key or hashlib.sha256(
        f"cloakbrowser:snapshot-master:{settings.secret_key}".encode("utf-8")
    ).digest()
    if len(snapshot_master_key) != 32:
        raise ValueError("snapshot_master_key must contain exactly 32 bytes")
    if settings.max_snapshot_bytes < 16 * 1024 * 1024:
        raise ValueError("max_snapshot_bytes must be at least 16 MiB")
    if settings.max_organization_snapshot_bytes < settings.max_snapshot_bytes:
        raise ValueError(
            "max_organization_snapshot_bytes must be at least max_snapshot_bytes"
        )
    if settings.max_extension_bytes < 1024 * 1024:
        raise ValueError("max_extension_bytes must be at least 1 MiB")
    if settings.max_organization_extension_bytes < settings.max_extension_bytes:
        raise ValueError(
            "max_organization_extension_bytes must be at least max_extension_bytes"
        )

    app = FastAPI(
        title="CloakBrowser Cloud",
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
    )
    app.state.settings = settings
    app.state.engine = engine
    app.state.session_factory = session_factory
    app.state.snapshot_dir = snapshot_dir
    app.state.extension_dir = extension_dir

    @app.middleware("http")
    async def security_middleware(request: Request, call_next: Callable[..., Any]) -> Response:
        raw_length = request.headers.get("content-length")
        request_limit = (
            settings.max_snapshot_bytes
            if request.method == "PUT"
            and request.url.path.startswith("/api/agent/snapshots/")
            and request.url.path.endswith("/content")
            else (
                settings.max_extension_bytes
                if request.method == "PUT"
                and request.url.path.startswith("/api/extensions/")
                and request.url.path.endswith("/content")
                else MAX_REQUEST_BYTES
            )
        )
        if raw_length:
            try:
                if int(raw_length) > request_limit:
                    return Response("request body is too large", status_code=413)
            except ValueError:
                return Response("invalid content length", status_code=400)
        response = await call_next(request)
        response.headers["Cache-Control"] = "no-store"
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; "
            "connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'"
        )
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
        return response

    def get_db() -> Generator[DatabaseSession, None, None]:
        db = session_factory()
        try:
            yield db
        finally:
            db.close()

    def current_auth(
        request: Request,
        db: DatabaseSession = Depends(get_db),
    ) -> AuthContext:
        raw_token = request.cookies.get(SESSION_COOKIE, "")
        if not raw_token:
            raise HTTPException(status_code=401, detail="authentication required")
        cloud_session = db.get(Session, session_digest(raw_token))
        if cloud_session is None or _session_expired(cloud_session.expires_at):
            if cloud_session is not None:
                db.delete(cloud_session)
                db.commit()
            raise HTTPException(status_code=401, detail="session expired")
        user = db.get(User, cloud_session.user_id)
        membership = db.scalar(
            select(Membership)
            .options(joinedload(Membership.organization))
            .where(
                Membership.user_id == cloud_session.user_id,
                Membership.organization_id == cloud_session.organization_id,
            )
        )
        if user is None or not user.is_active or membership is None:
            raise HTTPException(status_code=401, detail="session is no longer valid")
        return AuthContext(
            user=user,
            organization=membership.organization,
            membership=membership,
            session=cloud_session,
            raw_token=raw_token,
        )

    def mutation_auth(
        request: Request,
        auth: AuthContext = Depends(current_auth),
    ) -> AuthContext:
        supplied = request.headers.get("X-CSRF-Token", "")
        if not csrf_matches(settings.secret_key, auth.raw_token, supplied):
            raise HTTPException(status_code=403, detail="invalid CSRF token")
        return auth

    def current_agent(
        request: Request,
        db: DatabaseSession = Depends(get_db),
    ) -> AgentAuthContext:
        scheme, separator, raw_token = request.headers.get("Authorization", "").partition(" ")
        if (
            not separator
            or scheme.lower() != "bearer"
            or not raw_token.startswith(AGENT_TOKEN_PREFIX)
            or len(raw_token) > 160
        ):
            raise HTTPException(status_code=401, detail="invalid agent credentials")
        agent = db.scalar(
            select(AgentNode).where(
                AgentNode.token_digest == agent_token_digest(raw_token)
            )
        )
        if agent is None or agent.revoked_at is not None:
            raise HTTPException(status_code=401, detail="invalid agent credentials")
        return AgentAuthContext(agent=agent, raw_token=raw_token)

    def permission(name: str, *, mutation: bool = False) -> Callable[..., AuthContext]:
        dependency = mutation_auth if mutation else current_auth

        def require(auth: AuthContext = Depends(dependency)) -> AuthContext:
            if not has_permission(auth.membership.role, name):
                raise HTTPException(status_code=403, detail="permission denied")
            return auth

        return require

    def issue_session(
        db: DatabaseSession,
        response: Response,
        user: User,
        organization_id: str,
    ) -> tuple[str, Session]:
        raw_token = new_session_token()
        cloud_session = Session(
            token_digest=session_digest(raw_token),
            user_id=user.id,
            organization_id=organization_id,
            expires_at=utc_now() + timedelta(seconds=settings.session_ttl_seconds),
        )
        db.add(cloud_session)
        db.commit()
        response.set_cookie(
            SESSION_COOKIE,
            raw_token,
            max_age=settings.session_ttl_seconds,
            httponly=True,
            secure=settings.cookie_secure,
            samesite="lax",
            path="/",
        )
        return raw_token, cloud_session

    @app.get("/api/health")
    def health() -> dict[str, str]:
        return {"status": "ok"}

    @app.post("/api/auth/register", status_code=status.HTTP_201_CREATED)
    def register(
        payload: RegisterRequest,
        response: Response,
        db: DatabaseSession = Depends(get_db),
    ) -> dict[str, Any]:
        if db.scalar(select(User.id).where(User.email == payload.email)):
            raise HTTPException(status_code=409, detail="an account with this email already exists")
        user = User(
            email=payload.email,
            display_name=payload.display_name,
            password_hash=hash_password(payload.password),
        )
        db.add(user)
        db.flush()
        organization = Organization(
            name=payload.organization_name,
            slug=_unique_slug(db, payload.organization_name),
            created_by=user.id,
        )
        db.add(organization)
        db.flush()
        membership = Membership(
            organization_id=organization.id,
            user_id=user.id,
            role="owner",
        )
        db.add(membership)
        db.flush()
        db.add(
            AuditLog(
                organization_id=organization.id,
                actor_id=user.id,
                action="organization.created",
                target_type="organization",
                target_id=organization.id,
                details={"name": organization.name},
            )
        )
        try:
            db.commit()
        except IntegrityError as exc:
            db.rollback()
            raise HTTPException(
                status_code=409,
                detail="account or organization already exists",
            ) from exc
        raw_token, _ = issue_session(db, response, user, organization.id)
        return {
            "user": _user_json(user),
            "organization": _organization_json(organization, membership.role),
            "csrf_token": csrf_token(settings.secret_key, raw_token),
        }

    @app.post("/api/auth/login")
    def login(
        payload: LoginRequest,
        response: Response,
        db: DatabaseSession = Depends(get_db),
    ) -> dict[str, Any]:
        user = db.scalar(select(User).where(User.email == payload.email))
        if (
            user is None
            or not user.is_active
            or not verify_password(user.password_hash, payload.password)
        ):
            raise HTTPException(status_code=401, detail="invalid email or password")
        membership = db.scalar(
            select(Membership)
            .options(joinedload(Membership.organization))
            .where(Membership.user_id == user.id)
            .order_by(Membership.created_at)
        )
        if membership is None:
            raise HTTPException(status_code=403, detail="account does not belong to a team")
        raw_token, _ = issue_session(db, response, user, membership.organization_id)
        return {
            "user": _user_json(user),
            "organization": _organization_json(membership.organization, membership.role),
            "csrf_token": csrf_token(settings.secret_key, raw_token),
        }

    @app.post("/api/auth/logout", status_code=status.HTTP_204_NO_CONTENT)
    def logout(
        response: Response,
        auth: AuthContext = Depends(mutation_auth),
        db: DatabaseSession = Depends(get_db),
    ) -> Response:
        db.delete(auth.session)
        db.commit()
        response.delete_cookie(SESSION_COOKIE, path="/")
        response.status_code = status.HTTP_204_NO_CONTENT
        return response

    @app.get("/api/session")
    def session_info(
        auth: AuthContext = Depends(current_auth),
        db: DatabaseSession = Depends(get_db),
    ) -> dict[str, Any]:
        memberships = db.scalars(
            select(Membership)
            .options(joinedload(Membership.organization))
            .where(Membership.user_id == auth.user.id)
            .order_by(Membership.created_at)
        ).all()
        return {
            "user": _user_json(auth.user),
            "organization": _organization_json(auth.organization, auth.membership.role),
            "organizations": [
                _organization_json(item.organization, item.role) for item in memberships
            ],
            "permissions": sorted(ROLE_PERMISSIONS[auth.membership.role]),
            "csrf_token": csrf_token(settings.secret_key, auth.raw_token),
        }

    @app.post("/api/session/organization")
    def switch_organization(
        payload: OrganizationSwitch,
        auth: AuthContext = Depends(mutation_auth),
        db: DatabaseSession = Depends(get_db),
    ) -> dict[str, Any]:
        membership = db.scalar(
            select(Membership)
            .options(joinedload(Membership.organization))
            .where(
                Membership.user_id == auth.user.id,
                Membership.organization_id == payload.organization_id,
            )
        )
        if membership is None:
            raise HTTPException(status_code=404, detail="team not found")
        auth.session.organization_id = membership.organization_id
        db.commit()
        return {"organization": _organization_json(membership.organization, membership.role)}

    @app.post("/api/organizations", status_code=status.HTTP_201_CREATED)
    def create_organization(
        payload: OrganizationCreate,
        auth: AuthContext = Depends(mutation_auth),
        db: DatabaseSession = Depends(get_db),
    ) -> dict[str, Any]:
        organization = Organization(
            name=payload.name,
            slug=_unique_slug(db, payload.name),
            created_by=auth.user.id,
        )
        db.add(organization)
        db.flush()
        membership = Membership(
            organization_id=organization.id,
            user_id=auth.user.id,
            role="owner",
        )
        db.add(membership)
        auth.session.organization_id = organization.id
        db.add(
            AuditLog(
                organization_id=organization.id,
                actor_id=auth.user.id,
                action="organization.created",
                target_type="organization",
                target_id=organization.id,
                details={"name": organization.name},
            )
        )
        try:
            db.commit()
        except IntegrityError as exc:
            db.rollback()
            raise HTTPException(status_code=409, detail="team name already exists") from exc
        return {"organization": _organization_json(organization, membership.role)}

    @app.get("/api/members")
    def list_members(
        auth: AuthContext = Depends(current_auth),
        db: DatabaseSession = Depends(get_db),
    ) -> dict[str, Any]:
        memberships = db.scalars(
            select(Membership)
            .options(joinedload(Membership.user))
            .where(Membership.organization_id == auth.organization.id)
            .order_by(Membership.created_at)
        ).all()
        return {"members": [_member_json(item) for item in memberships]}

    @app.post("/api/members", status_code=status.HTTP_201_CREATED)
    def add_member(
        payload: MemberCreate,
        auth: AuthContext = Depends(permission("members.manage", mutation=True)),
        db: DatabaseSession = Depends(get_db),
    ) -> dict[str, Any]:
        if payload.role == "owner" and auth.membership.role != "owner":
            raise HTTPException(status_code=403, detail="only owners can assign the owner role")
        user = db.scalar(select(User).where(User.email == payload.email))
        if user is None:
            raise HTTPException(status_code=404, detail="user must register before being added")
        existing = db.scalar(
            select(Membership).where(
                Membership.organization_id == auth.organization.id,
                Membership.user_id == user.id,
            )
        )
        if existing:
            raise HTTPException(status_code=409, detail="user is already a team member")
        membership = Membership(
            organization_id=auth.organization.id,
            user_id=user.id,
            role=payload.role,
        )
        db.add(membership)
        try:
            db.flush()
        except IntegrityError as exc:
            db.rollback()
            raise HTTPException(status_code=409, detail="user is already a team member") from exc
        membership.user = user
        _audit(
            db,
            auth,
            "member.added",
            "membership",
            membership.id,
            {"user_id": user.id, "role": payload.role},
        )
        db.commit()
        return {"member": _member_json(membership)}

    def get_managed_membership(
        db: DatabaseSession,
        auth: AuthContext,
        membership_id: str,
    ) -> Membership:
        target = db.scalar(
            select(Membership)
            .options(joinedload(Membership.user))
            .where(
                Membership.id == membership_id,
                Membership.organization_id == auth.organization.id,
            )
        )
        if target is None:
            raise HTTPException(status_code=404, detail="member not found")
        if target.role == "owner" and auth.membership.role != "owner":
            raise HTTPException(status_code=403, detail="only owners can manage owners")
        return target

    def ensure_owner_remains(db: DatabaseSession, auth: AuthContext, target: Membership) -> None:
        if target.role != "owner":
            return
        db.scalar(
            select(Organization)
            .where(Organization.id == auth.organization.id)
            .with_for_update()
        )
        owner_count = db.scalar(
            select(func.count(Membership.id)).where(
                Membership.organization_id == auth.organization.id,
                Membership.role == "owner",
            )
        )
        if int(owner_count or 0) <= 1:
            raise HTTPException(status_code=409, detail="the team must keep at least one owner")

    @app.patch("/api/members/{membership_id}")
    def update_member(
        membership_id: str,
        payload: MemberUpdate,
        auth: AuthContext = Depends(permission("members.manage", mutation=True)),
        db: DatabaseSession = Depends(get_db),
    ) -> dict[str, Any]:
        target = get_managed_membership(db, auth, membership_id)
        if payload.role == "owner" and auth.membership.role != "owner":
            raise HTTPException(status_code=403, detail="only owners can assign the owner role")
        if target.role == "owner" and payload.role != "owner":
            ensure_owner_remains(db, auth, target)
        old_role = target.role
        target.role = payload.role
        _audit(
            db,
            auth,
            "member.role_changed",
            "membership",
            target.id,
            {"from": old_role, "to": payload.role, "user_id": target.user_id},
        )
        db.commit()
        return {"member": _member_json(target)}

    @app.delete("/api/members/{membership_id}", status_code=status.HTTP_204_NO_CONTENT)
    def remove_member(
        membership_id: str,
        auth: AuthContext = Depends(permission("members.manage", mutation=True)),
        db: DatabaseSession = Depends(get_db),
    ) -> Response:
        target = get_managed_membership(db, auth, membership_id)
        if target.user_id == auth.user.id:
            raise HTTPException(
                status_code=409,
                detail="current users cannot remove themselves from the active team",
            )
        ensure_owner_remains(db, auth, target)
        target_user_id = target.user_id
        db.delete(target)
        _audit(
            db,
            auth,
            "member.removed",
            "membership",
            target.id,
            {"user_id": target_user_id},
        )
        db.commit()
        return Response(status_code=status.HTTP_204_NO_CONTENT)

    def require_managed_agent(
        db: DatabaseSession,
        organization_id: str,
        agent_id: str,
    ) -> AgentNode:
        agent = db.scalar(
            select(AgentNode).where(
                AgentNode.id == agent_id,
                AgentNode.organization_id == organization_id,
            )
        )
        if agent is None:
            raise HTTPException(status_code=404, detail="agent not found")
        return agent

    @app.get("/api/agents")
    def list_agents(
        auth: AuthContext = Depends(permission("agents.read")),
        db: DatabaseSession = Depends(get_db),
    ) -> dict[str, Any]:
        agents = db.scalars(
            select(AgentNode)
            .where(AgentNode.organization_id == auth.organization.id)
            .order_by(AgentNode.created_at)
        ).all()
        now = utc_now()
        lease_counts = dict(
            db.execute(
                select(EnvironmentLease.agent_id, func.count(EnvironmentLease.environment_id))
                .where(
                    EnvironmentLease.organization_id == auth.organization.id,
                    EnvironmentLease.agent_id.is_not(None),
                    EnvironmentLease.lease_token_digest.is_not(None),
                    EnvironmentLease.expires_at.is_not(None),
                    EnvironmentLease.expires_at > now,
                )
                .group_by(EnvironmentLease.agent_id)
            ).all()
        )
        return {
            "agents": [
                _agent_json(agent, int(lease_counts.get(agent.id, 0)))
                for agent in agents
            ]
        }

    @app.post("/api/agents", status_code=status.HTTP_201_CREATED)
    def create_agent(
        payload: AgentCreate,
        auth: AuthContext = Depends(permission("agents.manage", mutation=True)),
        db: DatabaseSession = Depends(get_db),
    ) -> dict[str, Any]:
        raw_token = new_agent_token()
        agent = AgentNode(
            organization_id=auth.organization.id,
            name=payload.name,
            token_digest=agent_token_digest(raw_token),
            created_by=auth.user.id,
        )
        db.add(agent)
        try:
            db.flush()
        except IntegrityError as exc:
            db.rollback()
            raise HTTPException(status_code=409, detail="agent name already exists") from exc
        _audit(db, auth, "agent.created", "agent", agent.id, {"name": agent.name})
        db.commit()
        return {"agent": _agent_json(agent), "agent_token": raw_token}

    @app.post("/api/agents/{agent_id}/rotate-token")
    def rotate_agent_token(
        agent_id: str,
        auth: AuthContext = Depends(permission("agents.manage", mutation=True)),
        db: DatabaseSession = Depends(get_db),
    ) -> dict[str, Any]:
        agent = require_managed_agent(db, auth.organization.id, agent_id)
        if agent.revoked_at is not None:
            raise HTTPException(status_code=409, detail="revoked agents cannot rotate tokens")
        raw_token = new_agent_token()
        agent.token_digest = agent_token_digest(raw_token)
        _audit(db, auth, "agent.token_rotated", "agent", agent.id)
        db.commit()
        return {"agent": _agent_json(agent), "agent_token": raw_token}

    @app.delete("/api/agents/{agent_id}", status_code=status.HTTP_204_NO_CONTENT)
    def revoke_agent(
        agent_id: str,
        auth: AuthContext = Depends(permission("agents.manage", mutation=True)),
        db: DatabaseSession = Depends(get_db),
    ) -> Response:
        agent = require_managed_agent(db, auth.organization.id, agent_id)
        if agent.revoked_at is None:
            now = utc_now()
            agent.revoked_at = now
            released = db.execute(
                update(EnvironmentLease)
                .where(
                    EnvironmentLease.organization_id == auth.organization.id,
                    EnvironmentLease.agent_id == agent.id,
                    EnvironmentLease.lease_token_digest.is_not(None),
                )
                .values(
                    agent_id=None,
                    lease_id=None,
                    lease_token_digest=None,
                    heartbeat_at=now,
                    expires_at=now,
                )
            )
            cancelled = db.execute(
                update(RemoteTask)
                .where(
                    RemoteTask.organization_id == auth.organization.id,
                    RemoteTask.agent_id == agent.id,
                    RemoteTask.status.in_(("pending", "claimed")),
                )
                .values(
                    status="failed",
                    dedupe_key=None,
                    claim_token_digest=None,
                    error="agent was revoked before the task completed",
                    completed_at=now,
                    updated_at=now,
                )
            )
            _audit(
                db,
                auth,
                "agent.revoked",
                "agent",
                agent.id,
                {
                    "leases_released": released.rowcount,
                    "tasks_cancelled": cancelled.rowcount,
                },
            )
            db.commit()
        return Response(status_code=status.HTTP_204_NO_CONTENT)

    @app.get("/api/leases")
    def list_leases(
        auth: AuthContext = Depends(permission("leases.read")),
        db: DatabaseSession = Depends(get_db),
    ) -> dict[str, Any]:
        now = utc_now()
        leases = db.scalars(
            select(EnvironmentLease)
            .options(
                joinedload(EnvironmentLease.environment),
                joinedload(EnvironmentLease.agent),
            )
            .where(
                EnvironmentLease.organization_id == auth.organization.id,
                EnvironmentLease.agent_id.is_not(None),
                EnvironmentLease.lease_token_digest.is_not(None),
                EnvironmentLease.expires_at.is_not(None),
                EnvironmentLease.expires_at > now,
            )
            .order_by(EnvironmentLease.expires_at)
        ).all()
        return {"leases": [_lease_json(lease) for lease in leases]}

    def active_environment_lease(
        db: DatabaseSession,
        organization_id: str,
        environment_id: str,
    ) -> Optional[EnvironmentLease]:
        now = utc_now()
        return db.scalar(
            select(EnvironmentLease)
            .options(
                joinedload(EnvironmentLease.environment),
                joinedload(EnvironmentLease.agent),
            )
            .where(
                EnvironmentLease.environment_id == environment_id,
                EnvironmentLease.organization_id == organization_id,
                EnvironmentLease.agent_id.is_not(None),
                EnvironmentLease.lease_token_digest.is_not(None),
                EnvironmentLease.expires_at.is_not(None),
                EnvironmentLease.expires_at > now,
            )
        )

    def snapshot_object_path(object_key: str) -> Path:
        candidate = (snapshot_dir / object_key).resolve()
        try:
            candidate.relative_to(snapshot_dir)
        except ValueError as exc:
            raise HTTPException(status_code=500, detail="snapshot object path is invalid") from exc
        return candidate

    def extension_object_path(object_key: str) -> Path:
        candidate = (extension_dir / object_key).resolve()
        try:
            candidate.relative_to(extension_dir)
        except ValueError as exc:
            raise HTTPException(status_code=500, detail="extension object path is invalid") from exc
        return candidate

    def require_extension_packages(
        db: DatabaseSession,
        organization_id: str,
        extension_ids: list[str],
    ) -> list[ExtensionPackage]:
        if not extension_ids:
            return []
        packages = db.scalars(
            select(ExtensionPackage).where(
                ExtensionPackage.organization_id == organization_id,
                ExtensionPackage.id.in_(extension_ids),
                ExtensionPackage.status == "ready",
            )
        ).all()
        by_id = {package.id: package for package in packages}
        if len(by_id) != len(extension_ids):
            raise HTTPException(
                status_code=422,
                detail="one or more extension packages are unavailable",
            )
        return [by_id[extension_id] for extension_id in extension_ids]

    def set_environment_proxy(
        db: DatabaseSession,
        auth: AuthContext,
        environment_id: str,
        proxy: str,
    ) -> None:
        secret = db.get(EnvironmentSecret, environment_id)
        next_version = (secret.version if secret is not None else 0) + 1
        envelope = (
            encrypt_environment_secret(
                snapshot_master_key,
                auth.organization.id,
                environment_id,
                "proxy",
                next_version,
                proxy,
            )
            if proxy
            else None
        )
        if secret is None:
            secret = EnvironmentSecret(
                environment_id=environment_id,
                organization_id=auth.organization.id,
                proxy_envelope=envelope,
                proxy_masked=_mask_proxy(proxy) if proxy else "",
                version=next_version,
                updated_by=auth.user.id,
            )
            db.add(secret)
        else:
            secret.proxy_envelope = envelope
            secret.proxy_masked = _mask_proxy(proxy) if proxy else ""
            secret.version = next_version
            secret.updated_by = auth.user.id
            secret.updated_at = utc_now()

    @app.get("/api/extensions")
    def list_extensions(
        auth: AuthContext = Depends(permission("extensions.read")),
        db: DatabaseSession = Depends(get_db),
    ) -> dict[str, Any]:
        packages = db.scalars(
            select(ExtensionPackage)
            .where(ExtensionPackage.organization_id == auth.organization.id)
            .order_by(ExtensionPackage.created_at.desc())
        ).all()
        return {"extensions": [_extension_json(package) for package in packages]}

    @app.post("/api/extensions", status_code=status.HTTP_201_CREATED)
    def create_extension(
        payload: ExtensionCreate,
        auth: AuthContext = Depends(permission("extensions.manage", mutation=True)),
        db: DatabaseSession = Depends(get_db),
    ) -> dict[str, Any]:
        if payload.content_size > settings.max_extension_bytes:
            raise HTTPException(status_code=413, detail="extension package is too large")
        package = ExtensionPackage(
            organization_id=auth.organization.id,
            name=payload.name,
            version=payload.version,
            content_sha256=payload.content_sha256,
            content_size=payload.content_size,
            created_by=auth.user.id,
        )
        db.add(package)
        try:
            db.flush()
        except IntegrityError as exc:
            db.rollback()
            raise HTTPException(
                status_code=409,
                detail="an extension with this name and version already exists",
            ) from exc
        _audit(
            db,
            auth,
            "extension.created",
            "extension",
            package.id,
            {"name": package.name, "version": package.version},
        )
        db.commit()
        return {"extension": _extension_json(package)}

    @app.put("/api/extensions/{extension_id}/content")
    async def upload_extension_content(
        extension_id: str,
        request: Request,
        auth: AuthContext = Depends(permission("extensions.manage", mutation=True)),
        db: DatabaseSession = Depends(get_db),
    ) -> dict[str, Any]:
        package = db.scalar(
            select(ExtensionPackage).where(
                ExtensionPackage.id == extension_id,
                ExtensionPackage.organization_id == auth.organization.id,
            )
        )
        if package is None:
            raise HTTPException(status_code=404, detail="extension package not found")
        if package.status != "pending" or package.object_key:
            raise HTTPException(status_code=409, detail="extension package is already uploaded")
        content_type = request.headers.get("content-type", "").split(";", 1)[0].strip().lower()
        if content_type not in {"application/zip", "application/x-zip-compressed"}:
            raise HTTPException(status_code=415, detail="extension content must be a ZIP archive")
        descriptor, temporary_name = tempfile.mkstemp(
            prefix=".extension-upload-",
            dir=extension_dir,
        )
        os.close(descriptor)
        temporary_path = Path(temporary_name)
        try:
            temporary_path.chmod(0o600)
        except OSError:
            pass
        digest = hashlib.sha256()
        received = 0
        try:
            with temporary_path.open("wb") as output:
                async for block in request.stream():
                    if not block:
                        continue
                    received += len(block)
                    if received > settings.max_extension_bytes:
                        raise HTTPException(status_code=413, detail="extension package is too large")
                    digest.update(block)
                    output.write(block)
            if received != package.content_size:
                raise HTTPException(status_code=422, detail="extension package size does not match")
            if digest.hexdigest() != package.content_sha256:
                raise HTTPException(status_code=422, detail="extension package SHA-256 does not match")
            try:
                manifest = inspect_extension_zip(
                    temporary_path,
                    max_unpacked_bytes=max(512 * 1024 * 1024, settings.max_extension_bytes * 8),
                )
            except ExtensionPackageError as exc:
                raise HTTPException(status_code=422, detail=str(exc)) from exc
            if manifest.get("version") != package.version:
                raise HTTPException(
                    status_code=422,
                    detail="extension manifest version does not match the package version",
                )
            db.execute(
                select(Organization.id)
                .where(Organization.id == auth.organization.id)
                .with_for_update()
            ).scalar_one()
            current_bytes = db.scalar(
                select(func.coalesce(func.sum(ExtensionPackage.content_size), 0)).where(
                    ExtensionPackage.organization_id == auth.organization.id,
                    ExtensionPackage.status == "ready",
                )
            )
            if int(current_bytes or 0) + received > settings.max_organization_extension_bytes:
                raise HTTPException(
                    status_code=413,
                    detail="organization extension package quota exceeded",
                )
            object_key = (
                f"{auth.organization.id}/{package.id}/"
                f"{package.content_sha256[:16]}-{secrets.token_hex(6)}.zip"
            )
            destination = extension_object_path(object_key)
            destination.parent.mkdir(parents=True, exist_ok=True)
            os.replace(temporary_path, destination)
            package.object_key = object_key
            package.status = "ready"
            package.manifest = manifest
            package.updated_at = utc_now()
            _audit(
                db,
                auth,
                "extension.uploaded",
                "extension",
                package.id,
                {"size": received, "sha256": package.content_sha256},
            )
            try:
                db.commit()
            except Exception:
                db.rollback()
                destination.unlink(missing_ok=True)
                raise
        finally:
            temporary_path.unlink(missing_ok=True)
        return {"extension": _extension_json(package)}

    @app.delete("/api/extensions/{extension_id}", status_code=status.HTTP_204_NO_CONTENT)
    def delete_extension(
        extension_id: str,
        auth: AuthContext = Depends(permission("extensions.manage", mutation=True)),
        db: DatabaseSession = Depends(get_db),
    ) -> Response:
        package = db.scalar(
            select(ExtensionPackage).where(
                ExtensionPackage.id == extension_id,
                ExtensionPackage.organization_id == auth.organization.id,
            )
        )
        if package is None:
            raise HTTPException(status_code=404, detail="extension package not found")
        assigned = db.scalar(
            select(func.count()).select_from(EnvironmentExtension).where(
                EnvironmentExtension.extension_id == package.id
            )
        )
        if int(assigned or 0):
            raise HTTPException(
                status_code=409,
                detail="remove this extension from all environments before deleting it",
            )
        object_key = package.object_key
        _audit(
            db,
            auth,
            "extension.deleted",
            "extension",
            package.id,
            {"name": package.name, "version": package.version},
        )
        db.delete(package)
        db.commit()
        if object_key:
            try:
                extension_object_path(object_key).unlink(missing_ok=True)
            except OSError:
                pass
        return Response(status_code=status.HTTP_204_NO_CONTENT)

    @app.post("/api/agent/environments/{environment_id}/runtime-assets")
    def agent_runtime_assets(
        environment_id: str,
        proof: AgentLeaseProof,
        auth: AgentAuthContext = Depends(current_agent),
        db: DatabaseSession = Depends(get_db),
    ) -> dict[str, Any]:
        environment = db.scalar(
            select(Environment).where(
                Environment.id == environment_id,
                Environment.organization_id == auth.agent.organization_id,
            )
        )
        if environment is None:
            raise HTTPException(status_code=404, detail="environment not found")
        require_snapshot_lease(db, auth, environment_id, proof)
        proxy = ""
        secret = environment.secret
        if secret is not None and secret.proxy_envelope:
            try:
                proxy = decrypt_environment_secret(
                    snapshot_master_key,
                    auth.agent.organization_id,
                    environment_id,
                    "proxy",
                    secret.version,
                    secret.proxy_envelope,
                )
            except SecretCryptoError as exc:
                raise HTTPException(
                    status_code=503,
                    detail="environment runtime secrets are unavailable",
                ) from exc
        extensions = [
            {
                "id": link.extension.id,
                "name": link.extension.name,
                "version": link.extension.version,
                "content_sha256": link.extension.content_sha256,
                "content_size": link.extension.content_size,
            }
            for link in environment.extension_links
            if link.extension.status == "ready" and link.extension.object_key
        ]
        return {
            "proxy": proxy,
            "proxy_version": secret.version if secret else 0,
            "extensions": extensions,
            "max_extension_bytes": settings.max_extension_bytes,
            "max_extension_unpacked_bytes": max(
                512 * 1024 * 1024,
                settings.max_extension_bytes * 8,
            ),
        }

    @app.post(
        "/api/agent/environments/{environment_id}/extensions/{extension_id}/download"
    )
    def download_agent_extension(
        environment_id: str,
        extension_id: str,
        proof: AgentLeaseProof,
        auth: AgentAuthContext = Depends(current_agent),
        db: DatabaseSession = Depends(get_db),
    ) -> FileResponse:
        require_snapshot_lease(db, auth, environment_id, proof)
        package = db.scalar(
            select(ExtensionPackage)
            .join(
                EnvironmentExtension,
                EnvironmentExtension.extension_id == ExtensionPackage.id,
            )
            .join(Environment, Environment.id == EnvironmentExtension.environment_id)
            .where(
                Environment.id == environment_id,
                Environment.organization_id == auth.agent.organization_id,
                ExtensionPackage.id == extension_id,
                ExtensionPackage.organization_id == auth.agent.organization_id,
                ExtensionPackage.status == "ready",
                ExtensionPackage.object_key.is_not(None),
            )
        )
        if package is None or not package.object_key:
            raise HTTPException(status_code=404, detail="assigned extension package not found")
        path = extension_object_path(package.object_key)
        if not path.is_file():
            raise HTTPException(status_code=503, detail="extension package content is unavailable")
        return FileResponse(
            path,
            media_type="application/zip",
            filename=f"{package.name}-{package.version}.zip",
            headers={
                "X-CB-Extension-SHA256": package.content_sha256,
                "X-CB-Extension-Size": str(package.content_size),
            },
        )

    def require_snapshot_environment(
        db: DatabaseSession,
        organization_id: str,
        environment_id: str,
    ) -> Environment:
        environment = db.scalar(
            select(Environment).where(
                Environment.id == environment_id,
                Environment.organization_id == organization_id,
            )
        )
        if environment is None:
            raise HTTPException(status_code=404, detail="environment not found")
        if environment.storage_policy == "local":
            raise HTTPException(
                status_code=409,
                detail="environment storage policy does not enable cloud snapshots",
            )
        return environment

    def require_snapshot_lease(
        db: DatabaseSession,
        auth: AgentAuthContext,
        environment_id: str,
        proof: AgentLeaseProof,
    ) -> EnvironmentLease:
        now = utc_now()
        lease = db.scalar(
            select(EnvironmentLease).where(
                EnvironmentLease.environment_id == environment_id,
                EnvironmentLease.organization_id == auth.agent.organization_id,
                EnvironmentLease.agent_id == auth.agent.id,
                EnvironmentLease.lease_id == proof.lease_id,
                EnvironmentLease.fencing_token == proof.fencing_token,
                EnvironmentLease.lease_token_digest
                == lease_token_digest(proof.lease_token),
                EnvironmentLease.expires_at.is_not(None),
                EnvironmentLease.expires_at > now,
            )
        )
        if lease is None:
            raise HTTPException(status_code=409, detail="lease is stale or expired")
        return lease

    def snapshot_proof_from_headers(request: Request) -> AgentLeaseProof:
        try:
            fencing_token = int(request.headers.get("X-CB-Fencing-Token", ""))
            return AgentLeaseProof.model_validate(
                {
                    "lease_id": request.headers.get("X-CB-Lease-Id", ""),
                    "lease_token": request.headers.get("X-CB-Lease-Token", ""),
                    "fencing_token": fencing_token,
                }
            )
        except (TypeError, ValueError) as exc:
            raise HTTPException(status_code=422, detail="snapshot lease headers are invalid") from exc

    def ensure_snapshot_state(
        db: DatabaseSession,
        organization_id: str,
        environment_id: str,
    ) -> EnvironmentSnapshot:
        snapshot = db.get(EnvironmentSnapshot, environment_id)
        if snapshot is not None:
            return snapshot
        raw_key = secrets.token_bytes(32)
        snapshot = EnvironmentSnapshot(
            environment_id=environment_id,
            organization_id=organization_id,
            key_envelope=wrap_snapshot_key(
                snapshot_master_key,
                organization_id,
                environment_id,
                raw_key,
            ),
        )
        db.add(snapshot)
        try:
            db.commit()
        except IntegrityError:
            db.rollback()
            snapshot = db.get(EnvironmentSnapshot, environment_id)
            if snapshot is None:
                raise
        return snapshot

    @app.get("/api/snapshots")
    def list_snapshots(
        auth: AuthContext = Depends(permission("snapshots.read")),
        db: DatabaseSession = Depends(get_db),
    ) -> dict[str, Any]:
        snapshots = db.scalars(
            select(EnvironmentSnapshot)
            .options(
                joinedload(EnvironmentSnapshot.environment),
                joinedload(EnvironmentSnapshot.uploaded_by_agent),
            )
            .where(
                EnvironmentSnapshot.organization_id == auth.organization.id,
                EnvironmentSnapshot.version > 0,
            )
            .order_by(EnvironmentSnapshot.updated_at.desc())
        ).all()
        return {"snapshots": [_snapshot_json(item) for item in snapshots]}

    @app.post("/api/agent/snapshots/{environment_id}")
    def prepare_agent_snapshot(
        environment_id: str,
        payload: AgentLeaseProof,
        auth: AgentAuthContext = Depends(current_agent),
        db: DatabaseSession = Depends(get_db),
    ) -> dict[str, Any]:
        environment = require_snapshot_environment(
            db, auth.agent.organization_id, environment_id
        )
        require_snapshot_lease(db, auth, environment_id, payload)
        snapshot = ensure_snapshot_state(
            db, auth.agent.organization_id, environment_id
        )
        try:
            raw_key = unwrap_snapshot_key(
                snapshot_master_key,
                auth.agent.organization_id,
                environment_id,
                snapshot.key_envelope,
            )
        except SnapshotError as exc:
            raise HTTPException(status_code=500, detail=str(exc)) from exc
        return {
            "environment_id": environment.id,
            "storage_policy": environment.storage_policy,
            "version": snapshot.version,
            "ciphertext_size": snapshot.ciphertext_size,
            "plaintext_size": snapshot.plaintext_size,
            "ciphertext_sha256": snapshot.ciphertext_sha256,
            "updated_at": _iso(snapshot.updated_at) if snapshot.version else None,
            "encryption_key": encode_snapshot_key(raw_key),
            "max_snapshot_bytes": settings.max_snapshot_bytes,
        }

    @app.post("/api/agent/snapshots/{environment_id}/download")
    def download_agent_snapshot(
        environment_id: str,
        payload: AgentLeaseProof,
        auth: AgentAuthContext = Depends(current_agent),
        db: DatabaseSession = Depends(get_db),
    ) -> Response:
        require_snapshot_environment(db, auth.agent.organization_id, environment_id)
        require_snapshot_lease(db, auth, environment_id, payload)
        snapshot = db.scalar(
            select(EnvironmentSnapshot).where(
                EnvironmentSnapshot.environment_id == environment_id,
                EnvironmentSnapshot.organization_id == auth.agent.organization_id,
                EnvironmentSnapshot.version > 0,
            )
        )
        if snapshot is None or not snapshot.object_key:
            raise HTTPException(status_code=404, detail="cloud snapshot not found")
        path = snapshot_object_path(snapshot.object_key)
        if not path.is_file():
            raise HTTPException(status_code=503, detail="cloud snapshot content is unavailable")
        return FileResponse(
            path,
            media_type="application/vnd.cloakbrowser.snapshot",
            filename=f"{environment_id}-v{snapshot.version}.cbsnap",
            headers={
                "X-CB-Snapshot-Version": str(snapshot.version),
                "X-CB-Snapshot-SHA256": snapshot.ciphertext_sha256 or "",
            },
        )

    @app.put("/api/agent/snapshots/{environment_id}/content")
    async def upload_agent_snapshot(
        environment_id: str,
        request: Request,
        auth: AgentAuthContext = Depends(current_agent),
        db: DatabaseSession = Depends(get_db),
    ) -> dict[str, Any]:
        proof = snapshot_proof_from_headers(request)
        require_snapshot_environment(db, auth.agent.organization_id, environment_id)
        require_snapshot_lease(db, auth, environment_id, proof)
        content_type = request.headers.get("content-type", "").split(";", 1)[0].strip().lower()
        if content_type != "application/vnd.cloakbrowser.snapshot":
            raise HTTPException(
                status_code=415,
                detail="snapshot content type must be application/vnd.cloakbrowser.snapshot",
            )
        try:
            expected_version = int(
                request.headers.get("X-CB-Snapshot-Expected-Version", "")
            )
            plaintext_size = int(
                request.headers.get("X-CB-Snapshot-Plaintext-Size", "")
            )
        except ValueError as exc:
            raise HTTPException(status_code=422, detail="snapshot version or size is invalid") from exc
        expected_sha256 = request.headers.get("X-CB-Snapshot-SHA256", "").lower()
        if (
            expected_version < 0
            or plaintext_size <= 0
            or plaintext_size > settings.max_snapshot_bytes
            or not re.fullmatch(r"[a-f0-9]{64}", expected_sha256)
        ):
            raise HTTPException(status_code=422, detail="snapshot metadata is invalid")
        snapshot = db.get(EnvironmentSnapshot, environment_id)
        if snapshot is None:
            raise HTTPException(status_code=409, detail="prepare the cloud snapshot before upload")
        if snapshot.version != expected_version:
            raise HTTPException(
                status_code=409,
                detail="cloud snapshot changed; restore the latest version before uploading",
            )
        if proof.fencing_token < snapshot.fencing_token:
            raise HTTPException(status_code=409, detail="snapshot fencing token is stale")

        file_descriptor, temporary_name = tempfile.mkstemp(
            prefix=".snapshot-upload-", dir=snapshot_dir
        )
        os.close(file_descriptor)
        temporary_path = Path(temporary_name)
        try:
            temporary_path.chmod(0o600)
        except OSError:
            pass
        digest = hashlib.sha256()
        received = 0
        try:
            with temporary_path.open("wb") as output:
                async for block in request.stream():
                    if not block:
                        continue
                    received += len(block)
                    if received > settings.max_snapshot_bytes:
                        raise HTTPException(status_code=413, detail="snapshot is too large")
                    digest.update(block)
                    output.write(block)
            if received == 0:
                raise HTTPException(status_code=422, detail="snapshot content is empty")
            raw_length = request.headers.get("content-length")
            if raw_length and int(raw_length) != received:
                raise HTTPException(status_code=400, detail="snapshot content length is invalid")
            if digest.hexdigest() != expected_sha256:
                raise HTTPException(status_code=422, detail="snapshot SHA-256 does not match")
            with temporary_path.open("rb") as uploaded_content:
                if uploaded_content.read(len(SNAPSHOT_MAGIC)) != SNAPSHOT_MAGIC:
                    raise HTTPException(status_code=422, detail="snapshot format is invalid")
            encryption_overhead = len(SNAPSHOT_MAGIC) + NONCE_BYTES + TAG_BYTES
            if plaintext_size + encryption_overhead != received:
                raise HTTPException(
                    status_code=422,
                    detail="snapshot plaintext size does not match its encrypted content",
                )

            db.expire(snapshot)
            snapshot = db.get(EnvironmentSnapshot, environment_id)
            require_snapshot_lease(db, auth, environment_id, proof)
            if snapshot is None or snapshot.version != expected_version:
                raise HTTPException(
                    status_code=409,
                    detail="cloud snapshot changed during upload",
                )
            db.execute(
                select(Organization.id)
                .where(Organization.id == auth.agent.organization_id)
                .with_for_update()
            ).scalar_one()
            organization_snapshot_bytes = db.scalar(
                select(func.coalesce(func.sum(EnvironmentSnapshot.ciphertext_size), 0)).where(
                    EnvironmentSnapshot.organization_id == auth.agent.organization_id,
                    EnvironmentSnapshot.environment_id != environment_id,
                )
            )
            if int(organization_snapshot_bytes or 0) + received > (
                settings.max_organization_snapshot_bytes
            ):
                raise HTTPException(
                    status_code=413,
                    detail="organization cloud snapshot quota exceeded",
                )
            next_version = expected_version + 1
            object_key = (
                f"{auth.agent.organization_id}/{environment_id}/"
                f"v{next_version}-{expected_sha256[:16]}-{secrets.token_hex(6)}.cbsnap"
            )
            destination = snapshot_object_path(object_key)
            destination.parent.mkdir(parents=True, exist_ok=True)
            previous_object_key = snapshot.object_key
            os.replace(temporary_path, destination)
            updated = db.execute(
                update(EnvironmentSnapshot)
                .where(
                    EnvironmentSnapshot.environment_id == environment_id,
                    EnvironmentSnapshot.organization_id == auth.agent.organization_id,
                    EnvironmentSnapshot.version == expected_version,
                    EnvironmentSnapshot.fencing_token <= proof.fencing_token,
                )
                .values(
                    version=next_version,
                    fencing_token=proof.fencing_token,
                    object_key=object_key,
                    ciphertext_sha256=expected_sha256,
                    ciphertext_size=received,
                    plaintext_size=plaintext_size,
                    uploaded_by_agent_id=auth.agent.id,
                    updated_at=utc_now(),
                )
            )
            if updated.rowcount != 1:
                db.rollback()
                destination.unlink(missing_ok=True)
                raise HTTPException(status_code=409, detail="snapshot upload was superseded")
            db.execute(
                update(AgentNode)
                .where(AgentNode.id == auth.agent.id)
                .values(last_seen_at=utc_now())
            )
            try:
                db.commit()
            except Exception:
                db.rollback()
                destination.unlink(missing_ok=True)
                raise
            if previous_object_key:
                try:
                    snapshot_object_path(previous_object_key).unlink(missing_ok=True)
                except OSError:
                    pass
        finally:
            temporary_path.unlink(missing_ok=True)
        snapshot = db.scalar(
            select(EnvironmentSnapshot)
            .options(
                joinedload(EnvironmentSnapshot.environment),
                joinedload(EnvironmentSnapshot.uploaded_by_agent),
            )
            .where(
                EnvironmentSnapshot.environment_id == environment_id,
                EnvironmentSnapshot.organization_id == auth.agent.organization_id,
            )
        )
        return {"snapshot": _snapshot_json(snapshot)}

    @app.delete(
        "/api/environments/{environment_id}/snapshot",
        status_code=status.HTTP_204_NO_CONTENT,
    )
    def delete_environment_snapshot(
        environment_id: str,
        auth: AuthContext = Depends(permission("snapshots.manage", mutation=True)),
        db: DatabaseSession = Depends(get_db),
    ) -> Response:
        environment = db.scalar(
            select(Environment).where(
                Environment.id == environment_id,
                Environment.organization_id == auth.organization.id,
            )
        )
        if environment is None:
            raise HTTPException(status_code=404, detail="environment not found")
        if active_environment_lease(db, auth.organization.id, environment_id):
            raise HTTPException(
                status_code=409,
                detail="stop the environment before deleting its cloud snapshot",
            )
        active_task = db.scalar(
            select(RemoteTask.id).where(
                RemoteTask.environment_id == environment_id,
                RemoteTask.organization_id == auth.organization.id,
                RemoteTask.status.in_(("pending", "claimed")),
            )
        )
        if active_task is not None:
            raise HTTPException(
                status_code=409,
                detail="wait for the remote task before deleting its cloud snapshot",
            )
        snapshot = db.get(EnvironmentSnapshot, environment_id)
        if snapshot is None or snapshot.version == 0:
            raise HTTPException(status_code=404, detail="cloud snapshot not found")
        object_key = snapshot.object_key
        version = snapshot.version
        db.delete(snapshot)
        _audit(
            db,
            auth,
            "snapshot.deleted",
            "environment",
            environment_id,
            {"version": version},
        )
        db.commit()
        if object_key:
            try:
                snapshot_object_path(object_key).unlink(missing_ok=True)
            except OSError:
                pass
        return Response(status_code=status.HTTP_204_NO_CONTENT)

    def queue_remote_task(
        db: DatabaseSession,
        auth: AuthContext,
        environment: Environment,
        agent: AgentNode,
        kind: str,
        payload: dict[str, Any],
    ) -> RemoteTask:
        task = RemoteTask(
            organization_id=auth.organization.id,
            environment_id=environment.id,
            agent_id=agent.id,
            kind=kind,
            status="pending",
            dedupe_key=environment.id,
            environment_revision=environment.revision,
            payload=payload,
            created_by=auth.user.id,
        )
        db.add(task)
        try:
            db.flush()
        except IntegrityError as exc:
            db.rollback()
            raise HTTPException(
                status_code=409,
                detail="environment already has a pending remote task",
            ) from exc
        _audit(
            db,
            auth,
            f"environment.{kind}_requested",
            "environment",
            environment.id,
            {"task_id": task.id, "agent_id": agent.id},
        )
        db.commit()
        task = db.scalar(
            select(RemoteTask)
            .options(
                joinedload(RemoteTask.environment),
                joinedload(RemoteTask.agent),
            )
            .where(
                RemoteTask.id == task.id,
                RemoteTask.organization_id == auth.organization.id,
            )
        )
        return task

    @app.post(
        "/api/environments/{environment_id}/launch",
        status_code=status.HTTP_202_ACCEPTED,
    )
    def request_environment_launch(
        environment_id: str,
        payload: RemoteLaunchRequest,
        auth: AuthContext = Depends(permission("environments.launch", mutation=True)),
        db: DatabaseSession = Depends(get_db),
    ) -> dict[str, Any]:
        environment = db.scalar(
            select(Environment)
            .options(joinedload(Environment.group))
            .where(
                Environment.id == environment_id,
                Environment.organization_id == auth.organization.id,
            )
        )
        if environment is None:
            raise HTTPException(status_code=404, detail="environment not found")
        if environment.revision != payload.expected_revision:
            raise HTTPException(
                status_code=409,
                detail="environment was updated by another team member; reload and retry",
            )
        if active_environment_lease(db, auth.organization.id, environment.id):
            raise HTTPException(status_code=409, detail="environment is already running")
        agent = require_managed_agent(db, auth.organization.id, payload.agent_id)
        if not _agent_is_online(agent):
            raise HTTPException(status_code=409, detail="selected agent is offline")
        if not bool((agent.capabilities or {}).get("browser_launch")):
            raise HTTPException(status_code=409, detail="selected agent cannot launch browsers")
        if environment.storage_policy != "local" and not bool(
            (agent.capabilities or {}).get("snapshot_sync")
        ):
            raise HTTPException(
                status_code=409,
                detail="selected agent cannot synchronize cloud snapshots",
            )
        if environment.secret is not None and environment.secret.proxy_envelope and not bool(
            (agent.capabilities or {}).get("secret_sync")
        ):
            raise HTTPException(
                status_code=409,
                detail="selected agent cannot receive runtime secrets",
            )
        if environment.extension_links and not bool(
            (agent.capabilities or {}).get("extension_sync")
        ):
            raise HTTPException(
                status_code=409,
                detail="selected agent cannot synchronize extension packages",
            )
        task = queue_remote_task(
            db,
            auth,
            environment,
            agent,
            "launch",
            {
                "environment": {
                    "id": environment.id,
                    "name": environment.name,
                    "revision": environment.revision,
                    "storage_policy": environment.storage_policy,
                    "config": dict(environment.config or {}),
                }
            },
        )
        return {"task": _task_json(task)}

    @app.post(
        "/api/environments/{environment_id}/stop",
        status_code=status.HTTP_202_ACCEPTED,
    )
    def request_environment_stop(
        environment_id: str,
        auth: AuthContext = Depends(permission("environments.launch", mutation=True)),
        db: DatabaseSession = Depends(get_db),
    ) -> dict[str, Any]:
        environment = db.scalar(
            select(Environment)
            .options(joinedload(Environment.group))
            .where(
                Environment.id == environment_id,
                Environment.organization_id == auth.organization.id,
            )
        )
        if environment is None:
            raise HTTPException(status_code=404, detail="environment not found")
        lease = active_environment_lease(db, auth.organization.id, environment.id)
        if lease is None or lease.agent is None or lease.lease_id is None:
            raise HTTPException(status_code=409, detail="environment is not running")
        task = queue_remote_task(
            db,
            auth,
            environment,
            lease.agent,
            "stop",
            {
                "lease_id": lease.lease_id,
                "fencing_token": lease.fencing_token,
            },
        )
        return {"task": _task_json(task)}

    @app.get("/api/tasks")
    def list_remote_tasks(
        auth: AuthContext = Depends(permission("tasks.read")),
        db: DatabaseSession = Depends(get_db),
    ) -> dict[str, Any]:
        tasks = db.scalars(
            select(RemoteTask)
            .options(
                joinedload(RemoteTask.environment),
                joinedload(RemoteTask.agent),
            )
            .where(RemoteTask.organization_id == auth.organization.id)
            .order_by(RemoteTask.created_at.desc())
            .limit(200)
        ).all()
        return {"tasks": [_task_json(task) for task in tasks]}

    @app.post("/api/agent/tasks/claim")
    def claim_remote_task(
        auth: AgentAuthContext = Depends(current_agent),
        db: DatabaseSession = Depends(get_db),
    ) -> dict[str, Any]:
        now = utc_now()
        stale_before = now - timedelta(seconds=TASK_CLAIM_TTL_SECONDS)
        db.execute(
            update(RemoteTask)
            .where(
                RemoteTask.organization_id == auth.agent.organization_id,
                RemoteTask.agent_id == auth.agent.id,
                RemoteTask.status == "claimed",
                RemoteTask.claimed_at.is_not(None),
                RemoteTask.claimed_at <= stale_before,
            )
            .values(
                status="pending",
                claim_token_digest=None,
                claimed_at=None,
                updated_at=now,
            )
        )
        for _attempt in range(3):
            task_id = db.scalar(
                select(RemoteTask.id)
                .where(
                    RemoteTask.organization_id == auth.agent.organization_id,
                    RemoteTask.agent_id == auth.agent.id,
                    RemoteTask.status == "pending",
                )
                .order_by(RemoteTask.created_at)
                .limit(1)
            )
            if task_id is None:
                db.commit()
                return {"task": None}
            raw_task_token = new_task_token()
            claimed = db.execute(
                update(RemoteTask)
                .where(
                    RemoteTask.id == task_id,
                    RemoteTask.organization_id == auth.agent.organization_id,
                    RemoteTask.agent_id == auth.agent.id,
                    RemoteTask.status == "pending",
                )
                .values(
                    status="claimed",
                    claim_token_digest=task_token_digest(raw_task_token),
                    claimed_at=now,
                    updated_at=now,
                )
            )
            if claimed.rowcount == 1:
                db.execute(
                    update(AgentNode)
                    .where(AgentNode.id == auth.agent.id)
                    .values(last_seen_at=now)
                )
                db.commit()
                task = db.scalar(
                    select(RemoteTask)
                    .options(
                        joinedload(RemoteTask.environment),
                        joinedload(RemoteTask.agent),
                    )
                    .where(
                        RemoteTask.id == task_id,
                        RemoteTask.organization_id == auth.agent.organization_id,
                        RemoteTask.agent_id == auth.agent.id,
                    )
                )
                return {
                    "task": _task_json(task, include_payload=True),
                    "task_token": raw_task_token,
                }
            db.rollback()
        raise HTTPException(status_code=409, detail="task claim was superseded")

    @app.post("/api/agent/tasks/{task_id}/heartbeat")
    def heartbeat_remote_task(
        task_id: str,
        payload: AgentTaskProof,
        auth: AgentAuthContext = Depends(current_agent),
        db: DatabaseSession = Depends(get_db),
    ) -> dict[str, str]:
        now = utc_now()
        touched = db.execute(
            update(RemoteTask)
            .where(
                RemoteTask.id == task_id,
                RemoteTask.organization_id == auth.agent.organization_id,
                RemoteTask.agent_id == auth.agent.id,
                RemoteTask.status == "claimed",
                RemoteTask.claim_token_digest == task_token_digest(payload.task_token),
            )
            .values(claimed_at=now, updated_at=now)
        )
        if touched.rowcount != 1:
            db.rollback()
            raise HTTPException(status_code=409, detail="task claim is stale")
        db.execute(
            update(AgentNode)
            .where(AgentNode.id == auth.agent.id)
            .values(last_seen_at=now)
        )
        db.commit()
        return {"status": "ok"}

    @app.post("/api/agent/tasks/{task_id}/complete")
    def complete_remote_task(
        task_id: str,
        payload: AgentTaskCompletion,
        auth: AgentAuthContext = Depends(current_agent),
        db: DatabaseSession = Depends(get_db),
    ) -> dict[str, Any]:
        task_digest = task_token_digest(payload.task_token)
        task = db.scalar(
            select(RemoteTask).where(
                RemoteTask.id == task_id,
                RemoteTask.organization_id == auth.agent.organization_id,
                RemoteTask.agent_id == auth.agent.id,
                RemoteTask.status == "claimed",
                RemoteTask.claim_token_digest == task_digest,
            )
        )
        if task is None:
            raise HTTPException(status_code=409, detail="task claim is stale")
        now = utc_now()
        if task.kind == "launch" and payload.status == "succeeded":
            lease_id = payload.result.get("lease_id")
            fencing_token = payload.result.get("fencing_token")
            if not isinstance(lease_id, str) or not lease_id or isinstance(
                fencing_token, bool
            ) or not isinstance(fencing_token, int):
                raise HTTPException(
                    status_code=409,
                    detail="launch result must contain a valid lease_id and fencing_token",
                )
            active_lease = db.scalar(
                select(EnvironmentLease)
                .where(
                    EnvironmentLease.environment_id == task.environment_id,
                    EnvironmentLease.organization_id == task.organization_id,
                    EnvironmentLease.agent_id == auth.agent.id,
                    EnvironmentLease.lease_id == lease_id,
                    EnvironmentLease.fencing_token == fencing_token,
                    EnvironmentLease.lease_token_digest.is_not(None),
                    EnvironmentLease.expires_at.is_not(None),
                    EnvironmentLease.expires_at > now,
                )
                .with_for_update()
            )
            if active_lease is None:
                raise HTTPException(
                    status_code=409,
                    detail="a live matching lease is required to complete launch",
                )
        completed = db.execute(
            update(RemoteTask)
            .where(
                RemoteTask.id == task.id,
                RemoteTask.organization_id == auth.agent.organization_id,
                RemoteTask.agent_id == auth.agent.id,
                RemoteTask.status == "claimed",
                RemoteTask.claim_token_digest == task_digest,
            )
            .values(
                status=payload.status,
                result=payload.result,
                error=payload.error if payload.status == "failed" else "",
                dedupe_key=None,
                claim_token_digest=None,
                completed_at=now,
                updated_at=now,
            )
        )
        if completed.rowcount != 1:
            db.rollback()
            raise HTTPException(status_code=409, detail="task claim is stale")
        if task.kind == "stop" and payload.status == "succeeded":
            db.execute(
                update(EnvironmentLease)
                .where(
                    EnvironmentLease.environment_id == task.environment_id,
                    EnvironmentLease.organization_id == task.organization_id,
                    EnvironmentLease.agent_id == auth.agent.id,
                    EnvironmentLease.lease_id == task.payload.get("lease_id"),
                    EnvironmentLease.fencing_token
                    == task.payload.get("fencing_token"),
                )
                .values(
                    agent_id=None,
                    lease_id=None,
                    lease_token_digest=None,
                    heartbeat_at=now,
                    expires_at=now,
                )
            )
        db.execute(
            update(AgentNode)
            .where(AgentNode.id == auth.agent.id)
            .values(last_seen_at=now)
        )
        db.commit()
        task = db.scalar(
            select(RemoteTask)
            .options(
                joinedload(RemoteTask.environment),
                joinedload(RemoteTask.agent),
            )
            .where(
                RemoteTask.id == task_id,
                RemoteTask.organization_id == auth.agent.organization_id,
            )
        )
        return {"task": _task_json(task)}

    @app.post("/api/agent/heartbeat")
    def agent_heartbeat(
        payload: AgentHeartbeat,
        auth: AgentAuthContext = Depends(current_agent),
        db: DatabaseSession = Depends(get_db),
    ) -> dict[str, Any]:
        now = utc_now()
        db.execute(
            update(AgentNode)
            .where(
                AgentNode.id == auth.agent.id,
                AgentNode.revoked_at.is_(None),
            )
            .values(
                hostname=payload.hostname,
                platform=payload.platform,
                version=payload.version,
                capabilities=payload.capabilities,
                last_seen_at=now,
            )
        )
        db.commit()
        return {
            "agent_id": auth.agent.id,
            "organization_id": auth.agent.organization_id,
            "server_time": _iso(now),
            "heartbeat_interval_seconds": 20,
            "lease_ttl_seconds": LEASE_TTL_SECONDS,
        }

    @app.get("/api/agent/environments")
    def list_agent_environments(
        auth: AgentAuthContext = Depends(current_agent),
        db: DatabaseSession = Depends(get_db),
    ) -> dict[str, Any]:
        environments = db.scalars(
            select(Environment)
            .options(joinedload(Environment.group))
            .where(Environment.organization_id == auth.agent.organization_id)
            .order_by(Environment.updated_at.desc())
        ).all()
        return {"environments": [_environment_json(item) for item in environments]}

    def claim_existing_lease(
        db: DatabaseSession,
        *,
        organization_id: str,
        environment_id: str,
        agent_id: str,
        lease_id: str,
        raw_lease_token: str,
        now: datetime,
        expires_at: datetime,
    ) -> bool:
        claimed = db.execute(
            update(EnvironmentLease)
            .where(
                EnvironmentLease.environment_id == environment_id,
                EnvironmentLease.organization_id == organization_id,
                or_(
                    EnvironmentLease.lease_token_digest.is_(None),
                    EnvironmentLease.expires_at.is_(None),
                    EnvironmentLease.expires_at <= now,
                ),
            )
            .values(
                agent_id=agent_id,
                lease_id=lease_id,
                lease_token_digest=lease_token_digest(raw_lease_token),
                fencing_token=EnvironmentLease.fencing_token + 1,
                acquired_at=now,
                heartbeat_at=now,
                expires_at=expires_at,
            )
        )
        return claimed.rowcount == 1

    @app.post("/api/agent/leases/acquire", status_code=status.HTTP_201_CREATED)
    def acquire_agent_lease(
        payload: AgentLeaseAcquire,
        auth: AgentAuthContext = Depends(current_agent),
        db: DatabaseSession = Depends(get_db),
    ) -> dict[str, Any]:
        organization_id = auth.agent.organization_id
        environment_id = payload.environment_id
        environment_exists = db.scalar(
            select(Environment.id).where(
                Environment.id == environment_id,
                Environment.organization_id == organization_id,
            )
        )
        if environment_exists is None:
            raise HTTPException(status_code=404, detail="environment not found")

        now = utc_now()
        expires_at = now + timedelta(seconds=LEASE_TTL_SECONDS)
        lease_id = new_id()
        raw_lease_token = new_lease_token()
        claimed = claim_existing_lease(
            db,
            organization_id=organization_id,
            environment_id=environment_id,
            agent_id=auth.agent.id,
            lease_id=lease_id,
            raw_lease_token=raw_lease_token,
            now=now,
            expires_at=expires_at,
        )
        if not claimed:
            lease_exists = db.scalar(
                select(EnvironmentLease.environment_id).where(
                    EnvironmentLease.environment_id == environment_id,
                    EnvironmentLease.organization_id == organization_id,
                )
            )
            if lease_exists is not None:
                db.rollback()
                raise HTTPException(
                    status_code=409,
                    detail="environment already has an active lease",
                )
            db.add(
                EnvironmentLease(
                    environment_id=environment_id,
                    organization_id=organization_id,
                    agent_id=auth.agent.id,
                    lease_id=lease_id,
                    lease_token_digest=lease_token_digest(raw_lease_token),
                    fencing_token=1,
                    acquired_at=now,
                    heartbeat_at=now,
                    expires_at=expires_at,
                )
            )
            try:
                db.flush()
                claimed = True
            except IntegrityError:
                db.rollback()
                claimed = claim_existing_lease(
                    db,
                    organization_id=organization_id,
                    environment_id=environment_id,
                    agent_id=auth.agent.id,
                    lease_id=lease_id,
                    raw_lease_token=raw_lease_token,
                    now=now,
                    expires_at=expires_at,
                )
        if not claimed:
            db.rollback()
            raise HTTPException(status_code=409, detail="environment already has an active lease")
        db.execute(
            update(AgentNode)
            .where(AgentNode.id == auth.agent.id)
            .values(last_seen_at=now)
        )
        db.commit()
        lease = db.scalar(
            select(EnvironmentLease)
            .options(
                joinedload(EnvironmentLease.environment),
                joinedload(EnvironmentLease.agent),
            )
            .where(
                EnvironmentLease.environment_id == environment_id,
                EnvironmentLease.organization_id == organization_id,
                EnvironmentLease.lease_id == lease_id,
            )
        )
        if lease is None:
            raise HTTPException(status_code=409, detail="lease acquisition was superseded")
        return {"lease": _lease_json(lease), "lease_token": raw_lease_token}

    @app.post("/api/agent/leases/{environment_id}/heartbeat")
    def heartbeat_agent_lease(
        environment_id: str,
        payload: AgentLeaseProof,
        auth: AgentAuthContext = Depends(current_agent),
        db: DatabaseSession = Depends(get_db),
    ) -> dict[str, Any]:
        now = utc_now()
        expires_at = now + timedelta(seconds=LEASE_TTL_SECONDS)
        renewed = db.execute(
            update(EnvironmentLease)
            .where(
                EnvironmentLease.environment_id == environment_id,
                EnvironmentLease.organization_id == auth.agent.organization_id,
                EnvironmentLease.agent_id == auth.agent.id,
                EnvironmentLease.lease_id == payload.lease_id,
                EnvironmentLease.fencing_token == payload.fencing_token,
                EnvironmentLease.lease_token_digest
                == lease_token_digest(payload.lease_token),
                EnvironmentLease.expires_at.is_not(None),
                EnvironmentLease.expires_at > now,
            )
            .values(heartbeat_at=now, expires_at=expires_at)
        )
        if renewed.rowcount != 1:
            db.rollback()
            raise HTTPException(status_code=409, detail="lease is stale or expired")
        db.execute(
            update(AgentNode)
            .where(AgentNode.id == auth.agent.id)
            .values(last_seen_at=now)
        )
        db.commit()
        lease = db.scalar(
            select(EnvironmentLease)
            .options(
                joinedload(EnvironmentLease.environment),
                joinedload(EnvironmentLease.agent),
            )
            .where(
                EnvironmentLease.environment_id == environment_id,
                EnvironmentLease.organization_id == auth.agent.organization_id,
            )
        )
        return {"lease": _lease_json(lease)}

    @app.post(
        "/api/agent/leases/{environment_id}/release",
        status_code=status.HTTP_204_NO_CONTENT,
    )
    def release_agent_lease(
        environment_id: str,
        payload: AgentLeaseProof,
        auth: AgentAuthContext = Depends(current_agent),
        db: DatabaseSession = Depends(get_db),
    ) -> Response:
        now = utc_now()
        released = db.execute(
            update(EnvironmentLease)
            .where(
                EnvironmentLease.environment_id == environment_id,
                EnvironmentLease.organization_id == auth.agent.organization_id,
                EnvironmentLease.agent_id == auth.agent.id,
                EnvironmentLease.lease_id == payload.lease_id,
                EnvironmentLease.fencing_token == payload.fencing_token,
                EnvironmentLease.lease_token_digest
                == lease_token_digest(payload.lease_token),
            )
            .values(
                agent_id=None,
                lease_id=None,
                lease_token_digest=None,
                heartbeat_at=now,
                expires_at=now,
            )
        )
        if released.rowcount != 1:
            db.rollback()
            raise HTTPException(status_code=409, detail="lease is stale or already released")
        db.execute(
            update(AgentNode)
            .where(AgentNode.id == auth.agent.id)
            .values(last_seen_at=now)
        )
        db.commit()
        return Response(status_code=status.HTTP_204_NO_CONTENT)

    def require_group(db: DatabaseSession, organization_id: str, group_id: str) -> Group:
        group = db.scalar(
            select(Group).where(
                Group.id == group_id,
                Group.organization_id == organization_id,
            )
        )
        if group is None:
            raise HTTPException(status_code=404, detail="group not found")
        return group

    @app.get("/api/groups")
    def list_groups(
        auth: AuthContext = Depends(current_auth),
        db: DatabaseSession = Depends(get_db),
    ) -> dict[str, Any]:
        groups = db.scalars(
            select(Group)
            .where(Group.organization_id == auth.organization.id)
            .order_by(Group.name)
        ).all()
        return {"groups": [_group_json(group) for group in groups]}

    @app.post("/api/groups", status_code=status.HTTP_201_CREATED)
    def create_group(
        payload: GroupCreate,
        auth: AuthContext = Depends(permission("groups.manage", mutation=True)),
        db: DatabaseSession = Depends(get_db),
    ) -> dict[str, Any]:
        group = Group(
            organization_id=auth.organization.id,
            name=payload.name,
            description=payload.description,
            created_by=auth.user.id,
        )
        db.add(group)
        try:
            db.flush()
        except IntegrityError as exc:
            db.rollback()
            raise HTTPException(status_code=409, detail="group name already exists") from exc
        _audit(db, auth, "group.created", "group", group.id, {"name": group.name})
        db.commit()
        return {"group": _group_json(group)}

    @app.patch("/api/groups/{group_id}")
    def update_group(
        group_id: str,
        payload: GroupUpdate,
        auth: AuthContext = Depends(permission("groups.manage", mutation=True)),
        db: DatabaseSession = Depends(get_db),
    ) -> dict[str, Any]:
        group = require_group(db, auth.organization.id, group_id)
        if payload.name is not None:
            group.name = payload.name
        if payload.description is not None:
            group.description = payload.description
        group.updated_at = utc_now()
        _audit(db, auth, "group.updated", "group", group.id)
        try:
            db.commit()
        except IntegrityError as exc:
            db.rollback()
            raise HTTPException(status_code=409, detail="group name already exists") from exc
        return {"group": _group_json(group)}

    @app.delete("/api/groups/{group_id}", status_code=status.HTTP_204_NO_CONTENT)
    def delete_group(
        group_id: str,
        auth: AuthContext = Depends(permission("groups.manage", mutation=True)),
        db: DatabaseSession = Depends(get_db),
    ) -> Response:
        group = require_group(db, auth.organization.id, group_id)
        affected = db.execute(
            update(Environment)
            .where(
                Environment.organization_id == auth.organization.id,
                Environment.group_id == group.id,
            )
            .values(
                group_id=None,
                revision=Environment.revision + 1,
                updated_by=auth.user.id,
                updated_at=utc_now(),
            )
        )
        db.delete(group)
        _audit(
            db,
            auth,
            "group.deleted",
            "group",
            group.id,
            {"name": group.name, "environments_unassigned": affected.rowcount},
        )
        db.commit()
        return Response(status_code=status.HTTP_204_NO_CONTENT)

    @app.get("/api/environments")
    def list_environments(
        auth: AuthContext = Depends(permission("environments.read")),
        db: DatabaseSession = Depends(get_db),
    ) -> dict[str, Any]:
        environments = db.scalars(
            select(Environment)
            .options(joinedload(Environment.group))
            .where(Environment.organization_id == auth.organization.id)
            .order_by(Environment.updated_at.desc())
        ).all()
        return {"environments": [_environment_json(item) for item in environments]}

    @app.post("/api/environments", status_code=status.HTTP_201_CREATED)
    def create_environment(
        payload: EnvironmentCreate,
        auth: AuthContext = Depends(permission("environments.create", mutation=True)),
        db: DatabaseSession = Depends(get_db),
    ) -> dict[str, Any]:
        if payload.group_id:
            require_group(db, auth.organization.id, payload.group_id)
        packages = require_extension_packages(
            db,
            auth.organization.id,
            payload.extension_ids,
        )
        environment = Environment(
            organization_id=auth.organization.id,
            group_id=payload.group_id,
            name=payload.name,
            tags=payload.tags,
            storage_policy=payload.storage_policy,
            config=payload.config.model_dump(),
            created_by=auth.user.id,
            updated_by=auth.user.id,
        )
        db.add(environment)
        try:
            db.flush()
        except IntegrityError as exc:
            db.rollback()
            raise HTTPException(status_code=409, detail="environment name already exists") from exc
        if payload.proxy:
            set_environment_proxy(db, auth, environment.id, payload.proxy)
        for position, package in enumerate(packages):
            db.add(
                EnvironmentExtension(
                    environment_id=environment.id,
                    extension_id=package.id,
                    position=position,
                )
            )
        _audit(
            db,
            auth,
            "environment.created",
            "environment",
            environment.id,
            {
                "storage_policy": environment.storage_policy,
                "proxy_configured": bool(payload.proxy),
                "extensions": len(packages),
            },
        )
        db.commit()
        db.expire_all()
        environment = db.scalar(
            select(Environment)
            .options(joinedload(Environment.group))
            .where(
                Environment.id == environment.id,
                Environment.organization_id == auth.organization.id,
            )
        )
        return {"environment": _environment_json(environment)}

    @app.patch("/api/environments/{environment_id}")
    def update_environment(
        environment_id: str,
        payload: EnvironmentUpdate,
        auth: AuthContext = Depends(permission("environments.edit", mutation=True)),
        db: DatabaseSession = Depends(get_db),
    ) -> dict[str, Any]:
        existing = db.scalar(
            select(Environment).where(
                Environment.id == environment_id,
                Environment.organization_id == auth.organization.id,
            )
        )
        if existing is None:
            raise HTTPException(status_code=404, detail="environment not found")
        active_task = db.scalar(
            select(RemoteTask.id).where(
                RemoteTask.environment_id == environment_id,
                RemoteTask.organization_id == auth.organization.id,
                RemoteTask.status.in_(("pending", "claimed")),
            )
        )
        if active_task is not None:
            raise HTTPException(
                status_code=409,
                detail="wait for the remote task before editing this environment",
            )
        if (
            payload.config is not None
            or payload.storage_policy is not None
            or payload.proxy is not None
            or payload.clear_proxy
            or payload.extension_ids is not None
        ) and active_environment_lease(db, auth.organization.id, environment_id):
            raise HTTPException(
                status_code=409,
                detail=(
                    "stop the environment before editing runtime, secret, extension, "
                    "or storage settings"
                ),
            )
        if payload.group_id:
            require_group(db, auth.organization.id, payload.group_id)
        packages = (
            require_extension_packages(
                db,
                auth.organization.id,
                payload.extension_ids,
            )
            if payload.extension_ids is not None
            else None
        )
        values: dict[str, Any] = {
            "revision": Environment.revision + 1,
            "updated_by": auth.user.id,
            "updated_at": utc_now(),
        }
        if payload.name is not None:
            values["name"] = payload.name
        if payload.clear_group:
            values["group_id"] = None
        elif payload.group_id is not None:
            values["group_id"] = payload.group_id
        if payload.tags is not None:
            values["tags"] = payload.tags
        if payload.storage_policy is not None:
            values["storage_policy"] = payload.storage_policy
        if payload.config is not None:
            values["config"] = payload.config.model_dump()
        result = db.execute(
            update(Environment)
            .where(
                Environment.id == environment_id,
                Environment.organization_id == auth.organization.id,
                Environment.revision == payload.expected_revision,
            )
            .values(**values)
        )
        if result.rowcount != 1:
            db.rollback()
            raise HTTPException(
                status_code=409,
                detail="environment was updated by another team member; reload and retry",
            )
        proxy_changed = payload.proxy is not None or payload.clear_proxy
        if proxy_changed:
            set_environment_proxy(
                db,
                auth,
                environment_id,
                "" if payload.clear_proxy else (payload.proxy or ""),
            )
        if packages is not None:
            db.execute(
                delete(EnvironmentExtension).where(
                    EnvironmentExtension.environment_id == environment_id
                )
            )
            for position, package in enumerate(packages):
                db.add(
                    EnvironmentExtension(
                        environment_id=environment_id,
                        extension_id=package.id,
                        position=position,
                    )
                )
        _audit(
            db,
            auth,
            "environment.updated",
            "environment",
            environment_id,
            {
                "from_revision": payload.expected_revision,
                "proxy_changed": proxy_changed,
                "extensions_changed": packages is not None,
            },
        )
        try:
            db.commit()
        except IntegrityError as exc:
            db.rollback()
            raise HTTPException(status_code=409, detail="environment name already exists") from exc
        db.expire_all()
        environment = db.scalar(
            select(Environment)
            .options(joinedload(Environment.group))
            .where(
                Environment.id == environment_id,
                Environment.organization_id == auth.organization.id,
            )
        )
        return {"environment": _environment_json(environment)}

    @app.delete("/api/environments/{environment_id}", status_code=status.HTTP_204_NO_CONTENT)
    def delete_environment(
        environment_id: str,
        auth: AuthContext = Depends(permission("environments.delete", mutation=True)),
        db: DatabaseSession = Depends(get_db),
    ) -> Response:
        environment = db.scalar(
            select(Environment).where(
                Environment.id == environment_id,
                Environment.organization_id == auth.organization.id,
            )
        )
        if environment is None:
            raise HTTPException(status_code=404, detail="environment not found")
        if active_environment_lease(db, auth.organization.id, environment.id):
            raise HTTPException(
                status_code=409,
                detail="stop the running environment before deleting it",
            )
        active_task = db.scalar(
            select(RemoteTask.id).where(
                RemoteTask.environment_id == environment.id,
                RemoteTask.organization_id == auth.organization.id,
                RemoteTask.status.in_(("pending", "claimed")),
            )
        )
        if active_task is not None:
            raise HTTPException(
                status_code=409,
                detail="wait for the remote task to finish before deleting the environment",
            )
        snapshot = db.get(EnvironmentSnapshot, environment.id)
        snapshot_object_key = snapshot.object_key if snapshot is not None else None
        db.delete(environment)
        _audit(
            db,
            auth,
            "environment.deleted",
            "environment",
            environment.id,
            {"name": environment.name, "revision": environment.revision},
        )
        db.commit()
        if snapshot_object_key:
            try:
                snapshot_object_path(snapshot_object_key).unlink(missing_ok=True)
            except OSError:
                pass
        return Response(status_code=status.HTTP_204_NO_CONTENT)

    @app.get("/api/audit")
    def list_audit(
        auth: AuthContext = Depends(permission("audit.read")),
        db: DatabaseSession = Depends(get_db),
    ) -> dict[str, Any]:
        entries = db.scalars(
            select(AuditLog)
            .where(AuditLog.organization_id == auth.organization.id)
            .order_by(AuditLog.created_at.desc())
            .limit(200)
        ).all()
        return {
            "entries": [
                {
                    "id": entry.id,
                    "actor_id": entry.actor_id,
                    "action": entry.action,
                    "target_type": entry.target_type,
                    "target_id": entry.target_id,
                    "details": entry.details,
                    "created_at": _iso(entry.created_at),
                }
                for entry in entries
            ]
        }

    app.mount("/assets", StaticFiles(directory=assets_dir), name="assets")

    @app.get("/", include_in_schema=False)
    def index() -> FileResponse:
        return FileResponse(assets_dir / "index.html")

    return app
