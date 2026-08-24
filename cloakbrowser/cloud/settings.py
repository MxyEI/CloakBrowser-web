"""Runtime settings for the cloud control plane."""

from __future__ import annotations

import base64
import binascii
import os
import secrets
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from ..config import get_cache_dir
from .security import normalize_email


PUBLIC_HOSTS = {"0.0.0.0", "::"}
DEFAULT_MAX_SNAPSHOT_BYTES = 1024 * 1024 * 1024
DEFAULT_MAX_ORGANIZATION_SNAPSHOT_BYTES = 100 * 1024 * 1024 * 1024
DEFAULT_MAX_EXTENSION_BYTES = 100 * 1024 * 1024
DEFAULT_MAX_ORGANIZATION_EXTENSION_BYTES = 5 * 1024 * 1024 * 1024


def _decode_master_key(value: str) -> bytes:
    padding = "=" * (-len(value) % 4)
    try:
        decoded = base64.b64decode(
            value + padding,
            altchars=b"-_",
            validate=True,
        )
    except (binascii.Error, TypeError, ValueError) as exc:
        raise ValueError("CLOAKBROWSER_CLOUD_SNAPSHOT_KEY must be URL-safe base64") from exc
    if len(decoded) != 32:
        raise ValueError("CLOAKBROWSER_CLOUD_SNAPSHOT_KEY must encode exactly 32 bytes")
    return decoded


def _read_master_key(path: Path) -> str:
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            raise ValueError(f"snapshot master key must be a regular file: {path}")
        if os.name != "nt" and metadata.st_mode & 0o077:
            raise ValueError(f"snapshot master key must use owner-only permissions: {path}")
        with os.fdopen(descriptor, "r", encoding="ascii") as handle:
            descriptor = -1
            return handle.read().strip()
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def _load_or_create_master_key(root: Path) -> bytes:
    configured = os.environ.get("CLOAKBROWSER_CLOUD_SNAPSHOT_KEY", "").strip()
    if configured:
        return _decode_master_key(configured)
    path = root / "snapshot-master.key"
    try:
        value = _read_master_key(path)
    except FileNotFoundError:
        value = base64.urlsafe_b64encode(secrets.token_bytes(32)).decode("ascii")
        descriptor = -1
        created = False
        try:
            descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            created = True
            with os.fdopen(descriptor, "w", encoding="ascii") as handle:
                descriptor = -1
                handle.write(value + "\n")
                handle.flush()
                os.fsync(handle.fileno())
        except FileExistsError:
            value = _read_master_key(path)
        except Exception:
            if created:
                path.unlink(missing_ok=True)
            raise
        finally:
            if descriptor >= 0:
                os.close(descriptor)
    return _decode_master_key(value)


@dataclass(frozen=True)
class CloudSettings:
    database_url: str
    secret_key: str
    cookie_secure: bool = False
    session_ttl_seconds: int = 7 * 24 * 60 * 60
    assets_dir: Optional[Path] = None
    development_secret: bool = False
    snapshot_dir: Optional[Path] = None
    snapshot_master_key: Optional[bytes] = None
    max_snapshot_bytes: int = DEFAULT_MAX_SNAPSHOT_BYTES
    max_organization_snapshot_bytes: int = DEFAULT_MAX_ORGANIZATION_SNAPSHOT_BYTES
    extension_dir: Optional[Path] = None
    max_extension_bytes: int = DEFAULT_MAX_EXTENSION_BYTES
    max_organization_extension_bytes: int = DEFAULT_MAX_ORGANIZATION_EXTENSION_BYTES
    superadmin_emails: frozenset[str] = frozenset()

    @classmethod
    def from_env(cls, data_dir: Optional[str] = None) -> "CloudSettings":
        root = Path(data_dir) if data_dir else get_cache_dir() / "cloud"
        root.mkdir(parents=True, exist_ok=True)
        try:
            root.chmod(0o700)
        except OSError:
            pass

        database_url = os.environ.get(
            "CLOAKBROWSER_CLOUD_DATABASE_URL",
            f"sqlite:///{(root / 'cloud.db').resolve()}",
        )
        configured_secret = os.environ.get("CLOAKBROWSER_CLOUD_SECRET", "").strip()
        development_secret = not bool(configured_secret)
        secret_key = configured_secret or secrets.token_urlsafe(48)
        raw_superadmin_emails = os.environ.get(
            "CLOAKBROWSER_CLOUD_SUPERADMIN_EMAILS", ""
        )
        try:
            superadmin_emails = frozenset(
                normalize_email(value)
                for value in raw_superadmin_emails.split(",")
                if value.strip()
            )
        except ValueError as exc:
            raise ValueError(
                "CLOAKBROWSER_CLOUD_SUPERADMIN_EMAILS must contain "
                "comma-separated valid email addresses"
            ) from exc
        secure = os.environ.get("CLOAKBROWSER_CLOUD_COOKIE_SECURE", "").strip().lower()
        cookie_secure = secure in {"1", "true", "yes", "on"}
        raw_max_snapshot_mb = os.environ.get(
            "CLOAKBROWSER_CLOUD_MAX_SNAPSHOT_MB", "1024"
        ).strip()
        try:
            max_snapshot_mb = int(raw_max_snapshot_mb)
        except ValueError as exc:
            raise ValueError("CLOAKBROWSER_CLOUD_MAX_SNAPSHOT_MB must be an integer") from exc
        if not 16 <= max_snapshot_mb <= 10240:
            raise ValueError(
                "CLOAKBROWSER_CLOUD_MAX_SNAPSHOT_MB must be between 16 and 10240"
            )
        raw_organization_quota_mb = os.environ.get(
            "CLOAKBROWSER_CLOUD_ORG_SNAPSHOT_QUOTA_MB", "102400"
        ).strip()
        try:
            organization_quota_mb = int(raw_organization_quota_mb)
        except ValueError as exc:
            raise ValueError(
                "CLOAKBROWSER_CLOUD_ORG_SNAPSHOT_QUOTA_MB must be an integer"
            ) from exc
        if not max_snapshot_mb <= organization_quota_mb <= 10_485_760:
            raise ValueError(
                "CLOAKBROWSER_CLOUD_ORG_SNAPSHOT_QUOTA_MB must be at least the "
                "single-snapshot limit and no more than 10485760"
            )
        raw_max_extension_mb = os.environ.get(
            "CLOAKBROWSER_CLOUD_MAX_EXTENSION_MB", "100"
        ).strip()
        raw_extension_quota_mb = os.environ.get(
            "CLOAKBROWSER_CLOUD_ORG_EXTENSION_QUOTA_MB", "5120"
        ).strip()
        try:
            max_extension_mb = int(raw_max_extension_mb)
            extension_quota_mb = int(raw_extension_quota_mb)
        except ValueError as exc:
            raise ValueError("cloud extension limits must be integers") from exc
        if not 1 <= max_extension_mb <= 1024:
            raise ValueError("CLOAKBROWSER_CLOUD_MAX_EXTENSION_MB must be between 1 and 1024")
        if not max_extension_mb <= extension_quota_mb <= 1_048_576:
            raise ValueError(
                "CLOAKBROWSER_CLOUD_ORG_EXTENSION_QUOTA_MB must be at least the "
                "single-package limit and no more than 1048576"
            )
        return cls(
            database_url=database_url,
            secret_key=secret_key,
            cookie_secure=cookie_secure,
            development_secret=development_secret,
            snapshot_dir=root / "snapshots",
            snapshot_master_key=_load_or_create_master_key(root),
            max_snapshot_bytes=max_snapshot_mb * 1024 * 1024,
            max_organization_snapshot_bytes=organization_quota_mb * 1024 * 1024,
            extension_dir=root / "extensions",
            max_extension_bytes=max_extension_mb * 1024 * 1024,
            max_organization_extension_bytes=extension_quota_mb * 1024 * 1024,
            superadmin_emails=superadmin_emails,
        )

    def validate_bind(self, host: str, *, container_loopback: bool = False) -> None:
        if container_loopback and host not in PUBLIC_HOSTS:
            raise ValueError(
                "container_loopback is only valid when the container binds to 0.0.0.0 or ::"
            )
        if host in PUBLIC_HOSTS and self.development_secret:
            raise ValueError(
                "CLOAKBROWSER_CLOUD_SECRET must be set before binding the cloud server publicly"
            )
        if host in PUBLIC_HOSTS and len(self.secret_key) < 32:
            raise ValueError(
                "CLOAKBROWSER_CLOUD_SECRET must contain at least 32 characters"
            )
        if host in PUBLIC_HOSTS and not self.cookie_secure and not container_loopback:
            raise ValueError(
                "CLOAKBROWSER_CLOUD_COOKIE_SECURE=true is required for a public cloud server"
            )
        if self.snapshot_master_key is not None and len(self.snapshot_master_key) != 32:
            raise ValueError("snapshot_master_key must contain exactly 32 bytes")
        if self.max_snapshot_bytes < 16 * 1024 * 1024:
            raise ValueError("max_snapshot_bytes must be at least 16 MiB")
        if self.max_organization_snapshot_bytes < self.max_snapshot_bytes:
            raise ValueError(
                "max_organization_snapshot_bytes must be at least max_snapshot_bytes"
            )
        if self.max_extension_bytes < 1024 * 1024:
            raise ValueError("max_extension_bytes must be at least 1 MiB")
        if self.max_organization_extension_bytes < self.max_extension_bytes:
            raise ValueError(
                "max_organization_extension_bytes must be at least max_extension_bytes"
            )
