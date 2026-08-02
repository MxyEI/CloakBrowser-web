"""Validated request schemas for the cloud API."""

from __future__ import annotations

import re
import secrets
import uuid
from typing import Any, Dict, List, Literal, Optional
from urllib.parse import urlsplit

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from .permissions import ROLES
from .security import normalize_email


VERSION_RE = re.compile(r"^[0-9]{1,3}(?:\.[0-9]{1,7}){0,3}$")
TIMEZONE_RE = re.compile(r"^[A-Za-z0-9_+./-]{0,80}$")
LOCALE_RE = re.compile(r"^[A-Za-z0-9-]{0,35}$")
LOCATIONS = {
    "",
    "new-york",
    "chicago",
    "denver",
    "phoenix",
    "los-angeles",
    "anchorage",
    "honolulu",
}
PROXY_SCHEMES = {"http", "https", "socks5", "socks5h"}
SHA256_RE = re.compile(r"^[a-f0-9]{64}$")


def normalize_proxy(value: str) -> str:
    proxy = value.strip()
    if not proxy:
        return ""
    if len(proxy) > 2048 or any(ord(character) < 32 for character in proxy):
        raise ValueError("proxy contains invalid characters")
    candidate = proxy if "://" in proxy else f"http://{proxy}"
    try:
        parsed = urlsplit(candidate)
        _ = parsed.port
    except ValueError as exc:
        raise ValueError("proxy is not a valid URL") from exc
    if parsed.scheme.lower() not in PROXY_SCHEMES:
        raise ValueError("proxy scheme must be http, https, socks5, or socks5h")
    if not parsed.hostname:
        raise ValueError("proxy host is required")
    if parsed.query or parsed.fragment or parsed.path not in {"", "/"}:
        raise ValueError("proxy URL must not contain a path, query, or fragment")
    return candidate


def normalize_extension_ids(values: List[str]) -> List[str]:
    result: List[str] = []
    seen = set()
    for value in values:
        try:
            normalized = str(uuid.UUID(value))
        except ValueError as exc:
            raise ValueError("extension id is invalid") from exc
        if normalized not in seen:
            result.append(normalized)
            seen.add(normalized)
    return result


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)


class RegisterRequest(StrictModel):
    email: str
    password: str = Field(min_length=10, max_length=128)
    display_name: str = Field(min_length=1, max_length=80)
    organization_name: str = Field(min_length=1, max_length=100)

    @field_validator("email")
    @classmethod
    def validate_email(cls, value: str) -> str:
        try:
            return normalize_email(value)
        except ValueError as exc:
            raise ValueError(str(exc)) from exc


class LoginRequest(StrictModel):
    email: str
    password: str = Field(min_length=1, max_length=128)

    @field_validator("email")
    @classmethod
    def validate_email(cls, value: str) -> str:
        try:
            return normalize_email(value)
        except ValueError as exc:
            raise ValueError(str(exc)) from exc


class OrganizationCreate(StrictModel):
    name: str = Field(min_length=1, max_length=100)


class OrganizationSwitch(StrictModel):
    organization_id: str = Field(min_length=36, max_length=36)


class MemberCreate(StrictModel):
    email: str
    role: str = "viewer"

    @field_validator("email")
    @classmethod
    def validate_email(cls, value: str) -> str:
        try:
            return normalize_email(value)
        except ValueError as exc:
            raise ValueError(str(exc)) from exc

    @field_validator("role")
    @classmethod
    def validate_role(cls, value: str) -> str:
        if value not in ROLES:
            raise ValueError("role must be owner, admin, operator, or viewer")
        return value


class MemberUpdate(StrictModel):
    role: str

    @field_validator("role")
    @classmethod
    def validate_role(cls, value: str) -> str:
        if value not in ROLES:
            raise ValueError("role must be owner, admin, operator, or viewer")
        return value


class GroupCreate(StrictModel):
    name: str = Field(min_length=1, max_length=80)
    description: str = Field(default="", max_length=300)


class GroupUpdate(StrictModel):
    name: Optional[str] = Field(default=None, min_length=1, max_length=80)
    description: Optional[str] = Field(default=None, max_length=300)


class EnvironmentConfig(StrictModel):
    fingerprint_seed: int = Field(
        default_factory=lambda: 10_000 + secrets.randbelow(90_000),
        ge=1,
        le=2_147_483_647,
    )
    headless: bool = False
    humanize: bool = False
    geoip: bool = False
    timezone: str = Field(default="", max_length=80)
    location: str = Field(default="", max_length=40)
    locale: str = Field(default="", max_length=35)
    startup_url: str = Field(default="about:blank", max_length=2048)
    storage_quota_mb: int = Field(default=5000, ge=256, le=500_000)
    fingerprint_platform: Literal["", "windows", "macos"] = ""
    fingerprint_brand: Literal["", "Chrome", "Edge", "Opera", "Vivaldi"] = ""
    fingerprint_brand_version: str = Field(default="", max_length=40)
    fingerprint_platform_version: str = Field(default="", max_length=40)
    hardware_concurrency: int = Field(default=0, ge=0, le=64)
    device_memory_gb: int = 0
    screen_width: int = Field(default=0, ge=0, le=7680)
    screen_height: int = Field(default=0, ge=0, le=4320)
    gpu_vendor: str = Field(default="", max_length=160)
    gpu_renderer: str = Field(default="", max_length=240)
    taskbar_height: int = Field(default=-1, ge=-1, le=240)
    fingerprint_noise: bool = True
    allow_third_party_cookies: bool = False

    @field_validator("timezone")
    @classmethod
    def validate_timezone(cls, value: str) -> str:
        if not TIMEZONE_RE.fullmatch(value):
            raise ValueError("timezone contains invalid characters")
        return value

    @field_validator("locale")
    @classmethod
    def validate_locale(cls, value: str) -> str:
        if not LOCALE_RE.fullmatch(value):
            raise ValueError("locale contains invalid characters")
        return value

    @field_validator("location")
    @classmethod
    def validate_location(cls, value: str) -> str:
        if value not in LOCATIONS:
            raise ValueError("location is not supported")
        return value

    @field_validator("startup_url")
    @classmethod
    def validate_startup_url(cls, value: str) -> str:
        if value == "about:blank":
            return value
        parsed = urlsplit(value)
        if parsed.scheme not in {"http", "https"} or not parsed.netloc:
            raise ValueError("startup_url must be about:blank or an HTTP(S) URL")
        return value

    @field_validator("fingerprint_brand_version", "fingerprint_platform_version")
    @classmethod
    def validate_version(cls, value: str) -> str:
        if value and not VERSION_RE.fullmatch(value):
            raise ValueError("version must be numeric and dot-separated")
        return value

    @field_validator("device_memory_gb")
    @classmethod
    def validate_memory(cls, value: int) -> int:
        if value not in {0, 1, 2, 4, 8}:
            raise ValueError("device_memory_gb must be automatic, 1, 2, 4, or 8")
        return value

    @model_validator(mode="after")
    def validate_pairs(self) -> "EnvironmentConfig":
        if bool(self.screen_width) != bool(self.screen_height):
            raise ValueError("screen width and height must be set together")
        if self.screen_width and self.screen_width < 800:
            raise ValueError("screen width must be at least 800")
        if self.screen_height and self.screen_height < 600:
            raise ValueError("screen height must be at least 600")
        if bool(self.gpu_vendor) != bool(self.gpu_renderer):
            raise ValueError("GPU vendor and renderer must be set together")
        return self


class EnvironmentCreate(StrictModel):
    name: str = Field(min_length=1, max_length=100)
    group_id: Optional[str] = None
    tags: List[str] = Field(default_factory=list, max_length=20)
    storage_policy: Literal["local", "backup", "shared"] = "local"
    config: EnvironmentConfig = Field(default_factory=EnvironmentConfig)
    proxy: str = Field(default="", max_length=2048)
    extension_ids: List[str] = Field(default_factory=list, max_length=20)

    @field_validator("tags")
    @classmethod
    def normalize_tags(cls, values: List[str]) -> List[str]:
        result: List[str] = []
        seen = set()
        for raw in values:
            value = raw.strip()
            if not value or len(value) > 40:
                raise ValueError("tags must contain 1 to 40 characters")
            folded = value.casefold()
            if folded not in seen:
                result.append(value)
                seen.add(folded)
        return result

    @field_validator("proxy")
    @classmethod
    def validate_proxy(cls, value: str) -> str:
        return normalize_proxy(value)

    @field_validator("extension_ids")
    @classmethod
    def validate_extension_ids(cls, values: List[str]) -> List[str]:
        return normalize_extension_ids(values)


class EnvironmentUpdate(StrictModel):
    expected_revision: int = Field(ge=1)
    name: Optional[str] = Field(default=None, min_length=1, max_length=100)
    group_id: Optional[str] = None
    clear_group: bool = False
    tags: Optional[List[str]] = Field(default=None, max_length=20)
    storage_policy: Optional[Literal["local", "backup", "shared"]] = None
    config: Optional[EnvironmentConfig] = None
    proxy: Optional[str] = Field(default=None, max_length=2048)
    clear_proxy: bool = False
    extension_ids: Optional[List[str]] = Field(default=None, max_length=20)

    @field_validator("tags")
    @classmethod
    def normalize_tags(cls, values: Optional[List[str]]) -> Optional[List[str]]:
        if values is None:
            return None
        return EnvironmentCreate.normalize_tags(values)

    @field_validator("proxy")
    @classmethod
    def validate_proxy(cls, value: Optional[str]) -> Optional[str]:
        return None if value is None else normalize_proxy(value)

    @field_validator("extension_ids")
    @classmethod
    def validate_extension_ids(cls, values: Optional[List[str]]) -> Optional[List[str]]:
        return None if values is None else normalize_extension_ids(values)

    @model_validator(mode="after")
    def validate_secret_update(self) -> "EnvironmentUpdate":
        if self.clear_proxy and self.proxy:
            raise ValueError("proxy and clear_proxy cannot be used together")
        return self


class ExtensionCreate(StrictModel):
    name: str = Field(min_length=1, max_length=100)
    version: str = Field(min_length=1, max_length=40)
    content_sha256: str = Field(min_length=64, max_length=64)
    content_size: int = Field(ge=1)

    @field_validator("version")
    @classmethod
    def validate_version(cls, value: str) -> str:
        if not VERSION_RE.fullmatch(value):
            raise ValueError("extension version must be numeric and dot-separated")
        return value

    @field_validator("content_sha256")
    @classmethod
    def validate_sha256(cls, value: str) -> str:
        normalized = value.lower()
        if not SHA256_RE.fullmatch(normalized):
            raise ValueError("extension SHA-256 is invalid")
        return normalized


class AgentCreate(StrictModel):
    name: str = Field(min_length=1, max_length=100)


class AgentHeartbeat(StrictModel):
    hostname: str = Field(default="", max_length=255)
    platform: str = Field(default="", max_length=120)
    version: str = Field(default="", max_length=40)
    capabilities: Dict[str, bool] = Field(default_factory=dict, max_length=30)


class AgentLeaseAcquire(StrictModel):
    environment_id: str = Field(min_length=36, max_length=36)


class AgentLeaseProof(StrictModel):
    lease_id: str = Field(min_length=36, max_length=36)
    lease_token: str = Field(min_length=40, max_length=160)
    fencing_token: int = Field(ge=1)


class RemoteLaunchRequest(StrictModel):
    agent_id: str = Field(min_length=36, max_length=36)
    expected_revision: int = Field(ge=1)


class AgentTaskProof(StrictModel):
    task_token: str = Field(min_length=40, max_length=160)


class AgentTaskCompletion(AgentTaskProof):
    status: Literal["succeeded", "failed"]
    error: str = Field(default="", max_length=1000)
    result: Dict[str, Any] = Field(default_factory=dict, max_length=50)
